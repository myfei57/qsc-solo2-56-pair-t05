"""指令签名密钥环。

密钥按 ``kid`` 落盘（``sec/keys/<kid>``），三种状态：

``active``   当前主密钥，可签可验；
``retiring`` 轮换过渡期的旧密钥，**只验不签**，宽限期（``grace_until``）一到即退役；
``retired``  已退役，密钥材料被抹除，只留墓碑供审计区分"未知密钥"与"过期密钥"。

轮换兼容策略：轮换瞬间旧密钥进入 ``retiring`` 并继续可验一个宽限期，覆盖发送方
时钟偏差与在途指令；宽限期配置必须不小于指令有效期（或为 0 表示硬切换），由配置
校验保证。验签时用的是哪把钥匙（``active`` / ``retiring``）会写进审计，运维能
看到谁还在用旧密钥签。
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass

from ..store import JsonStore

ACTIVE = "active"
RETIRING = "retiring"
RETIRED = "retired"


@dataclass(frozen=True)
class KeyRecord:
    """一把签名密钥的落盘记录。"""

    kid: str
    material_hex: str
    state: str
    created_at: float
    grace_until: float = 0.0
    retired_at: float = 0.0

    def material_bytes(self) -> bytes:
        """返回密钥材料；已退役的密钥返回空字节（验签必然失败）。"""

        if not self.material_hex:
            return b""
        return bytes.fromhex(self.material_hex)

    def as_dict(self) -> dict:
        """完整序列化（含密钥材料），仅用于落盘。"""

        return {
            "kid": self.kid,
            "material_hex": self.material_hex,
            "state": self.state,
            "created_at": self.created_at,
            "grace_until": self.grace_until,
            "retired_at": self.retired_at,
        }

    def public_dict(self) -> dict:
        """不含密钥材料的对外视图，供状态接口展示。"""

        return {
            "kid": self.kid,
            "state": self.state,
            "created_at": self.created_at,
            "grace_until": self.grace_until,
            "retired_at": self.retired_at,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "KeyRecord":
        return cls(
            kid=str(payload.get("kid", "")),
            material_hex=str(payload.get("material_hex", "")),
            state=str(payload.get("state", "")),
            created_at=float(payload.get("created_at", 0.0)),
            grace_until=float(payload.get("grace_until", 0.0)),
            retired_at=float(payload.get("retired_at", 0.0)),
        )


class KeyRing:
    """落盘的签名密钥环，负责引导、轮换与退役。"""

    def __init__(self, store: JsonStore) -> None:
        self._store = store
        self._lock = threading.RLock()

    @staticmethod
    def _doc_id(kid: str) -> str:
        return f"sec/keys/{kid}"

    def _load(self) -> list[KeyRecord]:
        records: list[KeyRecord] = []
        for doc_id in self._store.list_ids():
            if not doc_id.startswith("sec/keys/"):
                continue
            raw = self._store.read(doc_id)
            if isinstance(raw, dict):
                records.append(KeyRecord.from_dict(raw))
        return sorted(records, key=lambda record: record.created_at)

    def _save(self, record: KeyRecord) -> None:
        self._store.write(self._doc_id(record.kid), record.as_dict())

    def list(self) -> list[KeyRecord]:
        """返回全部密钥记录（含退役墓碑）。"""

        with self._lock:
            return self._load()

    def get(self, kid: str) -> KeyRecord | None:
        """按标识取一把密钥。"""

        with self._lock:
            raw = self._store.read(self._doc_id(kid))
            if isinstance(raw, dict):
                return KeyRecord.from_dict(raw)
            return None

    def active(self) -> KeyRecord | None:
        """返回当前主密钥。"""

        with self._lock:
            for record in self._load():
                if record.state == ACTIVE:
                    return record
            return None

    def ensure_active(self, now: float) -> tuple[KeyRecord, bool]:
        """没有主密钥时生成第一把（引导），返回（主密钥, 是否新建）。"""

        with self._lock:
            existing = self.active()
            if existing is not None:
                return existing, False
            record = KeyRecord(
                kid=f"k{secrets.token_hex(8)}",
                material_hex=secrets.token_bytes(32).hex(),
                state=ACTIVE,
                created_at=now,
            )
            self._save(record)
            return record, True

    def rotate(self, now: float, grace_s: float) -> dict:
        """轮换主密钥：旧钥进入宽限期，生成新主密钥，并顺带退役到期旧钥。"""

        with self._lock:
            retired = self._sweep_locked(now)
            old = self.active()
            retiring: KeyRecord | None = None
            if old is not None:
                retiring = KeyRecord(
                    kid=old.kid,
                    material_hex=old.material_hex,
                    state=RETIRING,
                    created_at=old.created_at,
                    grace_until=now + grace_s,
                )
                self._save(retiring)
            new = KeyRecord(
                kid=f"k{secrets.token_hex(8)}",
                material_hex=secrets.token_bytes(32).hex(),
                state=ACTIVE,
                created_at=now,
            )
            self._save(new)
            return {"old": retiring, "new": new, "retired": retired}

    def sweep(self, now: float) -> list[KeyRecord]:
        """把宽限期已到的 ``retiring`` 密钥退役（抹除材料），返回新退役的记录。"""

        with self._lock:
            return self._sweep_locked(now)

    def _sweep_locked(self, now: float) -> list[KeyRecord]:
        retired: list[KeyRecord] = []
        for record in self._load():
            if record.state != RETIRING or record.grace_until > now:
                continue
            tombstone = KeyRecord(
                kid=record.kid,
                material_hex="",
                state=RETIRED,
                created_at=record.created_at,
                grace_until=record.grace_until,
                retired_at=now,
            )
            self._save(tombstone)
            retired.append(tombstone)
        return retired
