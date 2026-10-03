"""签名密钥环。

密钥四态：

``active``   当前签名密钥，全局唯一；验签也用它。
``grace``    轮换后旧密钥进入并存期：只验签不签名，带 ``retire_at``；
             并存期（默认 24h）一过即退役。
``retired``  并存期结束：密钥材料从磁盘擦除，只留墓碑（kid/指纹/时间），
             供历史审计追溯"当时是哪把钥匙签的"。
``revoked``  疑似泄露立即吊销：同样擦除密钥材料，验签一律拒绝。

密钥文件写在独立的 ``secrets_root`` 下（与普通状态目录分开，便于挂 tmpfs 或
收紧权限），每把钥匙一个 ``<kid>.json``，创建后立刻 ``chmod 0600``；墓碑文件
不含密钥，仅含指纹。
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from dataclasses import dataclass

from ..errors import SecurityError

ACTIVE = "active"
GRACE = "grace"
RETIRED = "retired"
REVOKED = "revoked"
VERIFYING = (ACTIVE, GRACE)
LIVE_STATES = (ACTIVE, GRACE, RETIRED, REVOKED)


def fingerprint(secret: str) -> str:
    """密钥指纹：SHA-256(secret) 的前 16 字节十六进制，供人工比对。"""

    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class KeyRecord:
    """密钥环中的一条记录（墓碑不携带 ``secret``）。"""

    kid: str
    state: str
    algorithm: str
    created_at: float
    rotated_at: float = 0.0
    retire_at: float = 0.0
    fingerprint: str = ""
    secret: str = ""

    def can_verify(self) -> bool:
        return self.state in VERIFYING and bool(self.secret)

    def as_dict(self, include_secret: bool = False) -> dict:
        data = {
            "kid": self.kid,
            "state": self.state,
            "algorithm": self.algorithm,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
            "retire_at": self.retire_at,
            "fingerprint": self.fingerprint,
        }
        if include_secret and self.secret:
            data["secret"] = self.secret
        return data

    @classmethod
    def from_dict(cls, payload: dict) -> "KeyRecord":
        return cls(
            kid=str(payload.get("kid", "")),
            state=str(payload.get("state", "")),
            algorithm=str(payload.get("algorithm", "")),
            created_at=float(payload.get("created_at", 0.0)),
            rotated_at=float(payload.get("rotated_at", 0.0)),
            retire_at=float(payload.get("retire_at", 0.0)),
            fingerprint=str(payload.get("fingerprint", "")),
            secret=str(payload.get("secret", "")),
        )


class KeyRing:
    """磁盘支撑的签名密钥环，所有读写都在同一把锁内串行。"""

    def __init__(
        self,
        root: str,
        *,
        overlap_s: float = 86_400.0,
        clock=None,
        sequence_width: int = 4,
    ) -> None:
        self._root = os.path.abspath(root)
        self._overlap_s = float(overlap_s)
        self._clock = clock
        self._width = sequence_width
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        try:
            os.chmod(self._root, 0o700)
        except OSError:
            pass

    # ---- 基础读写 -----------------------------------------------------

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else time.time()

    def _path(self, kid: str) -> str:
        if "/" in kid or ".." in kid or not kid:
            raise SecurityError(f"非法密钥标识: {kid!r}", reason="bad_kid")
        return os.path.join(self._root, f"{kid}.json")

    def _write(self, record: KeyRecord, *, secret: bool) -> None:
        path = self._path(record.kid)
        payload = record.as_dict(include_secret=secret)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        # 含密钥材料的活钥文件收紧到属主读写；墓碑可保持属主读写。
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _load(self, kid: str) -> KeyRecord | None:
        path = self._path(kid)
        if not os.path.isfile(path):
            return None
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return KeyRecord.from_dict(payload)

    def _list_records(self) -> list[KeyRecord]:
        records: list[KeyRecord] = []
        for name in os.listdir(self._root):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(self._root, name), "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and payload.get("kid"):
                records.append(KeyRecord.from_dict(payload))
        return sorted(records, key=lambda item: item.kid)

    def _all_kids(self) -> list[str]:
        return sorted(
            name[:-5]
            for name in os.listdir(self._root)
            if name.endswith(".json")
        )

    def _next_kid(self) -> str:
        highest = 0
        for kid in self._all_kids():
            if kid.startswith("key-"):
                try:
                    highest = max(highest, int(kid[4:]))
                except ValueError:
                    continue
        return f"key-{highest + 1:0{self._width}d}"

    # ---- 查询 ---------------------------------------------------------

    def list(self) -> list[KeyRecord]:
        """列出全部密钥（含墓碑），活钥不回带密钥材料。"""

        with self._lock:
            return [
                KeyRecord(
                    kid=record.kid,
                    state=record.state,
                    algorithm=record.algorithm,
                    created_at=record.created_at,
                    rotated_at=record.rotated_at,
                    retire_at=record.retire_at,
                    fingerprint=record.fingerprint,
                    secret="",
                )
                for record in self._list_records()
            ]

    def describe(self) -> list[dict]:
        """控制台/审计用的安全描述（永不带密钥）。"""

        with self._lock:
            return [record.as_dict(include_secret=False) for record in self._list_records()]

    def get(self, kid: str) -> KeyRecord | None:
        """取一条密钥记录（内部使用，可能含密钥材料）。"""

        with self._lock:
            return self._load(kid)

    def active(self) -> KeyRecord | None:
        """返回当前 active 密钥（惰性清理过期 grace 钥）。"""

        with self._lock:
            self._expire_locked(self._now())
            for record in self._list_records():
                if record.state == ACTIVE:
                    return record
            return None

    def secret_of(self, kid: str) -> str | None:
        """按 kid 取一把仍可验签密钥的材料；过期/吊销/退役都返回 ``None``。"""

        with self._lock:
            self._expire_locked(self._now())
            record = self._load(kid)
            if record is None or not record.can_verify():
                return None
            return record.secret

    # ---- 生命周期 -----------------------------------------------------

    def bootstrap(self, secret: str | None = None, now: float | None = None) -> KeyRecord:
        """没有任何密钥时创建第一把 active 钥；已有则直接返回当前 active。"""

        from .envelope import new_secret

        with self._lock:
            moment = self._now() if now is None else now
            self._expire_locked(moment)
            existing = [record for record in self._list_records() if record.state == ACTIVE]
            if existing:
                return existing[0]
            material = secret or new_secret()
            record = KeyRecord(
                kid=self._next_kid(),
                state=ACTIVE,
                algorithm="HS256",
                created_at=moment,
                fingerprint=fingerprint(material),
                secret=material,
            )
            self._write(record, secret=True)
            return record

    def rotate(self, secret: str | None = None, now: float | None = None) -> tuple[KeyRecord, KeyRecord | None]:
        """轮换：旧 active 转 grace（并存期），创建新 active。

        返回 ``(新active, 旧active或None)``。轮换时先把所有已过期 grace 钥
        退役，保证任意时刻可验签密钥最多两把。
        """

        from .envelope import new_secret

        with self._lock:
            moment = self._now() if now is None else now
            self._expire_locked(moment)
            current = next(
                (record for record in self._list_records() if record.state == ACTIVE), None
            )
            material = secret or new_secret()
            fresh = KeyRecord(
                kid=self._next_kid(),
                state=ACTIVE,
                algorithm="HS256",
                created_at=moment,
                fingerprint=fingerprint(material),
                secret=material,
            )
            old: KeyRecord | None = None
            if current is not None:
                old = KeyRecord(
                    **{
                        **current.as_dict(include_secret=True),
                        "state": GRACE,
                        "rotated_at": moment,
                        "retire_at": moment + self._overlap_s,
                    }
                )
                self._write(old, secret=True)
            self._write(fresh, secret=True)
            return fresh, old

    def retire_expired(self, now: float | None = None) -> list[str]:
        """显式退役所有并存期到期的 grace 钥，返回被退役的 kid 列表。"""

        moment = self._now() if now is None else now
        with self._lock:
            expired = [
                record
                for record in self._list_records()
                if record.state == GRACE and record.retire_at > 0 and moment >= record.retire_at
            ]
            for record in expired:
                self._tombstone(record, RETIRED)
            return [record.kid for record in expired]

    def _expire_locked(self, moment: float) -> None:
        for record in self._list_records():
            if record.state == GRACE and record.retire_at > 0 and moment >= record.retire_at:
                self._tombstone(record, RETIRED)

    def revoke(self, kid: str, now: float | None = None) -> KeyRecord:
        """立即吊销一把密钥并擦除密钥材料。"""

        moment = self._now() if now is None else now
        with self._lock:
            record = self._load(kid)
            if record is None:
                raise SecurityError(f"密钥不存在: {kid}", reason="unknown_kid")
            if record.state == REVOKED:
                return record
            return self._tombstone(
                KeyRecord(**{**record.as_dict(include_secret=True), "rotated_at": moment}),
                REVOKED,
            )

    def _tombstone(self, record: KeyRecord, state: str) -> KeyRecord:
        """擦除密钥材料，只保留指纹墓碑。"""

        grave = KeyRecord(
            **{**record.as_dict(include_secret=True), "state": state, "secret": ""}
        )
        self._write(grave, secret=False)
        return grave

    # ---- 给外部时钟/配置的小工具 -------------------------------------

    def has_any(self) -> bool:
        """密钥环里是否至少有一条记录（含墓碑）。"""

        with self._lock:
            return bool(self._list_records())
