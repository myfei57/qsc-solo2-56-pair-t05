"""nonce 台账：指令防重放的唯一权威。

每条验签通过的指令，其 ``nonce`` 先落盘再执行——"先消费后执行"，并且台账是
只追加 JSONL，不参与执行事务回滚：一条指令哪怕执行到一半失败回滚，它的 nonce
也已经烧掉，攻击者无法拿同一条报文再试一次（重发必须由签发侧用新 nonce 重签）。

内存里只在一个有锁集合里做 O(1) 判重；台账保留 ``nonce_retention_s``
（不短于指令有效期 + 时钟偏差）后由 :meth:`prune` 清掉过期条目。重启时从
JSONL 回放重建集合，掉电不丢判重能力。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..store import JsonlJournal


@dataclass(frozen=True)
class NonceRecord:
    """一条已消费 nonce 的台账记录。"""

    nonce: str
    kid: str
    action: str
    consumed_at: float
    expires_at: float
    auth_id: str = ""

    def as_dict(self) -> dict:
        return {
            "nonce": self.nonce,
            "kid": self.kid,
            "action": self.action,
            "consumed_at": self.consumed_at,
            "expires_at": self.expires_at,
            "auth_id": self.auth_id,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "NonceRecord":
        return cls(
            nonce=str(payload.get("nonce", "")),
            kid=str(payload.get("kid", "")),
            action=str(payload.get("action", "")),
            consumed_at=float(payload.get("consumed_at", 0.0)),
            expires_at=float(payload.get("expires_at", 0.0)),
            auth_id=str(payload.get("auth_id", "")),
        )


class NonceLedger:
    """落盘的 nonce 消费台账。"""

    def __init__(self, journal: JsonlJournal, *, retention_s: float) -> None:
        if retention_s <= 0:
            raise ValueError("nonce 保留窗口必须为正")
        self._journal = journal
        self._retention_s = float(retention_s)
        self._lock = threading.RLock()
        self._records: dict[str, NonceRecord] = {}
        self._rebuild()

    def _rebuild(self) -> None:
        for item in self._journal.read_all():
            if not isinstance(item, dict) or not item.get("nonce"):
                continue
            record = NonceRecord.from_dict(item)
            self._records[record.nonce] = record

    @property
    def retention_s(self) -> float:
        return self._retention_s

    def seen(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._records

    def lookup(self, nonce: str) -> NonceRecord | None:
        with self._lock:
            return self._records.get(nonce)

    def consume(
        self,
        nonce: str,
        *,
        kid: str,
        action: str,
        consumed_at: float,
        auth_id: str = "",
    ) -> bool:
        """原子地"判重并消费"：首次出现返回 ``True``，重复返回 ``False``。

        先在锁内判重，随即把记录 fsync 追加到台账后再写进内存集合；台账写
        成功才算消费完成，保证崩溃恢复后内存集合不会漏记。
        """

        with self._lock:
            if nonce in self._records:
                return False
            record = NonceRecord(
                nonce=nonce,
                kid=kid,
                action=action,
                consumed_at=consumed_at,
                expires_at=consumed_at + self._retention_s,
                auth_id=auth_id,
            )
            self._journal.append(record.as_dict())
            self._records[nonce] = record
            return True

    def prune(self, now: float) -> int:
        """清掉保留窗口外的过期内存条目，返回清掉的数量。

        JSONL 分段随审计段继续追加滚动，历史仍可追溯；内存索引只保留防重放
        窗口内的条目。
        """

        with self._lock:
            stale = [
                value.nonce
                for value in self._records.values()
                if value.expires_at <= now
            ]
            for nonce in stale:
                self._records.pop(nonce, None)
            return len(stale)

    def active_count(self) -> int:
        with self._lock:
            return len(self._records)

    def consumed_total(self) -> int:
        return self._journal.count()
