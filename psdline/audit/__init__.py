"""门控审计。

审计是控制链的最后一环：所有到发、开关门、联锁与探测动作都落一条流水，既能按
动作类型检索，也能按资产重建时间线。指令防伪启用后，每条外部指令的验签结论、
密钥轮换、隔离处置与回滚补偿同样落审计，并可用 :func:`by_auth` 按验签凭据
把一条指令的完整链路串起来。流水追加到分段 JSONL，内存里只保留最近一段供
控制台读取。
"""

from __future__ import annotations

from .entry import AuditEntry
from .log import AuditLog
from .query import by_auth, by_kind, by_train, count_by_kind, kinds, verification_verdicts
from .summary import count, last, latest_by_kind
from .timeline import build_timeline

__all__ = [
    "AuditEntry",
    "AuditLog",
    "build_timeline",
    "by_auth",
    "by_kind",
    "by_train",
    "count",
    "count_by_kind",
    "kinds",
    "last",
    "latest_by_kind",
    "verification_verdicts",
]
