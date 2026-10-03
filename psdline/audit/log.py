"""审计流水写入。"""

from __future__ import annotations

import contextlib
import json
import threading

from ..clock import Clock
from ..errors import RailError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from ..store import JsonlJournal
from .entry import AuditEntry

# 当前指令作用域内的验签凭据标识；该指令链路上所有审计条目的 detail 都会
# 带上同一个 auth_id，事后可按凭据把"验签结论→联锁→门控动作"串成一条线。
_CURRENT_AUTH = threading.local()
_RESERVED_DETAIL = frozenset({"severity", "auth_id"})


class AuditLog:
    """审计流水：内存索引 + 分段 JSONL 落盘。"""

    def __init__(self, clock: Clock, bus: EventBus, journal: JsonlJournal) -> None:
        self._clock = clock
        self._bus = bus
        self._journal = journal
        self._ids = IdFactory("audit")
        self._index: list[AuditEntry] = []

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    @property
    def ids(self) -> IdFactory:
        return self._ids

    def record(
        self,
        kind: str,
        train_id: str,
        station_id: str,
        at: float | None = None,
        severity: str = "notice",
        **detail: object,
    ) -> AuditEntry:
        """写入一条审计流水。

        ``severity`` 为 ``alarm`` 时事件总线以告警级别投递；处于 :meth:`scope`
        作用域内时 ``auth_id`` 自动并入明细（显式传入优先），让一条指令的
        "验签结论 → 联锁/门控动作 → 回滚补偿"在审计里能用同一凭据串起来。
        """

        if not kind:
            raise RailError("审计动作类型为空", component="audit")
        auth_id = detail.get("auth_id") or getattr(_CURRENT_AUTH, "id", "")
        clean = {
            key: value
            for key, value in detail.items()
            if value is not None and key not in _RESERVED_DETAIL
        }
        if auth_id:
            clean["auth_id"] = str(auth_id)
        if severity:
            clean["severity"] = severity
        entry = AuditEntry(
            id=self._ids.next(),
            kind=kind,
            train_id=train_id,
            station_id=station_id,
            at=self._clock.now() if at is None else at,
            detail=clean,
        )
        self._journal.append(entry.as_dict())
        self._index.append(entry)
        self._bus.publish(
            Event.of(
                "audit",
                "audit",
                kind,
                severity=severity or "notice",
                train_id=train_id,
                station_id=station_id,
                auth_id=str(auth_id or ""),
            )
        )
        return entry

    @contextlib.contextmanager
    def scope(self, auth_id: str):
        """把一个验签凭据标识绑定到当前线程的后续审计写入。"""

        previous = getattr(_CURRENT_AUTH, "id", "")
        _CURRENT_AUTH.id = auth_id
        try:
            yield
        finally:
            _CURRENT_AUTH.id = previous

    @staticmethod
    def current_auth() -> str:
        """返回当前线程绑定的验签凭据标识（未处于指令作用域时为空串）。"""

        return getattr(_CURRENT_AUTH, "id", "")

    def list(self) -> list[AuditEntry]:
        """返回内存里保留的审计条目。"""

        return list(self._index)

    def replay(self, limit: int = 100_000) -> list[AuditEntry]:
        """从落盘流水回放审计条目。"""

        records = self._journal.read_all()[:limit]
        return [AuditEntry.from_dict(item) for item in records if isinstance(item, dict)]

    def segments(self) -> list[list[dict]]:
        """按段返回落盘流水，供巡检逐段核对。"""

        return [
            self._journal.read_segment(index)
            for index in range(len(self._journal.segments()))
        ]

    def summary(self) -> dict:
        """返回审计用量与动作分布。"""

        entries = self.list()
        return {
            "entries": len(entries),
            "journal_records": self._journal.count(),
            "segment": self._journal.active_segment(),
            "segments": len(self._journal.segments()),
            "segment_sizes": [len(items) for items in self.segments()],
            "by_kind": count_kinds(entries),
        }

    def dump(self) -> str:
        """把内存索引序列化成一行 JSON，供状态接口内嵌。"""

        return json.dumps([entry.as_dict() for entry in self.list()], ensure_ascii=False)


def count_kinds(entries: list[AuditEntry]) -> dict[str, int]:
    """按动作类型统计条数。"""

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return counts
