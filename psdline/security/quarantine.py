"""指令隔离区。

``hold`` 模式下验签失败的开关指令**绝不执行**，但也不一丢了之：信封与验签
判定原样落进隔离区，等值班员事后核查。处置只能是两种——``rejected``（确认
伪造，丢弃并保留证据）或 ``reissued``（值班员核对后用自己的新签名重新签发
执行）；隔离区里的原始报文永远不会被"批准放行"。

隔离区是只追加 JSONL：每次提交写一条 ``held``，每次处置追加一条 disposition，
当前状态靠回放归并得到，审计可以重建完整的"谁在什么时候处置了什么"。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..store import JsonlJournal

HELD = "held"
DISMISSED = "dismissed"
REISSUED = "reissued"
RESOLVED = (DISMISSED, REISSUED)


@dataclass(frozen=True)
class HeldCommand:
    """一条被挂起的可疑指令。"""

    hold_id: str
    at: float
    reason: str
    message: str
    envelope: dict
    action: str
    source: str = ""
    status: str = HELD
    resolution: str = ""
    resolved_at: float = 0.0
    resolved_by: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "hold_id": self.hold_id,
            "at": self.at,
            "reason": self.reason,
            "message": self.message,
            "envelope": self.envelope,
            "action": self.action,
            "source": self.source,
            "status": self.status,
            "resolution": self.resolution,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by,
            "note": self.note,
        }


class Quarantine:
    """只追加的可疑指令隔离区。"""

    def __init__(self, journal: JsonlJournal, id_factory) -> None:
        self._journal = journal
        self._ids = id_factory
        self._lock = threading.RLock()
        self._holds: dict[str, HeldCommand] = {}
        self._rebuild()

    def _rebuild(self) -> None:
        for item in self._journal.read_all():
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind", ""))
            if kind == HELD:
                hold = HeldCommand(
                    hold_id=str(item.get("hold_id", "")),
                    at=float(item.get("at", 0.0)),
                    reason=str(item.get("reason", "")),
                    message=str(item.get("message", "")),
                    envelope=dict(item.get("envelope", {})),
                    action=str(item.get("action", "")),
                    source=str(item.get("source", "")),
                )
                self._holds[hold.hold_id] = hold
            elif kind in RESOLVED:
                hold_id = str(item.get("hold_id", ""))
                current = self._holds.get(hold_id)
                if current is None:
                    continue
                self._holds[hold_id] = HeldCommand(
                    **{
                        **current.as_dict(),
                        "status": kind,
                        "resolution": kind,
                        "resolved_at": float(item.get("at", 0.0)),
                        "resolved_by": str(item.get("by", "")),
                        "note": str(item.get("note", "")),
                    }
                )

    def hold(
        self,
        *,
        at: float,
        reason: str,
        message: str,
        envelope: dict,
        action: str,
        source: str = "",
    ) -> HeldCommand:
        """挂起一条可疑指令并落盘。"""

        with self._lock:
            held = HeldCommand(
                hold_id=self._ids.next(),
                at=at,
                reason=reason,
                message=message,
                envelope=dict(envelope),
                action=action,
                source=source,
            )
            self._journal.append({"kind": HELD, **held.as_dict()})
            self._holds[held.hold_id] = held
            return held

    def resolve(
        self,
        hold_id: str,
        resolution: str,
        *,
        at: float,
        by: str = "",
        note: str = "",
    ) -> HeldCommand:
        """处置一条挂起指令（``dismissed`` / ``reissued``）。"""

        if resolution not in RESOLVED:
            raise ValueError(f"未知处置方式: {resolution}")
        with self._lock:
            current = self._holds.get(hold_id)
            if current is None:
                raise KeyError(hold_id)
            if current.status in RESOLVED:
                return current
            event = {
                "kind": resolution,
                "hold_id": hold_id,
                "at": at,
                "by": by,
                "note": note,
            }
            self._journal.append(event)
            updated = HeldCommand(
                **{
                    **current.as_dict(),
                    "status": resolution,
                    "resolution": resolution,
                    "resolved_at": at,
                    "resolved_by": by,
                    "note": note,
                }
            )
            self._holds[hold_id] = updated
            return updated

    def pending(self) -> list[HeldCommand]:
        with self._lock:
            return [item for item in self._holds.values() if item.status == HELD]

    def get(self, hold_id: str) -> HeldCommand | None:
        with self._lock:
            return self._holds.get(hold_id)

    def list(self) -> list[HeldCommand]:
        with self._lock:
            return list(self._holds.values())

    def counts(self) -> dict:
        with self._lock:
            items = list(self._holds.values())
            return {
                "total": len(items),
                "pending": len([item for item in items if item.status == HELD]),
                "dismissed": len([item for item in items if item.status == DISMISSED]),
                "reissued": len([item for item in items if item.status == REISSUED]),
            }
