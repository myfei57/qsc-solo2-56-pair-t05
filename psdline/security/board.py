"""安全告警牌。

连续验签失败达到阈值后立牌告警（``alarm`` 事件上总线），记录失败计数、最近
失败原因与可疑 nonce/kid。告警牌**不拦截合法签名指令**——否则攻击者只需不断
发送坏报文就能瘫痪整条线路（失败流量 DoS）；它只负责把异常顶到控制台与审计，
由人工用 :meth:`SecurityBoard.reset` 清除。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from ..eventbus import Event, EventBus


@dataclass
class SecurityBoard:
    """验签失败计数与告警状态。"""

    bus: EventBus
    threshold: int = 5
    failures: int = 0
    alarms: int = 0
    alarm_active: bool = False
    last_reason: str = ""
    last_source: str = ""
    last_at: float = 0.0
    recent: list[dict] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def record_failure(self, *, reason: str, source: str, at: float, detail: dict) -> bool:
        """记一次验签失败；返回是否因此新立告警。"""

        with self._lock:
            self.failures += 1
            self.last_reason = reason
            self.last_source = source
            self.last_at = at
            self.recent.append({"reason": reason, "source": source, "at": at, **detail})
            if len(self.recent) > 20:
                del self.recent[:-20]
            new_alarm = not self.alarm_active and self.failures >= self.threshold
            if new_alarm:
                self.alarm_active = True
                self.alarms += 1
            self.bus.publish(
                Event.of(
                    "security",
                    "guard",
                    "security_alarm" if new_alarm else "signature_rejected",
                    severity="alarm",
                    reason=reason,
                    source=source,
                    failures=self.failures,
                    threshold=self.threshold,
                )
            )
            return new_alarm

    def reset(self, *, at: float, by: str = "") -> dict:
        """人工清除告警（失败计数保留累计值，另记一次清零动作数）。"""

        with self._lock:
            was = self.alarm_active
            self.alarm_active = False
            resets = getattr(self, "_resets", 0) + 1
            self._resets = resets
            self.bus.publish(
                Event.of(
                    "security",
                    "guard",
                    "security_alarm_cleared",
                    severity="notice",
                    by=by,
                    had_been_active=was,
                )
            )
            return {"cleared": was, "resets": resets, "at": at}

    def resets(self) -> int:
        return getattr(self, "_resets", 0)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "alarm_active": self.alarm_active,
                "alarms_raised": self.alarms,
                "alarms_cleared": self.resets(),
                "failures": self.failures,
                "threshold": self.threshold,
                "last_reason": self.last_reason,
                "last_source": self.last_source,
                "last_at": self.last_at,
                "recent": list(self.recent[-10:]),
            }
