"""指令验签闸门。

所有外部门控／联锁指令的唯一入口。每条指令按固定顺序检查：

1. 信封格式（``malformed``）；
2. 指令类型是否受支持（``unknown_kind``）；
3. 密钥是否存在（``unknown_key``）、是否已退役（``key_retired``）；
4. HMAC 签名是否匹配（``bad_signature``）；
5. 有效期声明是否超限（``ttl_exceeded``）、签发时间是否前倾过多（``not_yet_valid``）、
   指令是否已过期（``expired``）；
6. 是否重放（``replay``）。

**失败策略（取舍已定）：一律丢弃并告警，不挂起。** 门控是安全相关动作，"挂起等
人工确认"本身就是一条潜在执行路径（人工误确认即开门），而且每条失败都要人工
分拣，运维负担更重。丢弃 + 告警让合法发送方修正后重发即可；失败指令永远进不了
任何队列。无论放行还是拒绝，闸门都把验签结论写进审计（``command_verified`` /
``command_rejected``），拒绝时同时向总线发 ``alarm`` 事件。

验签与重放认领在同一把锁里完成，并发提交同一信封只有一条能放行。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..audit import AuditLog
from ..clock import Clock
from ..errors import RailError
from ..eventbus import Event, EventBus
from .envelope import CommandEnvelope
from .keys import RETIRED, KeyRing
from .replay import ReplayGuard

# 验签结论（reason 取值）。
OK = "ok"
MALFORMED = "malformed"
UNKNOWN_KIND = "unknown_kind"
UNKNOWN_KEY = "unknown_key"
KEY_RETIRED = "key_retired"
BAD_SIGNATURE = "bad_signature"
TTL_EXCEEDED = "ttl_exceeded"
NOT_YET_VALID = "not_yet_valid"
EXPIRED = "expired"
REPLAY = "replay"


@dataclass(frozen=True)
class Verdict:
    """一条指令的验签结论。"""

    ok: bool
    reason: str
    command_id: str
    kind: str
    kid: str
    key_state: str
    audit_id: str
    envelope: CommandEnvelope | None

    def as_dict(self) -> dict:
        """转成可放进响应与审计的字典（不含信封本体）。"""

        return {
            "ok": self.ok,
            "reason": self.reason,
            "command_id": self.command_id,
            "kind": self.kind,
            "kid": self.kid,
            "key_state": self.key_state,
            "audit_id": self.audit_id,
        }


class CommandGate:
    """验签闸门：先验签、再放行，结论逐条落审计。"""

    def __init__(
        self,
        keys: KeyRing,
        replay: ReplayGuard,
        clock: Clock,
        audit: AuditLog,
        bus: EventBus,
        kinds: tuple[str, ...],
        max_ttl_s: float,
        clock_skew_s: float,
    ) -> None:
        self._keys = keys
        self._replay = replay
        self._clock = clock
        self._audit = audit
        self._bus = bus
        self._kinds = tuple(kinds)
        self._max_ttl_s = max_ttl_s
        self._clock_skew_s = clock_skew_s
        self._lock = threading.RLock()
        self._accepted = 0
        self._rejected = 0
        self._by_reason: dict[str, int] = {}

    def submit(self, raw: object) -> Verdict:
        """验签一条指令信封；通过则认领（防重放）并放行。"""

        with self._lock:
            now = self._clock.now()
            for tombstone in self._keys.sweep(now):
                self._audit.record("sec_key_retired", "", "", kid=tombstone.kid, at=tombstone.retired_at)
            try:
                envelope = CommandEnvelope.from_dict(raw)
            except RailError:
                return self._reject(MALFORMED, "", "", "", "")
            if envelope.kind not in self._kinds:
                return self._reject(UNKNOWN_KIND, envelope.id, envelope.kind, envelope.kid, "")
            record = self._keys.get(envelope.kid)
            if record is None:
                return self._reject(UNKNOWN_KEY, envelope.id, envelope.kind, envelope.kid, "")
            if record.state == RETIRED:
                return self._reject(KEY_RETIRED, envelope.id, envelope.kind, envelope.kid, RETIRED)
            if not envelope.verify(record.material_bytes()):
                return self._reject(
                    BAD_SIGNATURE, envelope.id, envelope.kind, envelope.kid, record.state
                )
            if envelope.ttl_s > self._max_ttl_s:
                return self._reject(
                    TTL_EXCEEDED, envelope.id, envelope.kind, envelope.kid, record.state
                )
            if envelope.issued_at > now + self._clock_skew_s:
                return self._reject(
                    NOT_YET_VALID, envelope.id, envelope.kind, envelope.kid, record.state
                )
            if envelope.expires_at() < now:
                return self._reject(EXPIRED, envelope.id, envelope.kind, envelope.kid, record.state)
            if not self._replay.claim(envelope.id, envelope.nonce, envelope.expires_at(), now):
                return self._reject(REPLAY, envelope.id, envelope.kind, envelope.kid, record.state)
            return self._accept(envelope, record.state)

    def release(self, command_id: str) -> None:
        """执行失败回滚时撤销认领，让发送方能原样重试。"""

        with self._lock:
            self._replay.release(command_id)

    def status(self) -> dict:
        """返回闸门计数，供状态接口展示。"""

        with self._lock:
            return {
                "accepted": self._accepted,
                "rejected": self._rejected,
                "by_reason": dict(sorted(self._by_reason.items())),
                "replay_seen": self._replay.size(),
                "kinds": list(self._kinds),
                "max_ttl_s": self._max_ttl_s,
                "clock_skew_s": self._clock_skew_s,
            }

    def _accept(self, envelope: CommandEnvelope, key_state: str) -> Verdict:
        entry = self._audit.record(
            "command_verified",
            "",
            "",
            command_id=envelope.id,
            command_kind=envelope.kind,
            kid=envelope.kid,
            key_state=key_state,
            expires_at=envelope.expires_at(),
        )
        self._accepted += 1
        self._by_reason[OK] = self._by_reason.get(OK, 0) + 1
        return Verdict(True, OK, envelope.id, envelope.kind, envelope.kid, key_state, entry.id, envelope)

    def _reject(self, reason: str, command_id: str, kind: str, kid: str, key_state: str) -> Verdict:
        entry = self._audit.record(
            "command_rejected",
            "",
            "",
            command_id=command_id,
            command_kind=kind,
            kid=kid,
            key_state=key_state,
            reason=reason,
        )
        self._rejected += 1
        self._by_reason[reason] = self._by_reason.get(reason, 0) + 1
        self._bus.publish(
            Event.of(
                "audit",
                "sec",
                "command_rejected",
                severity="alarm",
                command_id=command_id,
                kind=kind,
                kid=kid,
                reason=reason,
                message=f"指令被拒绝（{reason}），已丢弃",
            )
        )
        return Verdict(False, reason, command_id, kind, kid, key_state, entry.id, None)


# 让模块常量对验签顺序的读者可见。
__all__ = [
    "CommandGate",
    "Verdict",
    "OK",
    "MALFORMED",
    "UNKNOWN_KIND",
    "UNKNOWN_KEY",
    "KEY_RETIRED",
    "BAD_SIGNATURE",
    "TTL_EXCEEDED",
    "NOT_YET_VALID",
    "EXPIRED",
    "REPLAY",
]
