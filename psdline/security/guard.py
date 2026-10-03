"""指令守卫：门控系统唯一的指令入口闸门。

每条外部开关指令都按同一条原子链处理::

    取指令锁 → 验签（9 步判定）→ 落盘消费 nonce → 记验签审计
              → 存储事务内执行 → 成功提交 / 异常逆序回滚并记补偿审计

关键取舍：

* **验签失败默认丢弃并告警报错**（``enforce``）。``hold`` 模式把失败指令放进
  隔离区留证但永不执行；``observe`` 只记录不拦截，仅供上线灰度期对账。
* **nonce 先于执行落盘消费，且不参与回滚**：执行失败的指令也不能拿原报文
  重发，必须由签发侧用新 nonce 重签，从根上断掉重放重试。
* **业务拒绝（:class:`RailError`，如联锁条件不满足）不回滚**，维持既有
  400/409 语义；**非预期异常才判定为部分失败**，存储事务逆序恢复全部落盘
  状态、遥测计数恢复到执行前，并追加 ``command_rolled_back`` 补偿审计。
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from ..audit import AuditLog
from ..clock import Clock
from ..errors import RailError
from ..ids import IdFactory
from ..store import JsonStore
from .board import SecurityBoard
from .envelope import ParsedEnvelope
from .keyring import KeyRing
from .nonces import NonceLedger
from .quarantine import Quarantine
from .verifier import ACCEPTED, Verifier

ENFORCE = "enforce"
HOLD = "hold"
OBSERVE = "observe"

Handler = Callable[[dict], dict]
Checkpoint = Callable[[], Any]
Restorer = Callable[[Any], None]


class Guard:
    """串行验签并执行外部指令。"""

    def __init__(
        self,
        *,
        keyring: KeyRing,
        nonces: NonceLedger,
        quarantine: Quarantine,
        board: SecurityBoard,
        verifier: Verifier,
        audit: AuditLog,
        store: JsonStore,
        clock: Clock,
        mode: str = ENFORCE,
        checkpoint: Checkpoint | None = None,
        restore: Restorer | None = None,
    ) -> None:
        self._keys = keyring
        self._nonces = nonces
        self._quarantine = quarantine
        self._board = board
        self._verifier = verifier
        self._audit = audit
        self._store = store
        self._clock = clock
        self._mode = mode
        self._checkpoint = checkpoint or (lambda: None)
        self._restore = restore or (lambda token: None)
        self._lock = threading.RLock()
        self._auth_ids = IdFactory("auth")
        self._accepted = 0
        self._executed = 0
        self._rolled_back = 0

    @property
    def mode(self) -> str:
        return self._mode

    def set_mode(self, mode: str) -> str:
        """切换防伪模式（运维灰度/应急使用，切换动作本身要走签名接口）。"""

        if mode not in (ENFORCE, HOLD, OBSERVE):
            raise RailError(f"未知防伪模式: {mode}", component="security")
        self._mode = mode
        return mode

    @property
    def board(self) -> SecurityBoard:
        return self._board

    @property
    def quarantine(self) -> Quarantine:
        return self._quarantine

    def counts(self) -> dict:
        return {
            "accepted": self._accepted,
            "executed": self._executed,
            "rolled_back": self._rolled_back,
            "mode": self._mode,
            "active_nonces": self._nonces.active_count(),
        }

    # ---- 主入口 -------------------------------------------------------

    def execute(self, raw: Any, path: str, handler: Handler, *, source: str = "") -> tuple[int, dict]:
        """验签并执行一条指令，返回 ``(HTTP 状态码, 响应体)``。"""

        with self._lock:
            now = self._clock.now()
            self._nonces.prune(now)
            verdict = self._verifier.verify(raw, path)

            if not verdict.accepted:
                return self._reject(verdict, raw, path, handler, source, now)

            return self._accept_and_run(verdict, handler, source, now)

    # ---- 拒绝分支 -----------------------------------------------------

    def _reject(
        self,
        verdict,
        raw: Any,
        path: str,
        handler: Handler,
        source: str,
        now: float,
    ) -> tuple[int, dict]:
        envelope = verdict.envelope
        detail = {
            "reason": verdict.reason,
            "action": envelope.action if envelope else path,
            "path": path,
            "kid": envelope.kid if envelope else "",
            "nonce": envelope.nonce if envelope else "",
            "source": source,
            "checks": verdict.checks,
            "mode": self._mode,
        }
        self._audit.record(
            "command_rejected",
            "",
            "",
            now,
            severity="alarm",
            **detail,
        )
        self._board.record_failure(
            reason=verdict.reason,
            source=source,
            at=now,
            detail={"action": detail["action"], "kid": detail["kid"], "nonce": detail["nonce"]},
        )

        if self._mode == OBSERVE:
            # 灰度观察：记录失败但不拦截，沿用旧式无信封正文执行。
            body = envelope.body if envelope else (raw if isinstance(raw, dict) else {})
            return self._run_legacy(body, handler, verdict, now)

        payload: dict = {
            "error": "SecurityError",
            "component": "security",
            "reason": verdict.reason,
            "message": verdict.message,
        }
        if self._mode == HOLD:
            held = self._quarantine.hold(
                at=now,
                reason=verdict.reason,
                message=verdict.message,
                envelope=envelope.as_envelope() if envelope else {"raw": raw},
                action=detail["action"],
                source=source,
            )
            self._audit.record(
                "command_held", "", "", now, severity="alarm", hold_id=held.hold_id,
                reason=verdict.reason, action=detail["action"],
            )
            payload["held"] = True
            payload["hold_id"] = held.hold_id
        else:
            payload["held"] = False
        return 401, payload

    def _run_legacy(self, body: dict, handler: Handler, verdict, now: float) -> tuple[int, dict]:
        """observe 模式放行（记一条 warning 审计），不做事务包裹。"""

        self._audit.record(
            "command_observe_pass",
            "",
            "",
            now,
            severity="alarm",
            reason=verdict.reason,
        )
        payload = handler(body)
        return 200, payload

    # ---- 接受分支 -----------------------------------------------------

    def _accept_and_run(self, verdict, handler: Handler, source: str, now: float) -> tuple[int, dict]:
        envelope: ParsedEnvelope = verdict.envelope  # type: ignore[assignment]
        auth_id = self._auth_ids.next()

        # 先落盘消费 nonce（不随事务回滚），再记验签结论。
        self._nonces.consume(
            envelope.nonce,
            kid=envelope.kid,
            action=envelope.action,
            consumed_at=now,
            auth_id=auth_id,
        )
        self._accepted += 1
        self._audit.record(
            "command_verified",
            "",
            "",
            now,
            auth_id=auth_id,
            kid=envelope.kid,
            nonce=envelope.nonce,
            action=envelope.action,
            unit=envelope.unit,
            iat=envelope.iat,
            exp=envelope.exp,
            age_s=round(now - envelope.iat, 3),
            source=source,
            result=ACCEPTED,
        )

        token = self._checkpoint()
        try:
            with self._store.transaction():
                with self._audit.scope(auth_id):
                    result = handler(envelope.body)
        except RailError:
            # 业务/联锁拒绝：不是部分失败，维持既有语义，不回滚已完成的落盘。
            raise
        except Exception as error:
            # 非预期异常：事务已逆序回滚落盘状态，再恢复遥测计数。
            self._restore(token)
            self._rolled_back += 1
            self._audit.record(
                "command_rolled_back",
                "",
                "",
                self._clock.now(),
                severity="alarm",
                auth_id=auth_id,
                nonce=envelope.nonce,
                action=envelope.action,
                error_type=type(error).__name__,
                message=str(error),
            )
            return 500, {
                "error": "PartialFailure",
                "component": "security",
                "message": f"指令执行部分失败，已回滚: {error}",
                "auth_id": auth_id,
                "rolled_back": True,
            }

        self._executed += 1
        self._audit.record(
            "command_executed",
            "",
            "",
            self._clock.now(),
            auth_id=auth_id,
            nonce=envelope.nonce,
            action=envelope.action,
            kid=envelope.kid,
        )
        if isinstance(result, dict):
            result = {**result, "auth_id": auth_id}
        return 200, result
