"""验签器：把一条原始报文变成一个确定的验签结论。

判定严格按下面的顺序进行，每一步失败都给出稳定的机器码，审计按机器码统计：

1. ``malformed``        信封结构 / 字段 / 算法 / 签名格式不对
2. ``unknown_kid``      密钥标识在环里查不到（含已退役墓碑）
3. ``key_revoked``      命中的密钥已被吊销
4. ``bad_timestamp``    ``iat`` 超过收发时钟偏差窗口（防提前生效/回拨）
5. ``expired``          当前时间已过 ``exp``（过期指令一律不放行）
6. ``bad_unit``         信封单元与本运行单元不一致（防跨单元重放）
7. ``action_mismatch``  报文实际投递路径与信封授权 ``action`` 不一致
8. ``bad_signature``    HMAC 不匹配（密钥轮换期间依次尝试 active/grace）
9. ``replay``           nonce 已在台账里（重放）

只有 9 步全部通过才返回 :meth:`Verdict.accepted`。
"""

from __future__ import annotations

import hmac as hmac_mod
from dataclasses import dataclass, field
from typing import Any

from ..errors import SecurityError
from .envelope import ParsedEnvelope, compute_signature
from .keyring import RETIRED, REVOKED, KeyRing
from .nonces import NonceLedger

# 稳定的判定码顺序（审计与文档都引用这里，避免散落字符串）。
REASON_MALFORMED = "malformed"
REASON_UNKNOWN_KID = "unknown_kid"
REASON_KEY_REVOKED = "key_revoked"
REASON_KEY_RETIRED = "key_retired"
REASON_BAD_TIMESTAMP = "bad_timestamp"
REASON_EXPIRED = "expired"
REASON_BAD_UNIT = "bad_unit"
REASON_ACTION_MISMATCH = "action_mismatch"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_REPLAY = "replay"
REASON_NO_KEYS = "no_keys"

ACCEPTED = "accepted"


@dataclass
class Verdict:
    """一次验签的完整结论。"""

    accepted: bool
    reason: str = ACCEPTED
    message: str = ""
    envelope: ParsedEnvelope | None = None
    kid: str = ""
    checks: list[dict] = field(default_factory=list)

    def reject(self, reason: str, message: str) -> "Verdict":
        self.accepted = False
        self.reason = reason
        self.message = message
        return self

    def as_dict(self) -> dict:
        return {
            "accepted": self.accepted,
            "reason": self.reason,
            "message": self.message,
            "kid": self.kid,
            "nonce": self.envelope.nonce if self.envelope else "",
            "checks": list(self.checks),
        }


class Verifier:
    """无状态验签器：只依赖密钥环、nonce 台账与时钟/策略参数。"""

    def __init__(
        self,
        keyring: KeyRing,
        nonces: NonceLedger,
        *,
        unit: str,
        ttl_s: float,
        max_skew_s: float,
        clock,
    ) -> None:
        self._keys = keyring
        self._nonces = nonces
        self._unit = unit
        self._ttl_s = float(ttl_s)
        self._skew = float(max_skew_s)
        self._clock = clock

    def verify(self, raw: Any, path: str) -> Verdict:
        """验签一条原始报文；只判定不消费 nonce，消费由守卫原子完成。"""

        verdict = Verdict(accepted=True)
        now = self._clock.now()
        # 先把并存期到期的 grace 钥落盘退役，保证第 3 步读到的状态是权威的。
        self._keys.retire_expired(now)

        # 1. 结构解析
        try:
            envelope = ParsedEnvelope.from_payload(raw)
        except SecurityError as error:
            return verdict.reject(error.reason, error.message)
        verdict.envelope = envelope
        verdict.kid = envelope.kid
        verdict.checks.append({"step": "shape", "ok": True})

        # 2. kid 能否在环里找到（墓碑也算找到，但状态会在下一步被拒）
        record = self._keys.get(envelope.kid)
        if record is None:
            verdict.checks.append({"step": "kid", "ok": False, "kid": envelope.kid})
            return verdict.reject(REASON_UNKNOWN_KID, f"未知密钥标识: {envelope.kid}")
        verdict.checks.append({"step": "kid", "ok": True, "kid": envelope.kid, "state": record.state})

        # 3. 吊销立即拒；退役（并存期已过、材料已擦除）同样拒绝但区分原因
        if record.state == REVOKED:
            return verdict.reject(
                REASON_KEY_REVOKED, f"密钥 {envelope.kid} 已吊销，指令一律拒绝"
            )
        if record.state == RETIRED:
            return verdict.reject(
                REASON_KEY_RETIRED,
                f"密钥 {envelope.kid} 并存期已过并退役，请用当前 active 密钥重签",
            )

        # 4. 签发时间窗口（iat 不能在未来超过 skew，也不能久远到超过 TTL+skew）
        if envelope.iat > now + self._skew:
            return verdict.reject(
                REASON_BAD_TIMESTAMP,
                f"签发时间在未来 {envelope.iat - now:.1f}s，超过偏差容限 {self._skew:.0f}s",
            )
        if envelope.iat < now - self._ttl_s - self._skew:
            return verdict.reject(
                REASON_EXPIRED,
                f"指令签发于 {now - envelope.iat:.1f}s 前，已超过有效期 {self._ttl_s:.0f}s",
            )

        # 5. 显式过期时间
        if envelope.exp < now:
            return verdict.reject(
                REASON_EXPIRED,
                f"指令已于 {now - envelope.exp:.1f}s 前过期，不予放行",
            )
        if envelope.exp - envelope.iat > self._ttl_s + self._skew:
            return verdict.reject(
                REASON_BAD_TIMESTAMP,
                f"指令有效期 {envelope.exp - envelope.iat:.1f}s 超过上限 {self._ttl_s:.0f}s",
            )

        # 6. 运行单元
        if envelope.unit != self._unit:
            return verdict.reject(
                REASON_BAD_UNIT,
                f"指令属于单元 {envelope.unit!r}，本单元为 {self._unit!r}",
            )

        # 7. action 授权范围必须与实际投递路径一致
        if envelope.action != path:
            return verdict.reject(
                REASON_ACTION_MISMATCH,
                f"信封授权 {envelope.action!r} 与实际路径 {path!r} 不一致",
            )

        # 8. 验签：轮换并存期内 active/grace 都要试，记录命中的是哪把
        secret = self._keys.secret_of(envelope.kid)
        if secret is None:
            return verdict.reject(
                REASON_UNKNOWN_KID, f"密钥 {envelope.kid} 已退役或不可用"
            )
        expected = compute_signature(secret.encode("utf-8"), envelope.as_envelope())
        if not hmac_mod.compare_digest(expected, envelope.sig):
            verdict.checks.append({"step": "signature", "ok": False, "kid": envelope.kid})
            return verdict.reject(
                REASON_BAD_SIGNATURE, "签名校验失败：报文被篡改或密钥不匹配"
            )
        verdict.checks.append({"step": "signature", "ok": True, "kid": envelope.kid})

        # 9. 重放判定：只查台账。nonce 的消费（落盘 + auth_id 关联）由守卫在
        # 验签通过后、执行前的同一把指令锁内原子完成，保证"先烧 nonce 再执行"。
        prior = self._nonces.lookup(envelope.nonce)
        if prior is not None:
            verdict.checks.append(
                {"step": "nonce", "ok": False, "first_auth_id": prior.auth_id}
            )
            return verdict.reject(
                REASON_REPLAY,
                f"nonce 已使用（首次放行凭据 {prior.auth_id or prior.kid}），判定为重放",
            )
        verdict.checks.append({"step": "nonce", "ok": True})
        return verdict
