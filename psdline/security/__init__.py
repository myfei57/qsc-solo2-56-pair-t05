"""指令防伪：每条门控指令先验签再执行。

模块边界：

* :mod:`psdline.security.envelope`  信封结构与 HMAC-SHA256 签名原语
* :mod:`psdline.security.keyring`   密钥环（active/grace/retired/revoked 轮换）
* :mod:`psdline.security.nonces`    落盘 nonce 台账（防重放）
* :mod:`psdline.security.verifier`  九步有序验签判定
* :mod:`psdline.security.quarantine` 失败指令隔离区（hold 模式留证）
* :mod:`psdline.security.board`     连续失败告警牌
* :mod:`psdline.security.guard`     指令守卫：串行验签→消费 nonce→事务执行→回滚
* :mod:`psdline.security.signer`    签发侧客户端（CLI / 上位机集成参考）
"""

from __future__ import annotations

from .board import SecurityBoard
from .envelope import (
    ALGORITHM,
    ParsedEnvelope,
    compute_signature,
    new_nonce,
    new_secret,
    sign,
)
from .guard import ENFORCE, HOLD, OBSERVE, Guard
from .keyring import (
    ACTIVE,
    GRACE,
    RETIRED,
    REVOKED,
    KeyRecord,
    KeyRing,
    fingerprint,
)
from .nonces import NonceLedger, NonceRecord
from .quarantine import DISMISSED, HELD, REISSUED, HeldCommand, Quarantine
from .signer import Signer
from .verifier import Verifier
from .verifier import (
    ACCEPTED,
    REASON_ACTION_MISMATCH,
    REASON_BAD_SIGNATURE,
    REASON_BAD_TIMESTAMP,
    REASON_BAD_UNIT,
    REASON_EXPIRED,
    REASON_KEY_REVOKED,
    REASON_KEY_RETIRED,
    REASON_MALFORMED,
    REASON_REPLAY,
    REASON_UNKNOWN_KID,
    Verdict,
)

__all__ = [
    "ACCEPTED",
    "ACTIVE",
    "ALGORITHM",
    "DISMISSED",
    "ENFORCE",
    "GRACE",
    "Guard",
    "HELD",
    "HOLD",
    "HeldCommand",
    "KeyRecord",
    "KeyRing",
    "NonceLedger",
    "NonceRecord",
    "OBSERVE",
    "ParsedEnvelope",
    "Quarantine",
    "REASON_ACTION_MISMATCH",
    "REASON_BAD_SIGNATURE",
    "REASON_BAD_TIMESTAMP",
    "REASON_BAD_UNIT",
    "REASON_EXPIRED",
    "REASON_KEY_REVOKED",
    "REASON_KEY_RETIRED",
    "REASON_MALFORMED",
    "REASON_REPLAY",
    "REASON_UNKNOWN_KID",
    "REISSUED",
    "RETIRED",
    "REVOKED",
    "SecurityBoard",
    "Signer",
    "Verdict",
    "Verifier",
    "compute_signature",
    "fingerprint",
    "new_nonce",
    "new_secret",
    "sign",
]
