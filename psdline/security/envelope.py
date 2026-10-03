"""指令信封与签名原语（HMAC-SHA256 / HS256，纯标准库）。

一条开关指令在网络上就是一个 JSON 信封::

    {
      "kid": "key-0001",          # 用哪把密钥签的
      "alg": "HS256",
      "nonce": "唯一随机串",       # 一条指令一个，消费后落盘
      "iat": 1758000000,          # 签发时间（Unix 秒）
      "exp": 1758000120,          # 过期时间；过期指令一律不放行
      "action": "/api/arrive",    # 授权范围：这条指令只能打这个接口
      "unit": "line1",            # 运行单元，跨单元重放直接拒
      "body": { ... },            # 真正的接口参数
      "sig": "hex(HMAC(...))"
    }

签名串是把除 ``sig`` 外的字段按固定顺序、紧凑 JSON（分隔符 ``,``/``:``、不做
ASCII 转义、``sort_keys=True``）重新序列化后的 UTF-8 字节。信封是自描述的，
不依赖传输层给的路径或时间——门控"只认内容不认来源"，防伪也只信信封自身。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets as pysecrets
from dataclasses import dataclass
from typing import Any

from ..errors import SecurityError

ALGORITHM = "HS256"
SIGNED_FIELDS = ("alg", "nonce", "iat", "exp", "action", "unit", "body", "kid")
ENVELOPE_FIELDS = (*SIGNED_FIELDS, "sig")


def canonical_json(value: Any) -> bytes:
    """把待签名内容序列化成收发双方一致的字节串。"""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def signing_string(envelope: dict) -> bytes:
    """从信封里取出待签名字段并规范化。"""

    return canonical_json({field: envelope.get(field) for field in SIGNED_FIELDS})


def compute_signature(secret: bytes, envelope: dict) -> str:
    """用共享密钥计算信封签名（小写十六进制）。"""

    return hmac.new(secret, signing_string(envelope), hashlib.sha256).hexdigest()


def sign(
    secret: bytes | str,
    *,
    kid: str,
    nonce: str,
    iat: float,
    exp: float,
    action: str,
    unit: str,
    body: dict,
) -> dict:
    """构造一个完整签名信封，供签发侧工具使用。"""

    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    envelope = {
        "kid": str(kid),
        "alg": ALGORITHM,
        "nonce": str(nonce),
        "iat": float(iat),
        "exp": float(exp),
        "action": str(action),
        "unit": str(unit),
        "body": dict(body),
    }
    envelope["sig"] = compute_signature(key, envelope)
    return envelope


def new_nonce() -> str:
    """生成一个 128 位随机 nonce（URL 安全的十六进制串）。"""

    return pysecrets.token_hex(16)


def new_secret(num_bytes: int = 32) -> str:
    """生成一把新的 HMAC 共享密钥（十六进制）。"""

    return pysecrets.token_hex(num_bytes)


@dataclass(frozen=True)
class ParsedEnvelope:
    """解析并初步规整后的信封。"""

    kid: str
    nonce: str
    iat: float
    exp: float
    action: str
    unit: str
    body: dict
    sig: str

    @classmethod
    def from_payload(cls, payload: object) -> "ParsedEnvelope":
        """从请求体解析信封；结构错误直接抛 :class:`SecurityError`。"""

        if not isinstance(payload, dict):
            raise SecurityError("指令信封必须是 JSON 对象", reason="malformed")
        missing = [field for field in ENVELOPE_FIELDS if field not in payload]
        if missing:
            raise SecurityError(f"信封缺少字段: {','.join(missing)}", reason="malformed")
        if str(payload.get("alg", "")) != ALGORITHM:
            raise SecurityError(
                f"不支持的签名算法: {payload.get('alg')!r}", reason="bad_algorithm"
            )
        sig = str(payload.get("sig", ""))
        if not sig or any(ch not in "0123456789abcdef" for ch in sig.lower()) or len(sig) != 64:
            raise SecurityError("签名必须是 64 位十六进制串", reason="malformed_signature")
        try:
            iat = float(payload["iat"])
            exp = float(payload["exp"])
        except (TypeError, ValueError) as error:
            raise SecurityError("iat/exp 必须是数值时间戳", reason="bad_timestamp") from error
        body = payload.get("body")
        if not isinstance(body, dict):
            raise SecurityError("信封 body 必须是 JSON 对象", reason="malformed_body")
        nonce = str(payload.get("nonce", ""))
        if not nonce:
            raise SecurityError("nonce 为空", reason="malformed")
        return cls(
            kid=str(payload.get("kid", "")),
            nonce=nonce,
            iat=iat,
            exp=exp,
            action=str(payload.get("action", "")),
            unit=str(payload.get("unit", "")),
            body=body,
            sig=sig.lower(),
        )

    def as_envelope(self) -> dict:
        """还原成完整信封字典（用于重算签名与隔离区留证）。"""

        return {
            "kid": self.kid,
            "alg": ALGORITHM,
            "nonce": self.nonce,
            "iat": self.iat,
            "exp": self.exp,
            "action": self.action,
            "unit": self.unit,
            "body": dict(self.body),
            "sig": self.sig,
        }
