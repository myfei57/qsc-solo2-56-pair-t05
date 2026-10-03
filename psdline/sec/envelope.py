"""签名指令信封。

门控与联锁指令不再"只认内容"：每一条外部指令都必须装进信封，信封上带密钥标识
（``kid``）、签发时间、有效期、随机数与 HMAC-SHA256 签名。签名覆盖除签名本身
以外的全部字段，任何字段被改动都会验签失败。

信封的规范序列化（键排序、无空白、UTF-8）是签名双方唯一的共识基础，因此
:meth:`CommandEnvelope.canonical` 不允许调用方自定义格式。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, replace

from ..errors import SecurityError

_SIGNATURE_FIELD = "signature"


@dataclass(frozen=True)
class CommandEnvelope:
    """一条带签名的指令信封。"""

    id: str
    kind: str
    kid: str
    issued_at: float
    ttl_s: float
    nonce: str
    payload: dict
    signature: str

    @classmethod
    def mint(
        cls,
        command_id: str,
        kind: str,
        kid: str,
        issued_at: float,
        ttl_s: float,
        payload: dict,
        material: bytes,
    ) -> "CommandEnvelope":
        """用给定密钥材料签发出一条新信封。"""

        envelope = cls(
            id=command_id,
            kind=kind,
            kid=kid,
            issued_at=float(issued_at),
            ttl_s=float(ttl_s),
            nonce=secrets.token_hex(16),
            payload=dict(payload),
            signature="",
        )
        return replace(envelope, signature=envelope.sign(material))

    @classmethod
    def from_dict(cls, raw: object) -> "CommandEnvelope":
        """从请求体解析信封；字段缺失或类型不对一律视为格式非法。"""

        if not isinstance(raw, dict):
            raise SecurityError("指令信封必须是 JSON 对象", component="sec")

        def text(key: str) -> str:
            value = raw.get(key)
            if not isinstance(value, str) or not value:
                raise SecurityError(f"指令信封字段 {key!r} 缺失或不是字符串", component="sec")
            return value

        def number(key: str) -> float:
            value = raw.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SecurityError(f"指令信封字段 {key!r} 缺失或不是数值", component="sec")
            return float(value)

        payload = raw.get("payload")
        if not isinstance(payload, dict):
            raise SecurityError("指令信封字段 'payload' 缺失或不是对象", component="sec")
        return cls(
            id=text("id"),
            kind=text("kind"),
            kid=text("kid"),
            issued_at=number("issued_at"),
            ttl_s=number("ttl_s"),
            nonce=text("nonce"),
            payload=dict(payload),
            signature=text("signature"),
        )

    def as_dict(self) -> dict:
        """序列化成可传输、可落盘的字典。"""

        return {
            "id": self.id,
            "kind": self.kind,
            "kid": self.kid,
            "issued_at": self.issued_at,
            "ttl_s": self.ttl_s,
            "nonce": self.nonce,
            "payload": dict(self.payload),
            "signature": self.signature,
        }

    def canonical(self) -> bytes:
        """签名用的规范序列化：键排序、无空白、不含签名字段。"""

        body = {key: value for key, value in self.as_dict().items() if key != _SIGNATURE_FIELD}
        return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def sign(self, material: bytes) -> str:
        """用密钥材料对规范序列化做 HMAC-SHA256，返回十六进制签名。"""

        return hmac.new(material, self.canonical(), hashlib.sha256).hexdigest()

    def verify(self, material: bytes) -> bool:
        """恒定时间比对签名；密钥材料为空（已退役）时直接失败。"""

        if not material:
            return False
        return hmac.compare_digest(self.signature, self.sign(material))

    def expires_at(self) -> float:
        """返回信封失效时刻（签发时间 + 有效期）。"""

        return self.issued_at + self.ttl_s
