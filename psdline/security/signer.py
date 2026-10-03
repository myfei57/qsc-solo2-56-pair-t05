"""签发侧客户端。

门控服务只持有验签能力；真正的签名动作发生在上位机 / 值班工具侧。:class:`Signer`
是它们的参考实现，也被命令行 ``psdline sign`` 与测试使用：给定一把带 kid 的
密钥、目标 action 与正文，产出一个可直接 POST 的签名信封。

签发侧只需知道三件事：共享密钥、本单元标识、默认有效期。时钟可注入，便于
复现；nonce 每次自动生成（也可显式传入做重放测试）。
"""

from __future__ import annotations

import json
from typing import Any

from .envelope import new_nonce, sign


class Signer:
    """构造签名指令信封的签发侧工具。"""

    def __init__(
        self,
        secret: str,
        kid: str,
        *,
        unit: str,
        ttl_s: float = 120.0,
        clock=None,
    ) -> None:
        self._secret = secret
        self._kid = kid
        self._unit = unit
        self._ttl_s = float(ttl_s)
        self._clock = clock

    @property
    def kid(self) -> str:
        return self._kid

    def envelope(
        self,
        action: str,
        body: dict | None = None,
        *,
        nonce: str | None = None,
        iat: float | None = None,
        ttl_s: float | None = None,
        unit: str | None = None,
    ) -> dict:
        """签出一个完整信封。"""

        moment = self._now() if iat is None else float(iat)
        ttl = self._ttl_s if ttl_s is None else float(ttl_s)
        return sign(
            self._secret,
            kid=self._kid,
            nonce=nonce or new_nonce(),
            iat=moment,
            exp=moment + ttl,
            action=action,
            unit=unit or self._unit,
            body=dict(body or {}),
        )

    def sealed(self, action: str, body: dict | None = None, **kwargs: Any) -> bytes:
        """签出并编码成可直接作为 HTTP 请求体的 JSON 字节。"""

        return json.dumps(self.envelope(action, body, **kwargs), ensure_ascii=False).encode("utf-8")

    def _now(self) -> float:
        if self._clock is not None:
            return self._clock.now()
        import time

        return time.time()
