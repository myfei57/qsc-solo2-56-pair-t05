"""指令防伪。

外部门控／联锁指令一律以签名信封提交：:class:`CommandEnvelope` 定义信封与签名，
:class:`KeyRing` 管理密钥的引导、轮换与退役，:class:`ReplayGuard` 防重放，
:class:`CommandGate` 把三者串成"先验签、再放行"的唯一入口，并把每条指令的验签
结论写进审计。
"""

from __future__ import annotations

from .envelope import CommandEnvelope
from .gate import CommandGate, Verdict
from .keys import ACTIVE, RETIRED, RETIRING, KeyRecord, KeyRing
from .replay import ReplayGuard

__all__ = [
    "ACTIVE",
    "RETIRED",
    "RETIRING",
    "CommandEnvelope",
    "CommandGate",
    "KeyRecord",
    "KeyRing",
    "ReplayGuard",
    "Verdict",
]
