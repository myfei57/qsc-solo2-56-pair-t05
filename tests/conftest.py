"""测试夹具：所有用例都从干净存储、可推进时钟、独立密钥目录起步。"""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from psdline.app import Platform, build_platform  # noqa: E402
from psdline.clock import ManualClock  # noqa: E402
from psdline.config import default_config  # noqa: E402
from psdline.console.api import Api  # noqa: E402
from psdline.security import Signer  # noqa: E402


@pytest.fixture()
def clock() -> ManualClock:
    return ManualClock()


@pytest.fixture()
def platform(tmp_path, clock) -> Platform:
    config = default_config()
    config = replace(
        config,
        platform=replace(config.platform, storage_root=str(tmp_path / "state")),
        security=replace(config.security, secrets_root=str(tmp_path / "secrets")),
    )
    return build_platform(config, clock=clock)


@pytest.fixture()
def online(platform) -> Platform:
    """已到站、已开门、已确认间隙的平台。"""

    platform.start()
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    return platform


@pytest.fixture()
def signer(platform) -> Signer:
    """用当前 active 密钥、绑定平台时钟与单元的签发器。"""

    active = platform.keyring.active()
    return Signer(active.secret, active.kid, unit=platform.unit, clock=platform.clock)


@pytest.fixture()
def signed_post(platform, signer):
    """返回 ``post(path, body)`` 帮助函数：自动签名信封并走控制台守卫。"""

    api = Api(platform)

    def post(path: str, body: dict | None = None, **overrides):
        envelope = signer.envelope(path, body or {}, **overrides)
        return api.handle("POST", path, {}, envelope)

    return post
