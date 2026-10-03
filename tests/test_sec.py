"""指令防伪：签名、验签、轮换、重放、并发与部分失败回滚。"""

from __future__ import annotations

import threading

import pytest

from psdline.app import build_platform
from psdline.config import config_from_mapping, config_to_mapping, default_config
from psdline.errors import ConfigError, RailError
from psdline.sec import CommandEnvelope


def _forged(platform, kind="door.enqueue", kid="k0000000000000000", material=b"\x01" * 32, **payload):
    """用平台不知道的密钥造一条信封（模拟伪造）。"""

    return CommandEnvelope.mint(
        "cmd-forged", kind, kid, platform.clock.now(), 30.0, payload, material
    ).as_dict()


def test_signed_command_executes_and_audits(platform):
    result = platform.submit_command(
        platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    )
    assert result["ok"] is True
    command_id = result["command_id"]
    # 队列里的指令记录了验签通过的密钥标识
    queued = platform.commands.pending("T01")
    assert [command.id for command in queued] == [command_id]
    assert queued[0].kid == result["verdict"]["kid"]
    # 审计能追到这条指令的验签结论与执行记录
    verified = [entry for entry in platform.audit.list() if entry.kind == "command_verified"]
    assert verified[-1].detail["command_id"] == command_id
    assert verified[-1].detail["key_state"] == "active"
    executed = [entry for entry in platform.audit.list() if entry.kind == "door_enqueue"]
    assert executed[-1].detail["command_id"] == command_id


def test_tampered_signature_rejected_and_alarmed(platform):
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    envelope["payload"]["kind"] = "close"  # 篡改载荷，签名失效
    rejected = platform.submit_command(envelope)
    assert rejected["ok"] is False
    assert rejected["verdict"]["reason"] == "bad_signature"
    assert platform.commands.pending("T01") == []
    alarms = [
        event
        for event in platform.bus.history("audit")
        if event.action == "command_rejected" and event.payload.get("severity") == "alarm"
    ]
    assert alarms and alarms[-1].payload["reason"] == "bad_signature"
    rejected_entries = [entry for entry in platform.audit.list() if entry.kind == "command_rejected"]
    assert rejected_entries[-1].detail["command_id"] == envelope["id"]


def test_forged_key_and_malformed_envelopes_rejected(platform):
    forged = platform.submit_command(_forged(platform, train_id="T01"))
    assert forged["verdict"]["reason"] == "unknown_key"
    malformed = platform.submit_command({"id": "cmd-x"})
    assert malformed["verdict"]["reason"] == "malformed"
    assert platform.submit_command("junk")["verdict"]["reason"] == "malformed"
    assert platform.command_gate.status()["rejected"] == 3


def test_unknown_kind_rejected(platform):
    record = platform.keys.active()
    envelope = CommandEnvelope.mint(
        "cmd-fly", "door.fly", record.kid, platform.clock.now(), 30.0, {}, record.material_bytes()
    )
    assert platform.submit_command(envelope.as_dict())["verdict"]["reason"] == "unknown_kind"
    with pytest.raises(RailError):
        platform.sign_command("door.fly", {})


def test_ttl_and_freshness_window(platform, clock):
    too_long = platform.sign_command("door.enqueue", {"train_id": "T01"}, ttl_s=9999.0)
    assert platform.submit_command(too_long)["verdict"]["reason"] == "ttl_exceeded"

    record = platform.keys.active()
    future = CommandEnvelope.mint(
        "cmd-future",
        "door.enqueue",
        record.kid,
        clock.now() + 60.0,
        30.0,
        {"train_id": "T01"},
        record.material_bytes(),
    )
    assert platform.submit_command(future.as_dict())["verdict"]["reason"] == "not_yet_valid"

    envelope = platform.sign_command("door.enqueue", {"train_id": "T01"})
    clock.advance(31.0)
    expired = platform.submit_command(envelope)
    assert expired["verdict"]["reason"] == "expired"
    assert platform.commands.pending("T01") == []


def test_replay_rejected_same_and_after_restart(platform, clock, tmp_path):
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    assert platform.submit_command(envelope)["ok"] is True
    replayed = platform.submit_command(envelope)
    assert replayed["ok"] is False
    assert replayed["verdict"]["reason"] == "replay"
    # 重放登记簿落了盘：换进程（重建平台）后同一条指令依然被拦
    rebuilt = build_platform(default_config(), clock=clock, storage_root=str(tmp_path / "state"))
    assert rebuilt.submit_command(envelope)["verdict"]["reason"] == "replay"


def test_replay_entries_pruned_after_expiry(platform, clock):
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01"})
    assert platform.submit_command(envelope)["ok"] is True
    clock.advance(31.0)
    assert platform.submit_command(envelope)["verdict"]["reason"] == "expired"
    fresh = platform.sign_command("door.enqueue", {"train_id": "T01"})
    assert platform.submit_command(fresh)["ok"] is True
    # 认领新指令时旧条目已随失效清理，登记簿里只剩新指令
    assert platform.replay.size() == 1


def test_rotation_grace_then_retirement(platform, clock):
    old = platform.keys.active()
    rotation = platform.rotate_keys()
    assert rotation["ok"] is True
    assert rotation["new_kid"] != old.kid
    assert rotation["grace_until"] == pytest.approx(clock.now() + 300.0)

    # 宽限期内：旧钥签的指令依然可验，验签结论标明用的是过渡密钥
    legacy = CommandEnvelope.mint(
        "cmd-legacy-1",
        "door.enqueue",
        old.kid,
        clock.now(),
        30.0,
        {"train_id": "T01", "kind": "open"},
        old.material_bytes(),
    )
    accepted = platform.submit_command(legacy.as_dict())
    assert accepted["ok"] is True
    assert accepted["verdict"]["key_state"] == "retiring"
    # 新钥签的指令照常放行
    fresh = platform.submit_command(platform.sign_command("door.enqueue", {"train_id": "T01"}))
    assert fresh["ok"] is True and fresh["verdict"]["key_state"] == "active"

    # 宽限期结束：旧钥退役、材料抹除，旧钥指令按 key_retired 拒收
    clock.advance(301.0)
    legacy_late = CommandEnvelope.mint(
        "cmd-legacy-2",
        "door.enqueue",
        old.kid,
        clock.now(),
        30.0,
        {"train_id": "T01", "kind": "open"},
        old.material_bytes(),
    )
    rejected = platform.submit_command(legacy_late.as_dict())
    assert rejected["verdict"]["reason"] == "key_retired"
    assert platform.keys.get(old.kid).material_bytes() == b""

    kinds = [entry.kind for entry in platform.audit.list()]
    assert "sec_key_rotated" in kinds
    assert "sec_key_retired" in kinds


def test_concurrent_identical_envelope_single_winner(platform):
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    results = []
    lock = threading.Lock()

    def worker() -> None:
        outcome = platform.submit_command(envelope)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(1 for outcome in results if outcome["ok"]) == 1
    assert sum(1 for outcome in results if outcome["verdict"]["reason"] == "replay") == 15
    assert len(platform.commands.pending("T01")) == 1


def test_concurrent_distinct_envelopes_all_pass(platform):
    envelopes = [
        platform.sign_command("door.enqueue", {"train_id": f"T{i:02d}", "kind": "open"})
        for i in range(16)
    ]
    results = []
    lock = threading.Lock()

    def worker(envelope) -> None:
        outcome = platform.submit_command(envelope)
        with lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker, args=(envelope,)) for envelope in envelopes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(outcome["ok"] for outcome in results)
    assert platform.command_gate.status()["accepted"] == 16


def test_enqueue_rolls_back_when_audit_fails(platform, monkeypatch):
    original = platform.audit.record

    def broken(kind, *args, **kwargs):
        if kind == "door_enqueue":
            raise RuntimeError("audit sink down")
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(platform.audit, "record", broken)
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    with pytest.raises(RuntimeError):
        platform.submit_command(envelope)
    # 队列已回撤、认领已释放，审计里留下了回滚记录
    assert platform.commands.pending("T01") == []
    assert platform.replay.size() == 0
    kinds = [entry.kind for entry in platform.audit.list()]
    assert "command_rolled_back" in kinds
    # 修复后同一信封可原样重试
    monkeypatch.setattr(platform.audit, "record", original)
    assert platform.submit_command(envelope)["ok"] is True


def test_clear_fault_rolls_back_to_locked_when_audit_fails(platform, sign, monkeypatch):
    gate = platform.gates.by_station("ST1")[0]
    sign("interlock.set_fault", psd_id=gate.id)
    original = platform.audit.record

    def broken(kind, *args, **kwargs):
        if kind == "interlock_clear":
            raise RuntimeError("audit sink down")
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(platform.audit, "record", broken)
    with pytest.raises(RuntimeError):
        sign("interlock.clear_fault", psd_id=gate.id)
    # 回滚到安全侧：故障重新置位、门重新锁定
    assert platform.faults.state(gate.id) == "active"
    assert platform.lockouts.is_locked(gate.id) is True


def test_batch_open_rolls_back_by_closing_station(platform, monkeypatch):
    original = platform.audit.record

    def broken(kind, *args, **kwargs):
        if kind == "batch_open":
            raise RuntimeError("audit sink down")
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(platform.audit, "record", broken)
    envelope = platform.sign_command("door.batch_open", {"station_id": "ST1"})
    with pytest.raises(RuntimeError):
        platform.submit_command(envelope)
    assert platform.gates.count_open() == 0


def test_arm_rolls_back_when_audit_fails(platform, monkeypatch):
    original = platform.audit.record

    def broken(kind, *args, **kwargs):
        if kind == "interlock_arm":
            raise RuntimeError("audit sink down")
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(platform.audit, "record", broken)
    envelope = platform.sign_command("interlock.arm", {"train_id": "T01", "armed": True})
    with pytest.raises(RuntimeError):
        platform.submit_command(envelope)
    assert platform.armers.armed("T01") is False


def test_missing_payload_field_releases_claim(platform):
    envelope = platform.sign_command("door.enqueue", {"kind": "open"})
    with pytest.raises(RailError):
        platform.submit_command(envelope)
    assert platform.replay.size() == 0


def test_interlock_commands_via_signed_envelopes(platform, sign):
    gate = platform.gates.by_station("ST1")[0]
    assert sign("interlock.set_fault", psd_id=gate.id)["locked"] is True
    assert platform.lockouts.is_locked(gate.id) is True
    assert sign("interlock.clear_fault", psd_id=gate.id)["ok"] is True
    assert platform.lockouts.is_locked(gate.id) is False
    assert sign("interlock.arm", train_id="T01", armed=True)["armed"] is True
    assert platform.armers.armed("T01") is True
    # 未验签的旧入口已经不存在
    for name in ("set_fault", "clear_fault", "arm", "enqueue", "batch_open"):
        assert not hasattr(platform, name)


def test_sec_status_hides_key_material(platform):
    status = platform.sec_status()
    assert status["active_kid"]
    assert status["gate"]["kinds"]
    for key in status["keys"]:
        assert "material_hex" not in key
        assert "material" not in key


def test_config_enforces_grace_covers_ttl():
    payload = config_to_mapping(default_config())
    payload["sec"]["rotation_grace_s"] = 10.0  # 小于指令有效期 30s
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
    payload["sec"]["rotation_grace_s"] = 0.0  # 显式硬切换是允许的
    config_from_mapping(payload)
    payload["sec"]["command_ttl_s"] = 0.0
    with pytest.raises(ConfigError):
        config_from_mapping(payload)
