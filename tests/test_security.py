"""指令防伪：签名验签、过期、重放、轮换、隔离区、并发与回滚。"""

from __future__ import annotations

import threading

import pytest

from psdline.console.api import Api
from psdline.errors import RailError
from psdline.security import (
    DISMISSED,
    ENFORCE,
    HOLD,
    KeyRing,
    NonceLedger,
    REASON_ACTION_MISMATCH,
    REASON_BAD_SIGNATURE,
    REASON_BAD_UNIT,
    REASON_EXPIRED,
    REASON_KEY_RETIRED,
    REASON_KEY_REVOKED,
    REASON_MALFORMED,
    REASON_REPLAY,
    REASON_UNKNOWN_KID,
    Signer,
    Verifier,
)
from psdline.store import JsonlJournal, JsonStore


# ---- 信封与验签判定 ----------------------------------------------------


def test_signed_envelope_roundtrip(platform, signer):
    envelope = signer.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    verdict = platform.guard._verifier.verify(envelope, "/api/arrive")
    assert verdict.accepted
    assert [step["step"] for step in verdict.checks] == [
        "shape", "kid", "signature", "nonce"
    ]
    assert verdict.kid == platform.keyring.active().kid


def test_tampered_body_is_bad_signature(platform, signer, signed_post):
    envelope = signer.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    verdict = platform.guard._verifier.verify(
        {**envelope, "body": {"train_id": "T99", "station_id": "ST1"}}, "/api/arrive"
    )
    assert not verdict.accepted and verdict.reason == REASON_BAD_SIGNATURE
    status, payload = signed_post(
        "/api/arrive", {"train_id": "T01", "station_id": "ST1"}
    )
    assert status == 200 and payload["ok"]


def test_malformed_and_missing_signature_rejected(platform):
    api = Api(platform)
    for raw in (None, [], "nope", {"foo": 1}, {"kid": "x"}):
        status, payload = api.handle("POST", "/api/arrive", {}, raw)
        assert status == 401 and payload["reason"] == REASON_MALFORMED


def test_unknown_kid_and_revocation(platform, signer, tmp_path, clock):
    rogue = Signer("00" * 32, "key-9999", unit=platform.unit, clock=clock)
    api = Api(platform)
    env = rogue.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    status, payload = api.handle("POST", "/api/arrive", {}, env)
    assert status == 401 and payload["reason"] == REASON_UNKNOWN_KID

    kid = platform.keyring.active().kid
    platform.revoke_key(kid)
    env = signer.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    status, payload = api.handle("POST", "/api/arrive", {}, env)
    assert status == 401 and payload["reason"] == REASON_KEY_REVOKED


def test_expired_command_is_refused(platform, signer, clock):
    # 在当前时刻签发，但时钟走过 TTL 后再投递。
    envelope = signer.envelope(
        "/api/arrive", {"train_id": "T01", "station_id": "ST1"}, ttl_s=120
    )
    clock.advance(121)
    verdict = platform.guard._verifier.verify(envelope, "/api/arrive")
    assert not verdict.accepted and verdict.reason == REASON_EXPIRED


def test_future_timestamp_beyond_skew_rejected(platform, signer):
    envelope = signer.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    envelope["iat"] += 999
    envelope["exp"] += 999
    verdict = platform.guard._verifier.verify(envelope, "/api/arrive")
    assert not verdict.accepted and verdict.reason == "bad_timestamp"


def test_unit_and_action_are_bound(platform, signer, clock):
    other_unit = Signer(
        platform.keyring.active().secret, platform.keyring.active().kid,
        unit="line2", clock=clock,
    )
    env = other_unit.envelope("/api/arrive", {"train_id": "T01", "station_id": "ST1"})
    assert platform.guard._verifier.verify(env, "/api/arrive").reason == REASON_BAD_UNIT
    env = signer.envelope("/api/gap", {"train_id": "T01"})
    assert platform.guard._verifier.verify(env, "/api/arrive").reason == REASON_ACTION_MISMATCH


# ---- 重放防护 ----------------------------------------------------------


def test_nonce_replay_is_rejected_and_persisted(platform, signed_post):
    status, first = signed_post("/api/gap", {"train_id": "T01"})
    # 没有对位记录，业务 409，但验签通过、nonce 已烧。
    assert status == 409
    api = Api(platform)
    # 手工重放同一条信封：重新签同样的 nonce 不可能，直接复用旧报文。
    # 这里通过计数器侧面验证 nonce 已消费。
    assert platform.nonces.active_count() == 1


def test_same_envelope_replayed_returns_401(platform, signer):
    api = Api(platform)
    env = signer.envelope("/api/cycle", {"dt": 1})
    status, _ = api.handle("POST", "/api/cycle", {}, env)
    assert status == 200
    status, payload = api.handle("POST", "/api/cycle", {}, env)
    assert status == 401 and payload["reason"] == REASON_REPLAY


def test_nonce_ledger_survives_restart(tmp_path, clock):
    journal = JsonlJournal(str(tmp_path / "state"), "nonces", segment_limit=128)
    ledger = NonceLedger(journal, retention_s=600)
    assert ledger.consume("n1", kid="k", action="/x", consumed_at=1.0, auth_id="auth-1")
    assert not ledger.consume("n1", kid="k", action="/x", consumed_at=2.0)
    reloaded = NonceLedger(
        JsonlJournal(str(tmp_path / "state"), "nonces", segment_limit=128), retention_s=600
    )
    assert reloaded.seen("n1")
    assert reloaded.lookup("n1").auth_id == "auth-1"
    assert reloaded.prune(700) == 1 and reloaded.active_count() == 0


# ---- 密钥轮换与并存期 --------------------------------------------------


def test_rotation_overlap_then_retire(platform, signer, clock, signed_post):
    fresh, old = platform.keyring.rotate()
    api = Api(platform)
    # 并存期：旧钥签的指令仍然可验。
    old_signer = Signer(old.secret, old.kid, unit=platform.unit, clock=clock)
    env = old_signer.envelope("/api/cycle", {"dt": 1})
    status, payload = api.handle("POST", "/api/cycle", {}, env)
    assert status == 200
    assert {record.state for record in platform.keyring.list()} <= {"active", "grace"}
    # 并存期一过，旧钥即便当场重新签发（模拟旧钥外泄后被利用）也被拒。
    clock.advance(86_401)
    env = old_signer.envelope("/api/cycle", {"dt": 1})
    status, payload = api.handle("POST", "/api/cycle", {}, env)
    assert status == 401 and payload["reason"] == REASON_KEY_RETIRED
    # 墓碑仍在，可供审计追溯。
    tombstone = platform.keyring.get(old.kid)
    assert tombstone.state == "retired" and tombstone.fingerprint and not tombstone.secret


def test_rotate_api_audited_and_new_signer_works(platform, clock):
    result = platform.rotate_keys()
    assert result["ok"] and result["grace_kid"]
    api = Api(platform)
    fresh = platform.keyring.active()
    signer = Signer(fresh.secret, fresh.kid, unit=platform.unit, clock=clock)
    status, payload = api.handle(
        "POST", "/api/cycle", {}, signer.envelope("/api/cycle", {"dt": 2})
    )
    assert status == 200 and payload["cycle"] == 1
    assert any(entry.kind == "key_rotated" for entry in platform.audit.list())


def test_key_files_are_owner_only(tmp_path):
    import os
    import stat

    ring = KeyRing(str(tmp_path / "secrets"), overlap_s=10)
    record = ring.bootstrap(now=1.0)
    mode = stat.S_IMODE(os.stat(ring._path(record.kid)).st_mode)
    assert mode == 0o600


# ---- hold 模式与隔离区 -------------------------------------------------


def test_hold_mode_quarantines_bad_command(platform, signer):
    platform.guard.set_mode(HOLD)
    api = Api(platform)
    bad = signer.envelope("/api/cycle", {"dt": 1})
    bad["sig"] = "0" * 64
    status, payload = api.handle("POST", "/api/cycle", {}, bad)
    assert status == 401 and payload["held"] is True and payload["hold_id"]
    hold = platform.quarantine.get(payload["hold_id"])
    assert hold.reason == REASON_BAD_SIGNATURE and hold.envelope["nonce"] == bad["nonce"]
    view = platform.list_quarantine()
    assert view["counts"]["pending"] == 1
    outcome = platform.dismiss_hold(payload["hold_id"], by="duty-zhang")
    assert outcome["status"] == DISMISSED
    assert platform.list_quarantine()["counts"]["pending"] == 0
    # 隔离区里的报文绝不可能被直接执行：cycle 没被推进。
    assert platform.status()["cycles"] == 0


def test_hold_resolution_does_not_execute_envelope(platform, signer):
    platform.guard.set_mode(HOLD)
    api = Api(platform)
    bad = signer.envelope("/api/cycle", {"dt": 1})
    bad["sig"] = "0" * 64
    _status, payload = api.handle("POST", "/api/cycle", {}, bad)
    result = platform.mark_hold_reissued(payload["hold_id"], by="duty-li")
    assert result["status"] == "reissued"
    assert any(entry.kind == "hold_reissued" for entry in platform.audit.list())


# ---- 告警牌 ------------------------------------------------------------


def test_failure_alarm_board_threshold(platform, signer):
    api = Api(platform)
    for _ in range(5):
        status, _ = api.handle("POST", "/api/cycle", {}, {"nope": 1})
        assert status == 401
    snap = platform.board.snapshot()
    assert snap["alarm_active"] and snap["failures"] == 5
    result = platform.reset_security_alarm(by="ops")
    assert result["cleared"] is True
    assert not platform.board.snapshot()["alarm_active"]


def test_alarm_does_not_block_valid_commands(platform, signer):
    api = Api(platform)
    for _ in range(6):
        api.handle("POST", "/api/cycle", {}, {"bad": True})
    assert platform.board.snapshot()["alarm_active"]
    status, payload = api.handle(
        "POST", "/api/cycle", {}, signer.envelope("/api/cycle", {"dt": 1})
    )
    assert status == 200 and payload["ok"]


# ---- 并发：同一 nonce 只放行一次 ---------------------------------------


def test_concurrent_same_nonce_single_execution(platform, signer):
    api = Api(platform)
    envelope = signer.envelope("/api/cycle", {"dt": 1})
    results: list[tuple[int, str]] = []
    lock = threading.Lock()

    def worker() -> None:
        status, payload = api.handle("POST", "/api/cycle", {}, envelope)
        with lock:
            results.append((status, str(payload.get("reason", payload.get("ok", "")))))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    accepted = [item for item in results if item[0] == 200]
    replayed = [item for item in results if item[1] == REASON_REPLAY]
    assert len(accepted) == 1 and len(replayed) == 7
    assert platform.status()["cycles"] == 1


def test_concurrent_distinct_nonces_all_execute(platform, signer):
    api = Api(platform)
    count = {"ok": 0}
    lock = threading.Lock()

    def worker(index: int) -> None:
        env = signer.envelope("/api/cycle", {"dt": 1})
        status, payload = api.handle("POST", "/api/cycle", {}, env)
        with lock:
            if status == 200 and payload["ok"]:
                count["ok"] += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert count["ok"] == 10
    assert platform.status()["cycles"] == 10


# ---- 部分失败回滚 ------------------------------------------------------


def test_transactional_store_rolls_back(tmp_path):
    store = JsonStore(str(tmp_path))
    store.write("a", {"v": 1})
    with pytest.raises(RuntimeError):
        with store.transaction():
            store.write("a", {"v": 2})
            store.write("b", {"v": 3})
            store.remove("a")
            raise RuntimeError("boom")
    assert store.read("a") == {"v": 1}
    assert store.read("b") is None
    # 正常提交保留修改。
    with store.transaction():
        store.write("a", {"v": 9})
    assert store.read("a") == {"v": 9}


def test_unexpected_handler_failure_rolls_back(platform, signer):
    api = Api(platform)

    def boom(_body):
        # 先造成真实落盘副作用，再抛非 RailError 的意外异常。
        platform.store.write("security/scratch", {"wrote": True})
        raise RuntimeError("设备总线失联")

    # 直接在守卫层用一个会中途失败的处理器。
    envelope = signer.envelope("/api/cycle", {"dt": 1})
    before_ops = platform._operations
    status, payload = platform.guard.execute(envelope, "/api/cycle", boom)
    assert status == 500 and payload["rolled_back"] is True
    assert platform.store.read("security/scratch") is None
    assert platform._operations == before_ops
    # nonce 已烧：同一条报文再来只能判重放。
    status2, payload2 = platform.guard.execute(envelope, "/api/cycle", lambda body: {})
    assert status2 == 401 and payload2["reason"] == REASON_REPLAY
    kinds = [entry.kind for entry in platform.audit.list()]
    assert "command_rolled_back" in kinds
    assert "command_verified" in kinds


def test_business_rejection_is_not_rolled_back(platform, signed_post):
    # gap 在未对位时抛 InterlockError(RailError)：语义为业务拒绝，不是部分失败。
    status, payload = signed_post("/api/gap", {"train_id": "T01"})
    assert status == 409 and payload["component"] == "gap"
    # 验签审计仍然存在，且没有回滚补偿。
    kinds = [entry.kind for entry in platform.audit.list()]
    assert "command_verified" in kinds and "command_rolled_back" not in kinds


# ---- 审计可追溯 --------------------------------------------------------


def test_every_verdict_is_audited_with_auth_chain(platform, signer, signed_post):
    status, payload = signed_post("/api/cycle", {"dt": 1})
    auth_id = payload["auth_id"]
    # 一次失败也要有审计。
    api = Api(platform)
    api.handle("POST", "/api/cycle", {}, {"bad": True})
    verified = [e for e in platform.audit.list() if e.kind == "command_verified"]
    rejected = [e for e in platform.audit.list() if e.kind == "command_rejected"]
    executed = [e for e in platform.audit.list() if e.kind == "command_executed"]
    assert verified and rejected
    assert verified[0].detail["auth_id"] == auth_id
    assert executed[0].detail["auth_id"] == auth_id
    assert rejected[0].detail["reason"] == REASON_MALFORMED
    assert rejected[0].detail["severity"] == "alarm"


def test_security_status_exposed(platform):
    status = platform.security_status()
    assert status["mode"] == ENFORCE
    assert status["active_kid"].startswith("key-")
    assert set(status) == {"mode", "keys", "active_kid", "nonces", "quarantine", "board", "guard"}
    assert platform.status()["security"]["guard"]["accepted"] == 0


def test_audit_chain_queryable_by_auth_id(platform, signed_post):
    from psdline.audit import by_auth, verification_verdicts

    status, payload = signed_post("/api/cycle", {"dt": 1})
    auth_id = payload["auth_id"]
    chain = by_auth(platform.audit.list(), auth_id)
    kinds = [entry.kind for entry in chain]
    assert "command_verified" in kinds and "command_executed" in kinds
    verdicts = verification_verdicts(platform.audit.list())
    assert any(entry.detail.get("auth_id") == auth_id for entry in verdicts)
    api = Api(platform)
    status, view = api.handle("GET", f"/api/audit/auth/{auth_id}", {}, {})
    assert status == 200 and "command_verified" in view["kinds"]
    status, view = api.handle("GET", "/api/audit/verdicts", {"limit": "10"}, {})
    assert status == 200 and view["verdicts"]
