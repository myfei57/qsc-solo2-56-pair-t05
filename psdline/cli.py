"""命令行入口。

五个子命令覆盖日常使用：

``serve``   启动控制台 HTTP 服务，可选地在启动后探测接口；
``demo``    在本地跑一遍完整流程（到站开门 → 间隙探测 → 发车 → 批量开门 →
            门区联动 → 故障置位与解除 → 序号回绕 → 控制周期 → 清扫），用于交付
            前的真实运行检查；
``status``  打印当前状态快照；
``config``  打印生效配置；
``reset``   清掉落盘的平台计数。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time

from .app import Platform, build_platform
from .clock import ManualClock, SystemClock
from .config import config_to_mapping, default_config, load_config
from .console.server import ConsoleServer, probe_endpoints
from .errors import RailError
from .security import Signer

DEFAULT_PROBE_PATHS = ("/api/status", "/api/readiness", "/api/stations", "/", "/alarms")


def _build(args: argparse.Namespace) -> Platform:
    config = load_config(args.config) if getattr(args, "config", None) else default_config()
    if getattr(args, "storage_root", None):
        return build_platform(config, storage_root=args.storage_root)
    return Platform(config=config)


def _dump(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _cmd_serve(args: argparse.Namespace) -> int:
    platform = _build(args)
    server = ConsoleServer(platform, host=args.host, port=args.port)
    base_url = server.start()
    payload: dict = {"listening": base_url, "routes": server.api.routes()}
    if args.probe:
        payload["probe"] = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    _dump(payload)
    if args.duration > 0:
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:  # pragma: no cover - 交互路径
            pass
        server.stop()
        return 0
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover - 交互路径
        server.stop()
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    clock = ManualClock() if args.fast else SystemClock()
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    storage_root = getattr(args, "storage_root", None) or tempfile.mkdtemp(prefix="psdline-demo-")
    platform = build_platform(config, clock=clock, storage_root=storage_root)

    startup = platform.start()
    arrival = platform.arrive(args.train, args.station, 0)
    position = platform.refresh_position(args.train, 12)
    gap = platform.check_gap(args.train)
    queued = platform.enqueue(args.train, "cmd-1", "open", args.station)
    processed = platform.process_queue(args.train)
    swept = platform.sweep(args.station)
    fault = platform.set_fault(_first_gate(platform, args.station))
    cleared = platform.clear_fault(_first_gate(platform, args.station))
    batched = platform.batch_open(args.station)
    renumber = platform.renumber(args.station, _mirror_mapping(platform, args.station))
    sequence = platform.sequence_verdict(65534, 4)
    dwell = platform.register_dwell(args.train, 45.0, args.station)
    route = platform.assign_route(args.train, args.station, _next_station(platform, args.station), 1200)
    departure = platform.depart(args.train, args.station)
    cycles = [platform.cycle(dt=args.dt) for _ in range(args.cycles)]
    final_sweep = platform.sweep(args.station)

    # 演示自检用临时端口，避免和本机常驻服务抢 8080。
    server = ConsoleServer(platform, port=0)
    base_url = server.start()
    probe_signer = Signer(
        platform.keyring.active().secret,
        platform.keyring.active().kid,
        unit=platform.unit,
        clock=clock,
    )
    probe = probe_endpoints(
        base_url, list(DEFAULT_PROBE_PATHS) + ["/api/cycle"], signer=probe_signer
    )
    server.stop()

    report = {
        "storage_root": storage_root,
        "startup": startup,
        "arrival": {key: arrival[key] for key in ("ok", "position_m", "violations")},
        "position": position,
        "gap": gap,
        "queued": {key: queued[key] for key in ("ok", "train_id")},
        "processed": processed,
        "swept": swept,
        "batch": {key: batched[key] for key in ("ok", "order", "opened", "nearest")},
        "renumber": {key: renumber[key] for key in ("ok", "revision", "active_group")},
        "fault": fault,
        "cleared": cleared,
        "sequence": sequence,
        "dwell": dwell,
        "route": route,
        "departure": departure,
        "cycles_run": len(cycles),
        "last_cycle": cycles[-1],
        "final_sweep": {key: final_sweep[key] for key in ("closed", "scanned")},
        "probe": probe,
        "status": platform.status(),
    }
    _dump(report)

    failures = [name for name, item in probe.items() if not item["ok"]]
    for name, operation in (
        ("arrival", arrival),
        ("processed", processed),
        ("renumber", renumber),
        ("cleared", cleared),
        ("sequence", sequence),
        ("departure", departure),
    ):
        if not operation.get("ok"):
            failures.extend(f"{name}:{item}" for item in operation.get("violations", []))
    if failures:
        print(f"检查未通过: {failures}", file=sys.stderr)
        return 1
    return 0


def _mirror_mapping(platform: Platform, station_id: str) -> dict[str, str]:
    """给演示重排构造一份反向映射。"""

    groups = sorted(platform.station_view(station_id)["groups"])
    rotated = groups[1:] + groups[:1]
    return {key: value for key, value in zip(groups, rotated)}


def _first_gate(platform: Platform, station_id: str) -> str:
    """返回演示用的第一樘站台门。"""

    gates = platform.gates.by_station(station_id)
    return gates[0].id if gates else ""


def _next_station(platform: Platform, station_id: str) -> str:
    """返回线路上下一个站台，用于演示交路。"""

    stations = platform.namespace.station_ids()
    if len(stations) < 2:
        return station_id
    index = stations.index(station_id) if station_id in stations else 0
    return stations[(index + 1) % len(stations)]


def _cmd_status(args: argparse.Namespace) -> int:
    platform = _build(args)
    payload = platform.status()
    payload["groups"] = platform.snapshot()["groups"]
    _dump(payload)
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    _dump(config_to_mapping(config))
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    platform = _build(args)
    removed = platform.reset_state()
    _dump({"storage_root": platform.store.root, "platform_state_removed": removed})
    return 0


# ---- 指令防伪：密钥管理与签名 -----------------------------------------


def _keyring(args: argparse.Namespace):
    config = load_config(args.config) if getattr(args, "config", None) else default_config()
    from .security import KeyRing

    ring = KeyRing(
        config.security.secrets_root,
        overlap_s=config.security.rotate_overlap_s,
        clock=SystemClock(),
    )
    return config, ring


def _cmd_keys_list(args: argparse.Namespace) -> int:
    _config, ring = _keyring(args)
    ring.retire_expired()
    _dump({"keys": ring.describe()})
    return 0


def _cmd_keys_bootstrap(args: argparse.Namespace) -> int:
    config, ring = _keyring(args)
    record = ring.bootstrap()
    _dump(
        {
            "kid": record.kid,
            "state": record.state,
            "fingerprint": record.fingerprint,
            "secret": record.secret if args.show_secret else None,
            "unit": config.platform.unit,
        }
    )
    if not args.show_secret:
        print("提示：密钥只显示一次，需要带出请加 --show-secret", file=sys.stderr)
    return 0


def _cmd_keys_rotate(args: argparse.Namespace) -> int:
    config, ring = _keyring(args)
    fresh, old = ring.rotate()
    _dump(
        {
            "active_kid": fresh.kid,
            "fingerprint": fresh.fingerprint,
            "secret": fresh.secret if args.show_secret else None,
            "grace_kid": old.kid if old else None,
            "retire_at": old.retire_at if old else None,
            "overlap_s": config.security.rotate_overlap_s,
            "unit": config.platform.unit,
        }
    )
    if not args.show_secret:
        print("提示：新密钥只显示一次，需要带出请加 --show-secret", file=sys.stderr)
    return 0


def _cmd_keys_revoke(args: argparse.Namespace) -> int:
    _config, ring = _keyring(args)
    record = ring.revoke(args.kid)
    _dump({"kid": args.kid, "state": record.state, "fingerprint": record.fingerprint})
    return 0


def _cmd_keys_retire(args: argparse.Namespace) -> int:
    _config, ring = _keyring(args)
    kids = ring.retire_expired()
    _dump({"retired": kids})
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    config, ring = _keyring(args)
    if args.kid:
        record = ring.get(args.kid)
        if record is None:
            print(json.dumps({"error": "unknown_kid", "kid": args.kid}), file=sys.stderr)
            return 2
    else:
        record = ring.active()
        if record is None:
            print(json.dumps({"error": "no_active_key"}), file=sys.stderr)
            return 2
    if not record.secret:
        print(json.dumps({"error": "key_not_usable", "kid": record.kid, "state": record.state}), file=sys.stderr)
        return 2
    try:
        body = json.loads(args.body) if args.body else {}
    except json.JSONDecodeError as error:
        print(json.dumps({"error": "bad_body", "message": str(error)}), file=sys.stderr)
        return 2
    signer = Signer(
        record.secret,
        record.kid,
        unit=args.unit or config.platform.unit,
        ttl_s=args.ttl or config.security.command_ttl_s,
    )
    envelope = signer.envelope(args.action, body)
    _dump(envelope)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="JSON 配置文件路径", default=argparse.SUPPRESS)
    common.add_argument("--storage-root", help="覆盖状态存储目录", default=argparse.SUPPRESS)
    parser = argparse.ArgumentParser(
        prog="psdline", description="作业顺序与联锁控制服务", parents=[common]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="启动控制台服务", parents=[common])
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--duration", type=float, default=0.0, help="运行多少秒后退出，0 表示常驻")
    serve.add_argument("--probe", action="store_true", help="启动后探测接口")
    serve.set_defaults(func=_cmd_serve)

    demo = sub.add_parser("demo", help="跑一遍完整流程", parents=[common])
    demo.add_argument("--train", default="T01", help="演示用的列车标识")
    demo.add_argument("--station", default="ST1", help="演示用的站台标识")
    demo.add_argument("--cycles", type=int, default=120, help="演示控制周期数")
    demo.add_argument("--dt", type=float, default=1.0, help="控制周期步长（秒）")
    demo.add_argument("--fast", action="store_true", help="使用可推进时钟，跳过真实等待")
    demo.set_defaults(func=_cmd_demo)

    status = sub.add_parser("status", help="打印状态快照", parents=[common])
    status.set_defaults(func=_cmd_status)

    config = sub.add_parser("config", help="打印生效配置", parents=[common])
    config.set_defaults(func=_cmd_config)

    reset = sub.add_parser("reset", help="清掉落盘的平台计数", parents=[common])
    reset.set_defaults(func=_cmd_reset)

    keys = sub.add_parser("keys", help="签名密钥管理", parents=[common])
    key_sub = keys.add_subparsers(dest="key_command", required=True)
    key_list = key_sub.add_parser("list", help="列出密钥环（不含密钥材料）", parents=[common])
    key_list.set_defaults(func=_cmd_keys_list)
    key_boot = key_sub.add_parser("bootstrap", help="首次布防：生成第一把 active 钥", parents=[common])
    key_boot.add_argument("--show-secret", action="store_true", help="打印密钥明文（仅此一次）")
    key_boot.set_defaults(func=_cmd_keys_bootstrap)
    key_rotate = key_sub.add_parser("rotate", help="轮换：旧 active 进并存期，生成新 active", parents=[common])
    key_rotate.add_argument("--show-secret", action="store_true", help="打印新密钥明文")
    key_rotate.set_defaults(func=_cmd_keys_rotate)
    key_revoke = key_sub.add_parser("revoke", help="立即吊销一把密钥", parents=[common])
    key_revoke.add_argument("--kid", required=True)
    key_revoke.set_defaults(func=_cmd_keys_revoke)
    key_retire = key_sub.add_parser("retire", help="退役并存期到期的旧钥", parents=[common])
    key_retire.set_defaults(func=_cmd_keys_retire)

    sign = sub.add_parser("sign", help="用 active 密钥签发一条指令信封", parents=[common])
    sign.add_argument("--action", required=True, help="授权接口路径，如 /api/arrive")
    sign.add_argument("--body", help="接口正文 JSON 字符串，缺省为空对象")
    sign.add_argument("--kid", help="指定密钥，缺省用当前 active")
    sign.add_argument("--unit", help="覆盖运行单元，缺省取配置里的 unit")
    sign.add_argument("--ttl", type=float, help="覆盖有效期秒数")
    sign.set_defaults(func=_cmd_sign)
    return parser


def main(argv: list[str] | None = None) -> int:
    """命令行主入口。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RailError as error:
        print(json.dumps(error.as_record(), ensure_ascii=False), file=sys.stderr)
        return 2
