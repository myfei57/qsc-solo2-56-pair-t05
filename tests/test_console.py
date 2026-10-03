"""控制台接口、页面与 HTTP 服务。"""

from __future__ import annotations

from psdline.console.api import Api
from psdline.console.pages import PAGE_PATHS, render_page
from psdline.console.router import Router
from psdline.console.server import ConsoleServer, probe_endpoints


def test_router_prefers_exact_path():
    router = Router()
    router.add("GET", "/api/trains/{trainID}", lambda params, body: {"param": params["trainID"]})
    router.add("GET", "/api/trains/summary", lambda params, body: {"exact": True})
    handler, params = router.match("GET", "/api/trains/summary")
    assert handler({}, {}) == {"exact": True}
    assert params == {}
    handler, params = router.match("GET", "/api/trains/T01")
    assert params == {"trainID": "T01"}
    assert router.match("GET", "/api/none") is None
    assert router.routes()[0].as_dict()["method"] == "GET"


def test_api_returns_status_and_routes(platform):
    api = Api(platform)
    status, payload = api.handle("GET", "/api/status", {}, {})
    assert status == 200
    assert payload["platform"] == platform.config.name
    paths = [route["path"] for route in api.routes()]
    assert "/api/arrive" in paths
    assert "/api/trains/{trainID}" in paths


def test_api_unknown_path_is_404(platform):
    api = Api(platform)
    status, payload = api.handle("GET", "/api/does-not-exist", {}, {})
    assert status == 404
    assert payload["error"] == "not_found"


def test_api_station_and_train_views(platform):
    api = Api(platform)
    status, view = api.handle("GET", "/api/stations/ST1", {}, {})
    assert status == 200
    assert view["station"]["id"] == "ST1"
    status, missing = api.handle("GET", "/api/trains/T99", {}, {})
    assert status == 400
    assert missing["component"] == "console"
    platform.arrive("T01", "ST1", 0)
    status, train = api.handle("GET", "/api/trains/T01", {}, {})
    assert status == 200
    assert train["aspect"] == "yellow"


def test_api_mapping_and_resolve(platform):
    api = Api(platform)
    status, mapping = api.handle("GET", "/api/mapping/ST1", {}, {})
    assert status == 200
    assert mapping["groups"]["G01"] == "G01"
    status, resolved = api.handle("GET", "/api/resolve", {"station_id": "ST1", "group_key": "G02"}, {})
    assert status == 200
    assert resolved["group"] == "G02"
    status, broken = api.handle("GET", "/api/resolve", {"station_id": "ST1", "group_key": "NOPE"}, {})
    assert status == 409


def test_api_action_flow(platform):
    api = Api(platform)
    status, arrival = api.handle(
        "POST", "/api/arrive", {}, {"train_id": "T01", "station_id": "ST1", "position_m": 0}
    )
    assert status == 200 and arrival["ok"] is True
    status, gap = api.handle("POST", "/api/gap", {}, {"train_id": "T01"})
    assert status == 200 and gap["clear"] is True
    envelope = platform.sign_command(
        "door.enqueue", {"train_id": "T01", "kind": "open", "station_id": "ST1"}
    )
    status, queued = api.handle("POST", "/api/commands", {}, envelope)
    assert status == 200 and queued["ok"] is True
    status, processed = api.handle("POST", "/api/process", {}, {"train_id": "T01"})
    assert status == 200 and processed["ids"] == [envelope["id"]] and processed["ready"] is False
    status, departure = api.handle(
        "POST", "/api/depart", {}, {"train_id": "T01", "station_id": "ST1"}
    )
    assert status == 200 and departure["ok"] is True


def test_api_unsigned_command_paths_are_gone(platform):
    api = Api(platform)
    for path in ("/api/enqueue", "/api/batch-open", "/api/fault", "/api/clear-fault", "/api/arm"):
        status, payload = api.handle("POST", path, {}, {})
        assert status == 404, path
    envelope = platform.sign_command("door.enqueue", {"train_id": "T01", "kind": "open"})
    envelope["payload"]["kind"] = "close"  # 篡改载荷，签名必然失效
    status, rejected = api.handle("POST", "/api/commands", {}, envelope)
    assert status == 200
    assert rejected["ok"] is False
    assert rejected["verdict"]["reason"] == "bad_signature"
    status, sec = api.handle("GET", "/api/sec", {}, {})
    assert status == 200 and sec["gate"]["rejected"] == 1
    status, rotated = api.handle("POST", "/api/sec/rotate", {}, {})
    assert status == 200 and rotated["ok"] is True and rotated["new_kid"]


def test_api_rejects_missing_and_bad_fields(platform):
    api = Api(platform)
    status, payload = api.handle("POST", "/api/arrive", {}, {"station_id": "ST1"})
    assert status == 400
    assert payload["component"] == "console"
    status, payload = api.handle("POST", "/api/cycle", {}, {"dt": "abc"})
    assert status == 400
    assert payload["error"] == "RailError"
    status, payload = api.handle("POST", "/api/renumber", {}, {"station_id": "ST1"})
    assert status == 400
    status, payload = api.handle(
        "POST", "/api/renumber", {}, {"station_id": "ST1", "groups": {"A": "G01"}}
    )
    assert status == 200


def test_api_readiness_and_queries(platform):
    api = Api(platform)
    platform.arrive("T01", "ST1", 0)
    status, ready = api.handle("GET", "/api/readiness", {}, {})
    assert status == 200 and ready["ready"] is True
    status, audit = api.handle("GET", "/api/audit", {"limit": "10"}, {})
    assert status == 200 and audit["entries"]
    status, timeline = api.handle("GET", "/api/timeline", {"train_id": "T01"}, {})
    assert status == 200 and timeline["timeline"][0]["kind"] == "arrival"
    status, store = api.handle("GET", "/api/store", {}, {})
    assert status == 200 and "quota/arrival" in store["documents"]
    status, namespace = api.handle("GET", "/api/namespace", {}, {})
    assert status == 200 and namespace["line"] == "L1"
    status, gate = api.handle("GET", "/api/doors/ST1-G01-01", {}, {})
    assert status == 200 and gate["gate"]["station"] == "ST1"


def test_pages_render_for_every_path(platform):
    platform.arrive("T01", "ST1", 0)
    for path in PAGE_PATHS:
        html = render_page(path, platform)
        assert html is not None
        assert html.startswith("<!doctype html>")
        assert "控制台" in html
    assert render_page("/nope", platform) is None


def test_server_serves_api_and_pages(platform):
    platform.arrive("T01", "ST1", 0)
    server = ConsoleServer(platform, host="127.0.0.1", port=0)
    base_url = server.start()
    try:
        probe = probe_endpoints(
            base_url,
            ["/api/status", "/api/readiness", "/api/stations", "/", "/trains", "/api/nope"],
        )
    finally:
        server.stop()
    assert probe["/api/status"]["ok"] is True
    assert probe["/api/readiness"]["ok"] is True
    assert probe["/api/stations"]["ok"] is True
    assert probe["/"]["ok"] is True
    assert probe["/trains"]["ok"] is True
    assert probe["/api/nope"]["ok"] is False
    assert server.api.routes()
