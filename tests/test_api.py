from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

ROOT = Path(__file__).parents[1]
client = TestClient(app)


def test_index_page_serves_html() -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def _analyze(fixture: str, vendor: str = "auto") -> dict:
    raw = (ROOT / fixture).read_text()
    resp = client.post("/api/analyze", data={"vendor": vendor}, files={"file": ("cfg.txt", raw)})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_analyze_returns_session_and_masks_credentials() -> None:
    data = _analyze("examples/cisco_ios/branch-router.cfg")
    assert data["vendor"] == "cisco_ios"
    assert "SANITIZED_HASH" not in data["sanitized"]
    assert "<REDACTED>" in data["sanitized"]


def test_reveal_requires_explicit_acknowledgement() -> None:
    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]
    denied = client.post(f"/api/sessions/{session_id}/reveal")
    assert denied.status_code == 400
    allowed = client.post(f"/api/sessions/{session_id}/reveal", data={"acknowledged": "true"})
    assert allowed.status_code == 200


def test_full_edit_diff_export_workflow() -> None:
    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]

    edit = client.post(
        f"/api/sessions/{session_id}/interfaces/GigabitEthernet0%2F0",
        data={"address": "10.10.99.1", "prefix_length": "24"},
    )
    assert edit.status_code == 200

    diff = client.get(f"/api/sessions/{session_id}/diff").json()
    assert diff["added"] >= 1 and "10.10.99.1" in diff["unified"]

    blocked = client.post(f"/api/sessions/{session_id}/export/modified")
    assert blocked.status_code == 400

    exported = client.post(f"/api/sessions/{session_id}/export/modified", data={"confirmed": "true"})
    assert exported.status_code == 200
    assert "10.10.99.1" in exported.text
    assert exported.headers["x-target-platform"] == "Cisco IOS"


def test_invalid_ip_edit_is_rejected_with_422() -> None:
    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]
    resp = client.post(
        f"/api/sessions/{session_id}/interfaces/GigabitEthernet0%2F0",
        data={"address": "not-an-ip", "prefix_length": "24"},
    )
    assert resp.status_code == 422


def test_unknown_session_returns_404() -> None:
    assert client.get("/api/sessions/does-not-exist/diff").status_code == 404


def test_export_sanitized_and_anonymized_differ_on_hostname() -> None:
    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]
    sanitized = client.get(f"/api/sessions/{session_id}/export/sanitized").text
    anonymized = client.get(f"/api/sessions/{session_id}/export/anonymized").text
    assert "BRANCH-RTR" in sanitized
    assert "BRANCH-RTR" not in anonymized


def test_compare_configurations_endpoint_diffs_two_independent_uploads() -> None:
    old = (ROOT / "examples/cisco_ios/branch-router.cfg").read_text()
    new = old.replace("10.10.10.1", "10.10.10.99")
    resp = client.post(
        "/api/diff",
        data={"vendor": "auto"},
        files={"old_file": ("old.cfg", old), "new_file": ("new.cfg", new)},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["old"]["hostname"] == "BRANCH-RTR"
    assert data["new"]["hostname"] == "BRANCH-RTR"
    assert data["vendor_mismatch"] is False
    assert data["added"] >= 1 and data["removed"] >= 1
    assert "10.10.10.99" in data["unified"]


def test_compare_configurations_accepts_pasted_text() -> None:
    resp = client.post(
        "/api/diff",
        data={
            "vendor": "auto",
            "old_text": "hostname A\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n",
            "new_text": "hostname A\ninterface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["added"] == 1


def test_compare_configurations_requires_both_sides() -> None:
    resp = client.post("/api/diff", data={"old_text": "hostname A\n"})
    assert resp.status_code == 422


def test_compare_configurations_flags_vendor_mismatch() -> None:
    old = (ROOT / "examples/cisco_ios/branch-router.cfg").read_text()
    new = (ROOT / "examples/mikrotik/branch-router.rsc").read_text()
    resp = client.post(
        "/api/diff",
        data={"vendor": "auto"},
        files={"old_file": ("old.cfg", old), "new_file": ("new.rsc", new)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["vendor_mismatch"] is True


def test_topology_endpoint_returns_well_formed_svg() -> None:
    from xml.dom import minidom

    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]
    data = client.get(f"/api/sessions/{session_id}/topology").json()
    assert data["svg"].startswith("<svg")
    minidom.parseString(data["svg"])


def test_topology_endpoint_404s_for_unknown_session() -> None:
    resp = client.get("/api/sessions/does-not-exist/topology")
    assert resp.status_code == 404


def test_replay_endpoint_includes_honesty_notice_and_compatibility_warning() -> None:
    session_id = _analyze("examples/cisco_ios/branch-router.cfg")["session_id"]
    data = client.get(f"/api/sessions/{session_id}/replay").json()
    assert "does not" in data["notice"] or "not stored" in data["notice"]
    assert data["target_platform"] == "Cisco IOS"
    assert data["compatibility_warning"]
    assert len(data["steps"]) > 0
