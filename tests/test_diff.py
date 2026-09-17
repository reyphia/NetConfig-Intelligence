from app.services import analyze, render_device, update_interface
from app.services.diff import configuration_diff


def test_no_edits_means_no_diff() -> None:
    session = analyze("hostname R1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n", "cisco_ios")
    result = configuration_diff(session.original_rendered_text, session.rendered_text or session.original_rendered_text)
    assert result["unified"] == ""
    assert result["added"] == 0
    assert result["removed"] == 0


def test_ip_edit_produces_a_minimal_diff_without_rendering_noise() -> None:
    """Regression test: the diff must compare renderer-output to
    renderer-output. Comparing raw uploaded text against rendered output
    used to produce large, unrelated diffs (missing `version` lines, `!`
    delimiters appearing/disappearing) even for a one-line edit."""
    raw = "hostname R1\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown\n"
    session = analyze(raw, "cisco_ios")
    update_interface(session, "Gi0/1", "10.0.0.99", 24)
    result = configuration_diff(session.original_rendered_text, session.rendered_text or "")
    assert result["added"] == 1
    assert result["removed"] == 1
    assert "10.0.0.99" in result["unified"]
    assert "ip address 10.0.0.1 255.255.255.0" in result["unified"]


def test_diff_between_two_independent_configs_via_render_device() -> None:
    old = analyze("hostname A\ninterface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n", "cisco_ios")
    new = analyze("hostname B\ninterface Gi0/1\n ip address 10.0.0.2 255.255.255.0\n", "cisco_ios")
    result = configuration_diff(render_device(old.device), render_device(new.device))
    assert result["added"] > 0 and result["removed"] > 0
