"""Edge cases for both checks: the real oc/kubectl subprocess client (against a
fake `oc` on PATH), "could not fetch" paths, and main() options."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest import mock

import pytest

import openshift_bio_check as ocp
import rhel10_bio_check as rhel


# --------------------------------------------------------------------------- oc client

@pytest.fixture
def fake_oc(tmp_path, monkeypatch):
    """An `oc` script on PATH. Its behaviour comes from FAKE_OC_MODE."""
    script = tmp_path / "oc"
    script.write_text(
        "#!/usr/bin/env bash\n"
        'case "$FAKE_OC_MODE:$1" in\n'
        '  ok:whoami) echo "kube:admin" ;;\n'
        "  ok:get) echo '{\"items\": [], \"args\": \"'\"$*\"'\"}' ;;\n"
        "  badjson:get) echo 'not json' ;;\n"
        "  slow:get) sleep 5 ;;\n"
        '  *) echo "error: You must be logged in to the server (Unauthorized)" >&2; exit 1 ;;\n'
        "esac\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_OC_MODE", "ok")
    return script


def test_client_detects_oc_and_parses_json(fake_oc):
    c = ocp.ClusterClient()
    assert c.available() and c.binary == "oc"
    ok, data, err = c.get_json(["get", "routes", "--all-namespaces"])
    assert ok and err == "" and data["items"] == []
    assert data["args"] == "get routes --all-namespaces -o json"
    assert c.whoami() == (True, "kube:admin")


def test_client_reports_errors_bad_json_and_timeouts(fake_oc, monkeypatch):
    c = ocp.ClusterClient()
    monkeypatch.setenv("FAKE_OC_MODE", "denied")
    assert c.get_json(["get", "scc"]) == (False, None, "error: You must be logged in to the server (Unauthorized)")
    assert c.whoami()[0] is False
    monkeypatch.setenv("FAKE_OC_MODE", "badjson")
    ok, _, err = c.get_json(["get", "scc"])
    assert not ok and err.startswith("could not parse JSON output")
    monkeypatch.setenv("FAKE_OC_MODE", "slow")
    ok, _, err = c.get_json(["get", "scc"], timeout=1)
    assert not ok and err == "command timed out: oc get scc"


def test_client_without_a_binary(monkeypatch):
    monkeypatch.setattr(ocp.shutil, "which", lambda _: None)
    c = ocp.ClusterClient()
    assert not c.available()
    assert c.get_json(["get", "x"]) == (False, None, "oc/kubectl binary not found on PATH")
    assert c.whoami() == (False, "")


class FailingClient:
    def get_json(self, args, timeout=30):
        return False, None, "forbidden"


@pytest.mark.parametrize("checker,check_id", [
    (ocp.ApiServerConfigChecker, "OCPL003"),
    (ocp.SccChecker, "OCPL005"),
    (ocp.NetworkPolicyChecker, "OCPL006"),
    (ocp.RouteTlsChecker, "OCPL007"),
])
def test_unreadable_resources_become_info_findings(checker, check_id):
    findings = checker().check(FailingClient())
    assert [f.check_id for f in findings] == [check_id]
    assert findings[0].severity == ocp.Severity.INFO and "forbidden" in findings[0].message


def test_networkpolicy_list_failure_after_namespaces():
    class Half:
        def get_json(self, args, timeout=30):
            if args[1] == "namespaces":
                return True, {"items": [{"metadata": {"name": "app"}}]}, ""
            return False, None, "no np access"
    findings = ocp.NetworkPolicyChecker().check(Half())
    assert [f.check_id for f in findings] == ["OCPL006"] and "NetworkPolicies" in findings[0].message


def test_ocp_main_without_a_binary(monkeypatch, capsys):
    monkeypatch.setattr(ocp.shutil, "which", lambda _: None)
    assert ocp.main([]) == 2
    assert "neither 'oc' nor 'kubectl'" in capsys.readouterr().err


def test_ocp_main_not_logged_in_writes_html_to_a_file(fake_oc, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("FAKE_OC_MODE", "denied")
    out = tmp_path / "report.html"
    rc = ocp.main(["--format", "html", "-o", str(out), "--fail-on", "critical"])
    assert rc == 0                                     # only INFO findings
    assert "may not be logged in" in capsys.readouterr().err
    html = out.read_text()
    assert html.lstrip().lower().startswith("<!doctype html") and "OCPL003" in html


def test_ocp_text_report_lists_highest_severity_first():
    text = ocp.format_text([
        ocp.Finding("A", "c", ocp.Severity.LOW, "low one", "x"),
        ocp.Finding("B", "c", ocp.Severity.CRITICAL, "crit one", "y"),
    ], "cluster")
    assert text.index("crit one") < text.index("low one")
    assert ocp.format_text([], "cluster").endswith("no findings. ✓")


# --------------------------------------------------------------------------- rhel

def test_run_cmd_never_raises():
    assert rhel.run_cmd(["definitely-not-a-command-xyz"]) == (False, "", "command not found: definitely-not-a-command-xyz")
    assert rhel.run_cmd(["sleep", "5"], timeout=1) == (False, "", "command timed out: sleep 5")
    assert rhel.run_cmd(["sh", "-c", "echo ' out '; echo err >&2; exit 3"]) == (False, "out", "err")


def test_sshd_parser_skips_malformed_lines():
    cfg = rhel.parse_sshd_config("PermitRootLogin\nPasswordAuthentication yes\n# c\n\nX11Forwarding   yes  \n")
    assert cfg == {"passwordauthentication": "yes", "x11forwarding": "yes"}


def test_unreadable_dropin_is_skipped(tmp_path, monkeypatch):
    main_cfg = tmp_path / "sshd_config"
    main_cfg.write_text("Include sshd_config.d/*.conf\nPasswordAuthentication no\n")
    dropins = tmp_path / "sshd_config.d"
    dropins.mkdir()
    (dropins / "50-ok.conf").write_text("X11Forwarding yes\n")
    (dropins / "60-broken.conf").write_text("x")
    real = Path.read_text

    def flaky(self, *a, **k):
        if self.name == "60-broken.conf":
            raise PermissionError("nope")
        return real(self, *a, **k)

    monkeypatch.setattr(Path, "read_text", flaky)
    cfg = rhel.read_sshd_config(main_cfg)
    assert cfg.get("x11forwarding") == "yes"


@pytest.mark.parametrize("text,check_id", [
    ("PasswordAuthentication yes\n", "RHL002"),
    ("X11Forwarding yes\n", "RHL004"),
])
def test_ssh_findings(tmp_path, text, check_id):
    p = tmp_path / "sshd_config"
    p.write_text("PermitRootLogin no\n" + text)
    assert check_id in [f.check_id for f in rhel.SshChecker().check(p)]


def fake_cmds(results):
    """run_cmd replacement: results maps a joined command prefix to ok (bool)."""
    def run(args, timeout=15):
        key = " ".join(args)
        for prefix, ok in results.items():
            if key.startswith(prefix):
                return (ok, "", "") if isinstance(ok, bool) else ok
        return False, "", ""
    return run


def test_firewalld_active_but_not_enabled(monkeypatch):
    monkeypatch.setattr(rhel, "run_cmd", fake_cmds({
        "systemctl is-active --quiet firewalld": True,
        "systemctl is-enabled --quiet firewalld": False,
        "firewall-cmd --get-default-zone": (True, "public", ""),
    }))
    assert "RHL010" in [f.check_id for f in rhel.FirewallChecker().check()]


def test_auditd_active_but_not_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(rhel, "run_cmd", fake_cmds({
        "systemctl is-active --quiet auditd": True,
        "systemctl is-enabled --quiet auditd": False,
    }))
    ids = [f.check_id for f in rhel.AuditdChecker().check(tmp_path)]
    assert "RHL031" in ids and "RHL030" not in ids


def test_rhel_main_writes_json_and_honours_fail_on(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(rhel, "run_all_checks", lambda: [
        rhel.Finding("RHL002", "Toegangsbeveiliging", rhel.Severity.MEDIUM, "pw auth", "sshd")])
    monkeypatch.setattr(rhel, "is_root", lambda: False)
    out = tmp_path / "r.json"
    assert rhel.main(["--format", "json", "-o", str(out)]) == 0          # medium < high
    assert "not running as root" in capsys.readouterr().err
    data = json.loads(out.read_text())
    assert data["findings"][0]["check_id"] == "RHL002"
    assert rhel.main(["--format", "text", "--fail-on", "medium"]) == 1
    assert "pw auth" in capsys.readouterr().out
