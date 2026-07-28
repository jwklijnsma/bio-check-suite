"""
Tests for rhel10_bio_check.py

Run with:
    pytest -v test_rhel10_bio_check.py
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from rhel10_bio_check import (
    AccountsChecker,
    AuditdChecker,
    FirewallChecker,
    Finding,
    SelinuxChecker,
    Severity,
    SshChecker,
    UpdatesChecker,
    format_html,
    format_json,
    format_text,
    main,
    parse_sshd_config,
    run_cmd,
)


def write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# run_cmd
# --------------------------------------------------------------------------- #

class TestRunCmd:
    def test_missing_binary_does_not_raise(self):
        ok, out, err = run_cmd(["definitely-not-a-real-binary-xyz"])
        assert ok is False
        assert "not found" in err

    def test_successful_command(self):
        ok, out, err = run_cmd(["echo", "hello"])
        assert ok is True
        assert out == "hello"


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

class TestSshChecker:
    def test_hardened_config_has_no_findings(self, tmp_path):
        cfg = write(tmp_path / "sshd_config", """
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
""")
        findings = SshChecker().check(cfg)
        assert findings == []

    def test_permit_root_login_yes_is_high(self, tmp_path):
        cfg = write(tmp_path / "sshd_config", "PermitRootLogin yes\n")
        findings = SshChecker().check(cfg)
        f = next(f for f in findings if f.check_id == "RHL001")
        assert f.severity == Severity.HIGH

    def test_permit_root_login_unset_is_medium(self, tmp_path):
        cfg = write(tmp_path / "sshd_config", "MaxAuthTries 3\n")
        findings = SshChecker().check(cfg)
        f = next(f for f in findings if f.check_id == "RHL001")
        assert f.severity == Severity.MEDIUM

    def test_empty_passwords_allowed_is_critical(self, tmp_path):
        cfg = write(tmp_path / "sshd_config", "PermitEmptyPasswords yes\n")
        findings = SshChecker().check(cfg)
        f = next(f for f in findings if f.check_id == "RHL003")
        assert f.severity == Severity.CRITICAL

    def test_missing_sshd_config_produces_info(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        findings = SshChecker().check(missing)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_drop_in_directory_overrides_main_config(self, tmp_path):
        write(tmp_path / "sshd_config", "PermitRootLogin yes\n")
        write(tmp_path / "sshd_config.d" / "10-hardening.conf", "PermitRootLogin no\n")
        cfg = tmp_path / "sshd_config"
        findings = SshChecker().check(cfg)
        assert not any(f.check_id == "RHL001" for f in findings)

    def test_parse_sshd_config_ignores_comments_and_blank_lines(self):
        text = "# comment\n\nPermitRootLogin no\n   # indented comment\nMaxAuthTries 3\n"
        cfg = parse_sshd_config(text)
        assert cfg == {"permitrootlogin": "no", "maxauthtries": "3"}


# --------------------------------------------------------------------------- #
# Firewall (mocked subprocess)
# --------------------------------------------------------------------------- #

class TestFirewallChecker:
    def test_no_firewall_active_is_high(self):
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(False, "", "")):
            findings = FirewallChecker().check()
        assert any(f.check_id == "RHL010" and f.severity == Severity.HIGH for f in findings)

    def test_firewalld_active_and_enabled_default_zone_public_has_no_findings(self):
        def fake_run_cmd(args, timeout=15):
            if args[:2] == ["systemctl", "is-active"]:
                return (True, "", "") if "firewalld" in args else (False, "", "")
            if args[:2] == ["systemctl", "is-enabled"]:
                return (True, "", "") if "firewalld" in args else (False, "", "")
            if args[:2] == ["firewall-cmd", "--get-default-zone"]:
                return (True, "public", "")
            return (False, "", "")

        with mock.patch("rhel10_bio_check.run_cmd", side_effect=fake_run_cmd):
            findings = FirewallChecker().check()
        assert findings == []

    def test_default_zone_trusted_is_flagged(self):
        def fake_run_cmd(args, timeout=15):
            if args[:2] == ["systemctl", "is-active"]:
                return (True, "", "")
            if args[:2] == ["systemctl", "is-enabled"]:
                return (True, "", "")
            if args[:2] == ["firewall-cmd", "--get-default-zone"]:
                return (True, "trusted", "")
            return (False, "", "")

        with mock.patch("rhel10_bio_check.run_cmd", side_effect=fake_run_cmd):
            findings = FirewallChecker().check()
        assert any(f.check_id == "RHL011" for f in findings)


# --------------------------------------------------------------------------- #
# SELinux
# --------------------------------------------------------------------------- #

class TestSelinuxChecker:
    def test_enforcing_with_matching_config_has_no_findings(self, tmp_path):
        cfg = write(tmp_path / "config", "SELINUX=enforcing\nSELINUXTYPE=targeted\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "Enforcing", "")):
            findings = SelinuxChecker().check(cfg)
        assert findings == []

    def test_disabled_is_critical(self, tmp_path):
        cfg = write(tmp_path / "config", "SELINUX=disabled\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "Disabled", "")):
            findings = SelinuxChecker().check(cfg)
        f = next(f for f in findings if f.check_id == "RHL020")
        assert f.severity == Severity.CRITICAL

    def test_permissive_is_high(self, tmp_path):
        cfg = write(tmp_path / "config", "SELINUX=permissive\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "Permissive", "")):
            findings = SelinuxChecker().check(cfg)
        f = next(f for f in findings if f.check_id == "RHL020")
        assert f.severity == Severity.HIGH

    def test_config_mismatch_after_reboot_is_flagged(self, tmp_path):
        cfg = write(tmp_path / "config", "SELINUX=permissive\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "Enforcing", "")):
            findings = SelinuxChecker().check(cfg)
        assert any(f.check_id == "RHL021" for f in findings)

    def test_getenforce_unavailable_produces_info(self, tmp_path):
        cfg = write(tmp_path / "config", "SELINUX=enforcing\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(False, "", "not found")):
            findings = SelinuxChecker().check(cfg)
        assert any(f.check_id == "RHL020" and f.severity == Severity.INFO for f in findings)


# --------------------------------------------------------------------------- #
# auditd
# --------------------------------------------------------------------------- #

class TestAuditdChecker:
    def test_active_enabled_with_rules_has_no_findings(self, tmp_path):
        rules_dir = tmp_path / "rules.d"
        write(rules_dir / "audit.rules", "-w /etc/passwd -p wa -k identity\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "", "")):
            findings = AuditdChecker().check(rules_dir)
        assert findings == []

    def test_inactive_auditd_is_high(self, tmp_path):
        rules_dir = tmp_path / "rules.d"
        rules_dir.mkdir()
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(False, "", "")):
            findings = AuditdChecker().check(rules_dir)
        assert any(f.check_id == "RHL030" and f.severity == Severity.HIGH for f in findings)

    def test_empty_rules_dir_is_flagged(self, tmp_path):
        rules_dir = tmp_path / "rules.d"
        rules_dir.mkdir()
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "", "")):
            findings = AuditdChecker().check(rules_dir)
        assert any(f.check_id == "RHL032" for f in findings)


# --------------------------------------------------------------------------- #
# Updates
# --------------------------------------------------------------------------- #

class TestUpdatesChecker:
    def test_pending_security_updates_is_high(self):
        def fake_run_cmd(args, timeout=15):
            if args[0] == "dnf":
                return (True, "openssl-1.1.1-1  Security  RHSA-2026:0001\nkernel-5.14  Security  RHSA-2026:0002", "")
            return (True, "", "")

        with mock.patch("rhel10_bio_check.run_cmd", side_effect=fake_run_cmd):
            findings = UpdatesChecker().check()
        f = next(f for f in findings if f.check_id == "RHL040")
        assert f.severity == Severity.HIGH

    def test_no_pending_updates_has_no_rhl040_finding(self):
        def fake_run_cmd(args, timeout=15):
            if args[0] == "dnf":
                return (True, "", "")
            return (True, "", "")

        with mock.patch("rhel10_bio_check.run_cmd", side_effect=fake_run_cmd):
            findings = UpdatesChecker().check()
        assert not any(f.check_id == "RHL040" for f in findings)

    def test_dnf_unavailable_produces_info(self):
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(False, "", "dnf not found")):
            findings = UpdatesChecker().check()
        f = next(f for f in findings if f.check_id == "RHL040")
        assert f.severity == Severity.INFO


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #

class TestAccountsChecker:
    def test_hardened_config_has_minimal_findings(self, tmp_path):
        pwquality = write(tmp_path / "pwquality.conf", "minlen = 15\n")
        login_defs = write(tmp_path / "login.defs", "PASS_MAX_DAYS   60\n")
        passwd = write(tmp_path / "passwd", "root:x:0:0:root:/root:/bin/bash\nsvc:x:1001:1001::/home/svc:/bin/bash\n")
        shadow = write(tmp_path / "shadow", "root:$6$hash:19700:0:99999:7:::\nsvc:$6$hash2:19700:0:99999:7:::\n")

        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "/etc/pam.d/system-auth:auth required pam_faillock.so", "")):
            findings = AccountsChecker().check(pwquality, login_defs, passwd, shadow)

        assert not any(f.check_id in ("RHL050", "RHL051", "RHL052", "RHL053", "RHL054") for f in findings)

    def test_short_minlen_is_flagged(self, tmp_path):
        pwquality = write(tmp_path / "pwquality.conf", "minlen = 8\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            findings = AccountsChecker().check(
                pwquality, tmp_path / "nope1", tmp_path / "nope2", tmp_path / "nope3"
            )
        assert any(f.check_id == "RHL050" for f in findings)

    def test_missing_minlen_is_flagged(self, tmp_path):
        pwquality = write(tmp_path / "pwquality.conf", "# no minlen set\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            findings = AccountsChecker().check(
                pwquality, tmp_path / "nope1", tmp_path / "nope2", tmp_path / "nope3"
            )
        f = next(f for f in findings if f.check_id == "RHL050")
        assert "niet ingesteld" in f.message

    def test_pass_max_days_too_high_is_flagged(self, tmp_path):
        login_defs = write(tmp_path / "login.defs", "PASS_MAX_DAYS   365\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            findings = AccountsChecker().check(
                tmp_path / "nope", login_defs, tmp_path / "nope2", tmp_path / "nope3"
            )
        assert any(f.check_id == "RHL051" for f in findings)

    def test_no_faillock_is_flagged(self, tmp_path):
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "", "")):
            findings = AccountsChecker().check(
                tmp_path / "nope", tmp_path / "nope2", tmp_path / "nope3", tmp_path / "nope4"
            )
        assert any(f.check_id == "RHL052" for f in findings)

    def test_extra_uid_zero_account_is_critical(self, tmp_path):
        passwd = write(tmp_path / "passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            findings = AccountsChecker().check(
                tmp_path / "nope", tmp_path / "nope2", passwd, tmp_path / "nope3"
            )
        f = next(f for f in findings if f.check_id == "RHL053")
        assert f.severity == Severity.CRITICAL
        assert "backdoor" in f.message

    def test_empty_password_hash_is_critical(self, tmp_path):
        shadow = write(tmp_path / "shadow", "root:$6$hash:19700:0:99999:7:::\nsvc::19700:0:99999:7:::\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            findings = AccountsChecker().check(
                tmp_path / "nope", tmp_path / "nope2", tmp_path / "nope3", shadow
            )
        f = next(f for f in findings if f.check_id == "RHL054")
        assert f.severity == Severity.CRITICAL
        assert "svc" in f.message

    def test_unreadable_shadow_produces_info_not_crash(self, tmp_path):
        shadow = tmp_path / "shadow"
        shadow.write_text("root:x:19700:0:99999:7:::\n")
        with mock.patch("rhel10_bio_check.run_cmd", return_value=(True, "pam_faillock", "")):
            with mock.patch.object(Path, "read_text", side_effect=PermissionError):
                findings = AccountsChecker().check(
                    tmp_path / "nope", tmp_path / "nope2", tmp_path / "nope3", shadow
                )
        f = next(f for f in findings if f.check_id == "RHL054")
        assert f.severity == Severity.INFO


# --------------------------------------------------------------------------- #
# Output formatting
# --------------------------------------------------------------------------- #

class TestOutputFormatting:
    def test_format_text_no_findings(self):
        assert "no findings" in format_text([], "myhost")

    def test_format_text_with_findings(self):
        f = Finding("RHL001", "Toegangsbeveiliging", Severity.HIGH, "test message", "/etc/ssh/sshd_config")
        text = format_text([f], "myhost")
        assert "RHL001" in text
        assert "myhost" in text

    def test_format_json_structure(self):
        f = Finding("RHL001", "Toegangsbeveiliging", Severity.HIGH, "test message", "/etc/ssh/sshd_config")
        data = json.loads(format_json([f], "myhost"))
        assert data["hostname"] == "myhost"
        assert data["finding_count"] == 1
        assert data["findings"][0]["check_id"] == "RHL001"
        assert data["findings"][0]["severity"] == "HIGH"

    def test_format_html_contains_findings_and_disclaimer(self):
        f = Finding("RHL003", "Toegangsbeveiliging", Severity.CRITICAL, "empty passwords allowed", "/etc/ssh/sshd_config")
        html = format_html([f], "myhost")
        assert "RHL003" in html
        assert "myhost" in html
        assert "BIO2" in html
        assert "<table>" in html

    def test_format_html_no_findings_still_valid(self):
        html = format_html([], "myhost")
        assert "Geen bevindingen" in html


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #

class TestCli:
    def test_main_runs_end_to_end_with_mocked_checks(self, tmp_path, monkeypatch):
        # Point every checker at empty/non-existent paths and mock run_cmd so
        # this executes deterministically regardless of the host it runs on.
        monkeypatch.setattr("rhel10_bio_check.run_cmd", lambda *a, **kw: (True, "", ""))
        out_file = tmp_path / "report.json"
        exit_code = main(["--format", "json", "-o", str(out_file), "--fail-on", "critical"])
        assert exit_code in (0, 1)
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert "findings" in data

    def test_cli_subprocess_smoke_test(self, tmp_path):
        out_file = tmp_path / "report.html"
        result = subprocess.run(
            [sys.executable, "rhel10_bio_check.py", "--format", "html", "-o", str(out_file), "--fail-on", "critical"],
            cwd=Path(__file__).parent,
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode in (0, 1)
        assert out_file.exists()
        assert "<html" in out_file.read_text(encoding="utf-8")
