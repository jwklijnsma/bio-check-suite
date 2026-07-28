#!/usr/bin/env python3
"""
rhel10_bio_check.py
====================

Standalone, dependency-free (stdlib only) BIO2-style baseline hardening
checker for a running RHEL 10 host. Checks live system state -- not
config files in a git repo -- across:

    - SSH daemon configuration
    - Firewall (firewalld / nftables)
    - SELinux
    - auditd
    - Pending security updates
    - Account / password policy

Designed to be copied to a single host and run directly:

    scp rhel10_bio_check.py user@host:/tmp/
    ssh user@host 'sudo python3 /tmp/rhel10_bio_check.py --format html -o /tmp/bio-report.html'

Some checks (shadow password inspection, full update check) need root to
be fully accurate; without root they degrade to an INFO finding rather
than failing.

IMPORTANT: control_category values are generic BIO2 control categories,
not verbatim official BIO2 article/measure numbers. Cross-check against
the authoritative BIO2 document from bio-overheid.nl for formal
compliance reporting.

Exit codes:
    0 -> no findings at/above --fail-on severity
    1 -> findings at/above --fail-on severity
    2 -> usage / runtime error
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


# --------------------------------------------------------------------------- #
# Data model (self-contained; no shared module so this file stays portable)
# --------------------------------------------------------------------------- #

class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.upper()]

    def __str__(self) -> str:
        return self.name


@dataclasses.dataclass
class Finding:
    check_id: str
    control_category: str
    severity: Severity
    message: str
    location: str  # e.g. "/etc/ssh/sshd_config", "firewalld", "/etc/shadow"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = str(self.severity)
        return d


def run_cmd(args: list[str], timeout: int = 15) -> tuple[bool, str, str]:
    """Run a command, never raise. Returns (ok, stdout, stderr)."""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return False, "", f"command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return False, "", f"command timed out: {' '.join(args)}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, "", str(exc)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def parse_sshd_config(text: str) -> dict[str, str]:
    """Parse sshd_config-style key/value pairs. Last occurrence wins, which
    matches how OpenSSH itself applies Match-less top-level directives when
    concatenating Include'd drop-in files in order."""
    config: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0], parts[1].strip()
        config[key.lower()] = value
    return config


def read_sshd_config(sshd_config_path: Path) -> dict[str, str]:
    merged: dict[str, str] = {}
    if sshd_config_path.exists():
        merged.update(parse_sshd_config(sshd_config_path.read_text(encoding="utf-8", errors="replace")))
    drop_in_dir = sshd_config_path.parent / "sshd_config.d"
    if drop_in_dir.is_dir():
        for f in sorted(drop_in_dir.glob("*.conf")):
            try:
                merged.update(parse_sshd_config(f.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    return merged


class SshChecker:
    def check(self, sshd_config_path: Path = Path("/etc/ssh/sshd_config")) -> list[Finding]:
        findings: list[Finding] = []
        if not sshd_config_path.exists():
            return [Finding("RHL001", "Toegangsbeveiliging", Severity.INFO,
                             f"{sshd_config_path} niet gevonden; SSH-checks overgeslagen.",
                             str(sshd_config_path))]

        cfg = read_sshd_config(sshd_config_path)
        loc = str(sshd_config_path)

        permit_root = cfg.get("permitrootlogin", "").lower()
        if permit_root == "yes":
            findings.append(Finding("RHL001", "Toegangsbeveiliging", Severity.HIGH,
                                     "PermitRootLogin staat op 'yes'; direct root-login via SSH is toegestaan.", loc))
        elif permit_root == "":
            findings.append(Finding("RHL001", "Toegangsbeveiliging", Severity.MEDIUM,
                                     "PermitRootLogin is niet expliciet geconfigureerd; zet dit expliciet op 'no'.", loc))

        password_auth = cfg.get("passwordauthentication", "").lower()
        if password_auth == "yes":
            findings.append(Finding("RHL002", "Toegangsbeveiliging", Severity.MEDIUM,
                                     "PasswordAuthentication staat op 'yes'; overweeg alleen sleutel-authenticatie.", loc))
        elif password_auth == "":
            findings.append(Finding("RHL002", "Toegangsbeveiliging", Severity.LOW,
                                     "PasswordAuthentication is niet expliciet geconfigureerd.", loc))

        if cfg.get("permitemptypasswords", "no").lower() == "yes":
            findings.append(Finding("RHL003", "Toegangsbeveiliging", Severity.CRITICAL,
                                     "PermitEmptyPasswords staat op 'yes'; accounts zonder wachtwoord kunnen inloggen.", loc))

        if cfg.get("x11forwarding", "no").lower() == "yes":
            findings.append(Finding("RHL004", "Hardening", Severity.LOW,
                                     "X11Forwarding staat aan; alleen nodig indien functioneel vereist.", loc))

        max_auth_tries = cfg.get("maxauthtries")
        if max_auth_tries is None or not max_auth_tries.isdigit() or int(max_auth_tries) > 4:
            findings.append(Finding("RHL005", "Toegangsbeveiliging", Severity.MEDIUM,
                                     "MaxAuthTries is niet ingesteld of hoger dan 4.", loc))

        client_alive = cfg.get("clientaliveinterval")
        if client_alive is None or not client_alive.isdigit() or int(client_alive) == 0:
            findings.append(Finding("RHL006", "Continuiteit", Severity.LOW,
                                     "ClientAliveInterval is niet ingesteld; sessies verlopen mogelijk niet automatisch.", loc))

        return findings


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #

class FirewallChecker:
    def check(self) -> list[Finding]:
        findings: list[Finding] = []

        fw_active, _, _ = run_cmd(["systemctl", "is-active", "--quiet", "firewalld"])
        fw_enabled, _, _ = run_cmd(["systemctl", "is-enabled", "--quiet", "firewalld"])
        nft_active, _, _ = run_cmd(["systemctl", "is-active", "--quiet", "nftables"])

        if not fw_active and not nft_active:
            findings.append(Finding("RHL010", "Netwerkbeveiliging", Severity.HIGH,
                                     "Geen actieve firewall gevonden (firewalld en nftables zijn beide inactief).",
                                     "firewalld/nftables"))
        elif fw_active and not fw_enabled:
            findings.append(Finding("RHL010", "Netwerkbeveiliging", Severity.MEDIUM,
                                     "firewalld is actief maar niet enabled; staat na reboot mogelijk uit.",
                                     "firewalld"))

        if fw_active:
            ok, zone_out, _ = run_cmd(["firewall-cmd", "--get-default-zone"])
            if ok and zone_out.strip().lower() == "trusted":
                findings.append(Finding("RHL011", "Netwerkbeveiliging", Severity.MEDIUM,
                                         "Standaard firewalld-zone is 'trusted' (staat al het verkeer toe).",
                                         "firewalld"))

        return findings


# --------------------------------------------------------------------------- #
# SELinux
# --------------------------------------------------------------------------- #

class SelinuxChecker:
    def check(self, config_path: Path = Path("/etc/selinux/config")) -> list[Finding]:
        findings: list[Finding] = []

        ok, out, _ = run_cmd(["getenforce"])
        if ok:
            mode = out.strip().lower()
            if mode != "enforcing":
                sev = Severity.CRITICAL if mode == "disabled" else Severity.HIGH
                findings.append(Finding("RHL020", "Hardening", sev,
                                         f"SELinux staat op '{out.strip()}' in plaats van 'Enforcing'.",
                                         "getenforce"))
        else:
            findings.append(Finding("RHL020", "Hardening", Severity.INFO,
                                     "Kon SELinux-status niet bepalen (getenforce niet beschikbaar).", "getenforce"))

        if config_path.exists():
            text = config_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\s*SELINUX\s*=\s*(\w+)", text, re.MULTILINE | re.IGNORECASE)
            if m and m.group(1).lower() != "enforcing":
                findings.append(Finding("RHL021", "Hardening", Severity.HIGH,
                                         f"{config_path}: SELINUX={m.group(1)}; blijft na reboot niet in Enforcing-modus.",
                                         str(config_path)))

        return findings


# --------------------------------------------------------------------------- #
# auditd
# --------------------------------------------------------------------------- #

class AuditdChecker:
    def check(self, rules_dir: Path = Path("/etc/audit/rules.d")) -> list[Finding]:
        findings: list[Finding] = []

        active, _, _ = run_cmd(["systemctl", "is-active", "--quiet", "auditd"])
        enabled, _, _ = run_cmd(["systemctl", "is-enabled", "--quiet", "auditd"])

        if not active:
            findings.append(Finding("RHL030", "Logging en monitoring", Severity.HIGH,
                                     "auditd is niet actief; systeemgebeurtenissen worden niet gelogd.", "auditd"))
        elif not enabled:
            findings.append(Finding("RHL031", "Logging en monitoring", Severity.MEDIUM,
                                     "auditd is actief maar niet enabled; staat na reboot mogelijk uit.", "auditd"))

        if rules_dir.is_dir():
            rule_files = [f for f in rules_dir.glob("*.rules") if f.stat().st_size > 0]
            if not rule_files:
                findings.append(Finding("RHL032", "Logging en monitoring", Severity.LOW,
                                         f"Geen (niet-lege) audit rules gevonden in {rules_dir}.", str(rules_dir)))

        return findings


# --------------------------------------------------------------------------- #
# Updates
# --------------------------------------------------------------------------- #

class UpdatesChecker:
    def check(self) -> list[Finding]:
        findings: list[Finding] = []

        ok, out, err = run_cmd(["dnf", "-q", "updateinfo", "list", "security"], timeout=60)
        if ok:
            lines = [l for l in out.splitlines() if l.strip()]
            if lines:
                findings.append(Finding("RHL040", "Patchmanagement", Severity.HIGH,
                                         f"{len(lines)} openstaande security-update(s) gevonden (dnf updateinfo).",
                                         "dnf"))
        else:
            findings.append(Finding("RHL040", "Patchmanagement", Severity.INFO,
                                     f"Kon security-updates niet controleren: {err or 'dnf niet beschikbaar of geen netwerktoegang'}.",
                                     "dnf"))

        auto_active, _, _ = run_cmd(["systemctl", "is-active", "--quiet", "dnf-automatic.timer"])
        auto_enabled, _, _ = run_cmd(["systemctl", "is-enabled", "--quiet", "dnf-automatic.timer"])
        if not (auto_active or auto_enabled):
            findings.append(Finding("RHL041", "Patchmanagement", Severity.LOW,
                                     "dnf-automatic.timer is niet actief/enabled; overweeg geautomatiseerde (security-)updates.",
                                     "dnf-automatic"))

        return findings


# --------------------------------------------------------------------------- #
# Accounts / password policy
# --------------------------------------------------------------------------- #

class AccountsChecker:
    def check(
        self,
        pwquality_path: Path = Path("/etc/security/pwquality.conf"),
        login_defs_path: Path = Path("/etc/login.defs"),
        passwd_path: Path = Path("/etc/passwd"),
        shadow_path: Path = Path("/etc/shadow"),
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Password quality (minlen)
        minlen = None
        if pwquality_path.exists():
            text = pwquality_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\s*minlen\s*=\s*(\d+)", text, re.MULTILINE)
            if m:
                minlen = int(m.group(1))
        if minlen is None or minlen < 14:
            findings.append(Finding("RHL050", "Toegangsbeveiliging", Severity.MEDIUM,
                                     f"Minimale wachtwoordlengte (pwquality minlen) is "
                                     f"{'niet ingesteld' if minlen is None else minlen}; BIO-baseline adviseert >= 14.",
                                     str(pwquality_path)))

        # Password max age
        max_days = None
        if login_defs_path.exists():
            text = login_defs_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", text, re.MULTILINE)
            if m:
                max_days = int(m.group(1))
        if max_days is None or max_days > 90 or max_days == 99999:
            findings.append(Finding("RHL051", "Toegangsbeveiliging", Severity.MEDIUM,
                                     f"PASS_MAX_DAYS is "
                                     f"{'niet ingesteld' if max_days is None else max_days}; BIO-baseline adviseert <= 90 dagen.",
                                     str(login_defs_path)))

        # faillock / account lockout
        ok, out, _ = run_cmd(["grep", "-r", "pam_faillock", "/etc/pam.d/"])
        if not ok or not out.strip():
            findings.append(Finding("RHL052", "Toegangsbeveiliging", Severity.MEDIUM,
                                     "pam_faillock lijkt niet geconfigureerd in /etc/pam.d/; geen account-lockout na mislukte pogingen.",
                                     "/etc/pam.d/"))

        # extra UID 0 accounts
        if passwd_path.exists():
            uid0_users = []
            for line in passwd_path.read_text(encoding="utf-8", errors="replace").splitlines():
                fields = line.split(":")
                if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                    uid0_users.append(fields[0])
            if uid0_users:
                findings.append(Finding("RHL053", "Toegangsbeveiliging", Severity.CRITICAL,
                                         f"Extra account(s) met UID 0 naast root gevonden: {', '.join(uid0_users)}.",
                                         str(passwd_path)))

        # empty password hashes in shadow (root required to read)
        if shadow_path.exists():
            try:
                empty_pw_users = []
                for line in shadow_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    fields = line.split(":")
                    if len(fields) >= 2 and fields[1] == "":
                        empty_pw_users.append(fields[0])
                if empty_pw_users:
                    findings.append(Finding("RHL054", "Toegangsbeveiliging", Severity.CRITICAL,
                                             f"Account(s) zonder wachtwoord-hash gevonden: {', '.join(empty_pw_users)}.",
                                             str(shadow_path)))
            except PermissionError:
                findings.append(Finding("RHL054", "Toegangsbeveiliging", Severity.INFO,
                                         f"Geen leesrechten op {shadow_path}; draai als root voor volledige controle.",
                                         str(shadow_path)))
        elif not is_root():
            findings.append(Finding("RHL054", "Toegangsbeveiliging", Severity.INFO,
                                     "Kon /etc/shadow niet lezen; draai als root voor volledige controle.",
                                     str(shadow_path)))

        return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_all_checks() -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(SshChecker().check())
    findings.extend(FirewallChecker().check())
    findings.extend(SelinuxChecker().check())
    findings.extend(AuditdChecker().check())
    findings.extend(UpdatesChecker().check())
    findings.extend(AccountsChecker().check())
    return findings


# --------------------------------------------------------------------------- #
# Output formatting
# --------------------------------------------------------------------------- #

def format_text(findings: list[Finding], hostname: str) -> str:
    if not findings:
        return f"BIO baseline check ({hostname}): no findings. \u2713"
    lines = [f"BIO baseline check ({hostname}): {len(findings)} finding(s)\n"]
    for f in sorted(findings, key=lambda x: -x.severity.value):
        lines.append(f"[{f.severity}] {f.check_id} ({f.control_category}) - {f.location}")
        lines.append(f"    {f.message}")
    return "\n".join(lines)


def format_json(findings: list[Finding], hostname: str) -> str:
    payload = {
        "hostname": hostname,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


SEVERITY_COLORS = {
    "CRITICAL": "#b30000",
    "HIGH": "#d9534f",
    "MEDIUM": "#e0a800",
    "LOW": "#5b8def",
    "INFO": "#6c757d",
}


def format_html(findings: list[Finding], hostname: str) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {s.name: 0 for s in Severity}
    for f in findings:
        counts[f.severity.name] += 1

    rows = []
    for f in sorted(findings, key=lambda x: -x.severity.value):
        color = SEVERITY_COLORS.get(f.severity.name, "#333")
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity.name}</span></td>
          <td><code>{f.check_id}</code></td>
          <td>{f.control_category}</td>
          <td>{f.message}</td>
          <td><code>{f.location}</code></td>
        </tr>""")

    summary_chips = "".join(
        f'<span class="chip" style="background:{SEVERITY_COLORS[name]}">{name}: {count}</span>'
        for name, count in counts.items() if count
    )

    return f"""<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="utf-8">
<title>BIO baseline rapport - {hostname}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 2rem; background: #f7f7f9; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.2rem; }}
  .meta {{ color: #555; margin-bottom: 1.2rem; }}
  .disclaimer {{ background: #fff8e1; border-left: 4px solid #e0a800; padding: 0.8rem 1rem; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .chip {{ display: inline-block; color: white; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.8rem; margin-right: 0.4rem; }}
  table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  th, td {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 1px solid #eee; vertical-align: top; }}
  th {{ background: #fafafa; }}
  .badge {{ color: white; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
  code {{ background: #f0f0f0; padding: 0.1rem 0.3rem; border-radius: 3px; font-size: 0.85em; }}
</style>
</head>
<body>
  <h1>BIO baseline rapport</h1>
  <div class="meta">Host: <strong>{hostname}</strong> &middot; Gegenereerd: {generated} &middot; {len(findings)} bevinding(en)</div>
  <div class="disclaimer">
    De <em>control_category</em> per bevinding is een generieke BIO2-controlecategorie, geen letterlijk
    BIO2-artikel-/maatregelnummer. Gebruik dit rapport als hulpmiddel; toets tegen de officiele BIO2-baseline
    van bio-overheid.nl voor een formele compliance-vaststelling.
  </div>
  <div>{summary_chips}</div>
  <table>
    <thead><tr><th>Severity</th><th>ID</th><th>Categorie</th><th>Bevinding</th><th>Locatie</th></tr></thead>
    <tbody>{"".join(rows) if rows else '<tr><td colspan="5">Geen bevindingen.</td></tr>'}</tbody>
  </table>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="BIO2-style baseline hardening checker for a running RHEL 10 host."
    )
    parser.add_argument("--format", choices=["text", "json", "html"], default="text")
    parser.add_argument("-o", "--output", help="Write report to this file instead of stdout")
    parser.add_argument(
        "--fail-on", choices=["low", "medium", "high", "critical"], default="high",
        help="Minimum severity that causes a non-zero exit code. Default: high",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not is_root():
        print("WARNING: not running as root; some checks (shadow file, full audit rules) "
              "will be limited. Run with sudo for a complete scan.", file=sys.stderr)

    hostname = socket.gethostname()

    try:
        findings = run_all_checks()
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"ERROR running BIO checks: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = format_json(findings, hostname)
    elif args.format == "html":
        report = format_html(findings, hostname)
    else:
        report = format_text(findings, hostname)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report)

    threshold = Severity.from_str(args.fail_on)
    if any(f.severity.value >= threshold.value for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
