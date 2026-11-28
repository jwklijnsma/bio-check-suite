# RHEL 10 host

## Usage

```bash
# Copy to the target host
scp rhel10_bio_check.py user@host:/tmp/

# Run directly on the host (sudo recommended for full accuracy —
# reading /etc/shadow and full audit rules needs root)
ssh user@host 'sudo python3 /tmp/rhel10_bio_check.py'

# HTML report for an auditor
ssh user@host 'sudo python3 /tmp/rhel10_bio_check.py --format html -o /tmp/bio-report.html'
scp user@host:/tmp/bio-report.html .
```

No pip install required — pure standard library.

## What it checks

| ID | Severity | Area | Description |
|---|---|---|---|
| `RHL001` | Medium/High | SSH | `PermitRootLogin` not disabled |
| `RHL002` | Low/Medium | SSH | `PasswordAuthentication` not disabled |
| `RHL003` | Critical | SSH | `PermitEmptyPasswords yes` |
| `RHL004` | Low | SSH | `X11Forwarding yes` |
| `RHL005` | Medium | SSH | `MaxAuthTries` unset or > 4 |
| `RHL006` | Low | SSH | `ClientAliveInterval` unset/0 |
| `RHL010` | Medium/High | Firewall | firewalld/nftables inactive or not enabled at boot |
| `RHL011` | Medium | Firewall | Default firewalld zone is `trusted` |
| `RHL020` | High/Critical | SELinux | Not in `Enforcing` mode |
| `RHL021` | High | SELinux | `/etc/selinux/config` won't be Enforcing after reboot |
| `RHL030` | High | Auditd | `auditd` not active |
| `RHL031` | Medium | Auditd | `auditd` active but not enabled at boot |
| `RHL032` | Low | Auditd | No audit rules configured |
| `RHL040` | High | Updates | Pending security updates (via `dnf updateinfo`) |
| `RHL041` | Low | Updates | `dnf-automatic.timer` not active/enabled |
| `RHL050` | Medium | Accounts | Password minimum length (`pwquality minlen`) < 14 or unset |
| `RHL051` | Medium | Accounts | `PASS_MAX_DAYS` > 90 or unset |
| `RHL052` | Medium | Accounts | `pam_faillock` not configured (no lockout policy) |
| `RHL053` | Critical | Accounts | Extra account(s) with UID 0 besides root |
| `RHL054` | Critical | Accounts | Account(s) with an empty password hash |

---
