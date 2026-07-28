# BIO Runtime Checks — RHEL 10 & OpenShift

Two standalone, dependency-free (Python 3 stdlib only) scripts that check
**live system/cluster state** against a practical **Baseline
Informatiebeveiliging Overheid (BIO2)**-inspired hardening baseline:

| Script | Runs on | Checks |
|---|---|---|
| `rhel10_bio_check.py` | A RHEL 10 host, directly | SSH, firewall, SELinux, auditd, updates, accounts |
| `openshift_bio_check.py` | Anywhere with `oc`/`kubectl` logged into a cluster | kubeadmin, RBAC, audit logging, encryption, SCCs, network policies, Route TLS, workload hardening |

Each file is fully self-contained — no shared imports, no third-party
dependencies — so you can copy just the one you need.

> [!IMPORTANT]
> `control_category` values (e.g. *"Toegangsbeveiliging"*, *"Hardening"*,
> *"Cryptografie"*) are generic BIO2 control categories, not verbatim official
> BIO2 article/measure numbers. These are heuristic hardening checks, not a
> certified compliance attestation — cross-check findings against the
> authoritative BIO2 document and BIO2 v1.3 control list from
> [bio-overheid.nl](https://www.bio-overheid.nl/).

This is a **different tool** from the static `bio_pipeline_check.py`
Ansible/Helm/OpenShift-manifest linter built earlier — that one scans files
in a git repo as a CI/CD gate; these two scan **actual running systems**.

---

## 1. `rhel10_bio_check.py` — RHEL 10 host

### Usage

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

### What it checks

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

## 2. `openshift_bio_check.py` — live OpenShift cluster

### Usage

```bash
oc login https://api.cluster.example.com:6443

python3 openshift_bio_check.py
python3 openshift_bio_check.py --format html -o bio-report.html
python3 openshift_bio_check.py --format json -o bio-report.json --fail-on critical
```

Uses whatever `oc` (preferred) or `kubectl` context is currently active — it
does not manage login/auth itself. Cluster-scoped resources (`ClusterRoleBinding`,
`SecurityContextConstraints`, `apiserver`) typically need `cluster-reader` or
better to read.

### What it checks

| ID | Severity | Area | Description |
|---|---|---|---|
| `OCPL001` | Critical | Toegangsbeveiliging | `kubeadmin` bootstrap credential still present |
| `OCPL002` | High | Toegangsbeveiliging | `cluster-admin` granted to a non-default subject |
| `OCPL003` | High | Logging en monitoring | API server audit profile is `None`/unset |
| `OCPL004` | High | Cryptografie | etcd/API encryption type is `identity`/unset (not `aescbc`/`aesgcm`) |
| `OCPL005` | Medium | Hardening | Custom SCC allows `allowPrivilegedContainer: true` |
| `OCPL006` | Medium | Netwerkbeveiliging | Namespace(s) with no `NetworkPolicy` |
| `OCPL007` | Medium/High | Cryptografie / Transportbeveiliging | `Route` missing TLS or allows insecure edge termination |
| `OCPL008` | Critical | Hardening | Running pod(s) with `privileged: true` outside system namespaces |
| `OCPL009` | High | Netwerkbeveiliging | Running pod(s) with `hostNetwork: true` outside system namespaces |

System namespaces (`openshift-*`, `kube-*`, `default`) are excluded from the
namespace/workload checks since cluster components legitimately need elevated
access there.

---

## Exit codes (both scripts)

| Code | Meaning |
|---|---|
| `0` | No findings at/above `--fail-on` severity |
| `1` | Findings at/above `--fail-on` severity |
| `2` | Usage/runtime error (e.g. `oc`/`kubectl` not found or not logged in) |

## CLI options (both scripts)

| Flag | Description |
|---|---|
| `--format {text,json,html}` | Output format (default: `text`) |
| `-o, --output FILE` | Write report to a file instead of stdout |
| `--fail-on {low,medium,high,critical}` | Minimum severity that triggers exit code 1 (default: `high`) |

`openshift_bio_check.py` additionally accepts `--binary` to point at a
specific `oc`/`kubectl` path.

## Testing

```bash
pip install pytest
pytest -v test_rhel10_bio_check.py test_openshift_bio_check.py
```

Tests mock `subprocess`/the cluster client so they run without a real RHEL
host or OpenShift cluster.

## Limitations

- **RHEL script**: without root, `/etc/shadow` and some audit-rule checks
  degrade to an `INFO` finding rather than a hard pass/fail — always run with
  `sudo` for a complete scan.
- **OpenShift script**: read access to cluster-scoped resources is required
  for full coverage; missing permissions degrade individual checks to `INFO`
  rather than failing the whole run.
- Both are a practical/core hardening subset, not an exhaustive OpenSCAP-style
  or full-BIO2 audit.
- Control-category labels are illustrative, not authoritative BIO2 clause
  numbers.
