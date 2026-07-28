#!/usr/bin/env python3
"""
openshift_bio_check.py
========================

Standalone, dependency-free (stdlib only) BIO2-style baseline checker for a
LIVE OpenShift cluster. Uses the `oc` (or `kubectl`) CLI against your
current logged-in context -- it does not scan files, it queries the
running cluster.

Usage:
    oc login https://api.cluster.example.com:6443
    python3 openshift_bio_check.py --format html -o bio-report.html

Requires: `oc` (preferred) or `kubectl` already installed and authenticated
to the target cluster with sufficient read (get/list) RBAC across the
resources checked (cluster-scoped resources like ClusterRoleBinding, SCC,
and the apiserver/authentication configs typically need cluster-reader or
better).

Checks (practical/core subset, not exhaustive):
    - kubeadmin bootstrap credential still present
    - cluster-admin ClusterRoleBindings granted to non-default subjects
    - API server audit logging profile
    - etcd/API data encryption configuration
    - permissive custom SecurityContextConstraints
    - namespaces without any NetworkPolicy
    - Routes without TLS
    - running pods with privileged / hostNetwork security context

IMPORTANT: control_category values are generic BIO2 control categories,
not verbatim official BIO2 article/measure numbers. Cross-check against
the authoritative BIO2 document from bio-overheid.nl for formal
compliance reporting.

Exit codes:
    0 -> no findings at/above --fail-on severity
    1 -> findings at/above --fail-on severity
    2 -> usage / runtime error (e.g. oc/kubectl not found or not logged in)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
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
    location: str  # e.g. namespace/name, "ClusterRoleBinding", "apiserver"

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = str(self.severity)
        return d


# System namespaces excluded from namespace-level checks (NetworkPolicy etc.)
SYSTEM_NAMESPACE_PREFIXES = ("openshift-", "kube-", "default", "openshift")


def is_system_namespace(name: str) -> bool:
    return name == "default" or any(name.startswith(p) for p in SYSTEM_NAMESPACE_PREFIXES if p != "default")


# --------------------------------------------------------------------------- #
# Cluster client: thin wrapper around `oc`/`kubectl -o json`
# --------------------------------------------------------------------------- #

class ClusterClient:
    def __init__(self, binary: str | None = None):
        self.binary = binary or self._detect_binary()

    @staticmethod
    def _detect_binary() -> str | None:
        for candidate in ("oc", "kubectl"):
            if shutil.which(candidate):
                return candidate
        return None

    def available(self) -> bool:
        return self.binary is not None

    def get_json(self, args: list[str], timeout: int = 30) -> tuple[bool, object, str]:
        """Run `<binary> get ... -o json` style command. Returns (ok, data, error)."""
        if not self.binary:
            return False, None, "oc/kubectl binary not found on PATH"
        try:
            proc = subprocess.run(
                [self.binary, *args, "-o", "json"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return False, None, f"command timed out: {self.binary} {' '.join(args)}"
        except Exception as exc:  # pragma: no cover - defensive
            return False, None, str(exc)

        if proc.returncode != 0:
            return False, None, proc.stderr.strip() or f"{self.binary} exited {proc.returncode}"
        try:
            return True, json.loads(proc.stdout), ""
        except json.JSONDecodeError as exc:
            return False, None, f"could not parse JSON output: {exc}"

    def whoami(self) -> tuple[bool, str]:
        if not self.binary:
            return False, ""
        try:
            proc = subprocess.run([self.binary, "whoami"], capture_output=True, text=True, timeout=15)
            return proc.returncode == 0, proc.stdout.strip()
        except Exception:
            return False, ""


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #

class KubeadminChecker:
    def check(self, client: ClusterClient) -> list[Finding]:
        ok, data, err = client.get_json(["get", "secret", "kubeadmin", "-n", "kube-system"])
        if ok and data:
            return [Finding(
                "OCPL001", "Toegangsbeveiliging", Severity.CRITICAL,
                "Het kubeadmin bootstrap-account bestaat nog; verwijder dit na initiele setup "
                "en gebruik een echte identity provider.",
                "secret/kubeadmin (kube-system)",
            )]
        if not ok and "NotFound" not in err and "not found" not in err.lower():
            return [Finding("OCPL001", "Toegangsbeveiliging", Severity.INFO,
                             f"Kon kubeadmin-secret niet controleren: {err}", "secret/kubeadmin (kube-system)")]
        return []


class ClusterAdminBindingChecker:
    # Subjects considered "expected"/built-in and not worth flagging.
    EXPECTED_SUBJECT_PREFIXES = ("system:", "kube:")

    def check(self, client: ClusterClient) -> list[Finding]:
        ok, data, err = client.get_json(["get", "clusterrolebindings"])
        if not ok:
            return [Finding("OCPL002", "Toegangsbeveiliging", Severity.INFO,
                             f"Kon ClusterRoleBindings niet ophalen: {err}", "ClusterRoleBinding")]

        findings: list[Finding] = []
        for item in data.get("items", []):
            role_ref = item.get("roleRef", {})
            if role_ref.get("name") != "cluster-admin":
                continue
            subjects = item.get("subjects") or []
            flagged = [
                f"{s.get('kind', '?')}:{s.get('name', '?')}"
                for s in subjects
                if not str(s.get("name", "")).startswith(self.EXPECTED_SUBJECT_PREFIXES)
            ]
            if flagged:
                binding_name = item.get("metadata", {}).get("name", "?")
                findings.append(Finding(
                    "OCPL002", "Toegangsbeveiliging", Severity.HIGH,
                    f"ClusterRoleBinding '{binding_name}' geeft cluster-admin aan: {', '.join(flagged)}. "
                    f"Controleer of dit noodzakelijk is (least privilege).",
                    f"clusterrolebinding/{binding_name}",
                ))
        return findings


class ApiServerConfigChecker:
    def check(self, client: ClusterClient) -> list[Finding]:
        findings: list[Finding] = []
        ok, data, err = client.get_json(["get", "apiserver", "cluster"])
        if not ok:
            return [Finding("OCPL003", "Logging en monitoring", Severity.INFO,
                             f"Kon apiserver-configuratie niet ophalen: {err}", "apiserver/cluster")]

        spec = data.get("spec", {})
        audit_profile = (spec.get("audit") or {}).get("profile")
        if not audit_profile or audit_profile == "None":
            findings.append(Finding(
                "OCPL003", "Logging en monitoring", Severity.HIGH,
                f"API server audit-profiel is '{audit_profile or 'niet ingesteld'}'; "
                f"API-aanroepen worden niet of nauwelijks gelogd.",
                "apiserver/cluster",
            ))

        encryption_type = (spec.get("encryption") or {}).get("type")
        if not encryption_type or encryption_type.lower() in ("", "identity"):
            findings.append(Finding(
                "OCPL004", "Cryptografie", Severity.HIGH,
                f"Etcd/API data-encryptie staat op "
                f"'{encryption_type or 'niet ingesteld (identity/plaintext)'}'; "
                f"overweeg 'aescbc' of 'aesgcm' voor encryptie van data-at-rest.",
                "apiserver/cluster",
            ))

        return findings


class SccChecker:
    # SCCs shipped by OpenShift itself; anything else is operator-added.
    BUILTIN_SCC_NAMES = {
        "anyuid", "hostaccess", "hostmount-anyuid", "hostnetwork", "hostnetwork-v2",
        "node-exporter", "nonroot", "nonroot-v2", "privileged", "restricted", "restricted-v2",
    }

    def check(self, client: ClusterClient) -> list[Finding]:
        ok, data, err = client.get_json(["get", "scc"])
        if not ok:
            return [Finding("OCPL005", "Hardening", Severity.INFO,
                             f"Kon SecurityContextConstraints niet ophalen: {err}", "scc")]

        findings: list[Finding] = []
        for item in data.get("items", []):
            name = item.get("metadata", {}).get("name", "?")
            if name in self.BUILTIN_SCC_NAMES:
                continue  # built-in 'privileged' SCC existing is expected; usage is what matters
            if item.get("allowPrivilegedContainer") is True:
                findings.append(Finding(
                    "OCPL005", "Hardening", Severity.MEDIUM,
                    f"Aangepaste SecurityContextConstraints '{name}' staat "
                    f"allowPrivilegedContainer: true toe.",
                    f"scc/{name}",
                ))
        return findings


class NetworkPolicyChecker:
    def check(self, client: ClusterClient) -> list[Finding]:
        ok_ns, ns_data, err_ns = client.get_json(["get", "namespaces"])
        if not ok_ns:
            return [Finding("OCPL006", "Netwerkbeveiliging", Severity.INFO,
                             f"Kon namespaces niet ophalen: {err_ns}", "namespace")]

        namespaces = [
            item.get("metadata", {}).get("name", "")
            for item in ns_data.get("items", [])
        ]
        namespaces = [n for n in namespaces if n and not is_system_namespace(n)]

        ok_np, np_data, err_np = client.get_json(["get", "networkpolicy", "--all-namespaces"])
        if not ok_np:
            return [Finding("OCPL006", "Netwerkbeveiliging", Severity.INFO,
                             f"Kon NetworkPolicies niet ophalen: {err_np}", "networkpolicy")]

        namespaces_with_policy = {
            item.get("metadata", {}).get("namespace", "")
            for item in np_data.get("items", [])
        }

        missing = sorted(set(namespaces) - namespaces_with_policy)
        if missing:
            shown = ", ".join(missing[:10]) + (f", +{len(missing) - 10} meer" if len(missing) > 10 else "")
            return [Finding(
                "OCPL006", "Netwerkbeveiliging", Severity.MEDIUM,
                f"{len(missing)} namespace(s) zonder NetworkPolicy (standaard 'allow-all' verkeer): {shown}.",
                "networkpolicy",
            )]
        return []


class RouteTlsChecker:
    def check(self, client: ClusterClient) -> list[Finding]:
        ok, data, err = client.get_json(["get", "routes", "--all-namespaces"])
        if not ok:
            return [Finding("OCPL007", "Cryptografie / Transportbeveiliging", Severity.INFO,
                             f"Kon Routes niet ophalen: {err}", "route")]

        findings: list[Finding] = []
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            ns, name = meta.get("namespace", "?"), meta.get("name", "?")
            spec = item.get("spec", {})
            if "tls" not in spec:
                findings.append(Finding(
                    "OCPL007", "Cryptografie / Transportbeveiliging", Severity.HIGH,
                    f"Route '{name}' in namespace '{ns}' heeft geen TLS-configuratie.",
                    f"route/{name} ({ns})",
                ))
            elif str(spec.get("tls", {}).get("insecureEdgeTerminationPolicy", "")).lower() == "allow":
                findings.append(Finding(
                    "OCPL007", "Cryptografie / Transportbeveiliging", Severity.MEDIUM,
                    f"Route '{name}' in namespace '{ns}' staat onversleuteld verkeer toe "
                    f"(insecureEdgeTerminationPolicy: Allow).",
                    f"route/{name} ({ns})",
                ))
        return findings


class WorkloadHardeningChecker:
    def check(self, client: ClusterClient) -> list[Finding]:
        ok, data, err = client.get_json(["get", "pods", "--all-namespaces"])
        if not ok:
            return [Finding("OCPL008", "Hardening", Severity.INFO,
                             f"Kon pods niet ophalen: {err}", "pod")]

        findings: list[Finding] = []
        privileged_pods: list[str] = []
        host_network_pods: list[str] = []

        for item in data.get("items", []):
            meta = item.get("metadata", {})
            ns, name = meta.get("namespace", "?"), meta.get("name", "?")
            if is_system_namespace(ns):
                continue  # cluster/system workloads legitimately need elevated access
            spec = item.get("spec", {})

            if spec.get("hostNetwork") is True:
                host_network_pods.append(f"{ns}/{name}")

            containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
            for c in containers:
                sc = c.get("securityContext") or {}
                if sc.get("privileged") is True:
                    privileged_pods.append(f"{ns}/{name} ({c.get('name', '?')})")
                    break

        if privileged_pods:
            shown = ", ".join(privileged_pods[:10]) + (f", +{len(privileged_pods) - 10} meer" if len(privileged_pods) > 10 else "")
            findings.append(Finding(
                "OCPL008", "Hardening", Severity.CRITICAL,
                f"{len(privileged_pods)} draaiende pod(s) met privileged container buiten systeem-namespaces: {shown}.",
                "pod",
            ))

        if host_network_pods:
            shown = ", ".join(host_network_pods[:10]) + (f", +{len(host_network_pods) - 10} meer" if len(host_network_pods) > 10 else "")
            findings.append(Finding(
                "OCPL009", "Netwerkbeveiliging", Severity.HIGH,
                f"{len(host_network_pods)} draaiende pod(s) met hostNetwork: true buiten systeem-namespaces: {shown}.",
                "pod",
            ))

        return findings


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_all_checks(client: ClusterClient) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(KubeadminChecker().check(client))
    findings.extend(ClusterAdminBindingChecker().check(client))
    findings.extend(ApiServerConfigChecker().check(client))
    findings.extend(SccChecker().check(client))
    findings.extend(NetworkPolicyChecker().check(client))
    findings.extend(RouteTlsChecker().check(client))
    findings.extend(WorkloadHardeningChecker().check(client))
    return findings


# --------------------------------------------------------------------------- #
# Output formatting (same shape/style as rhel10_bio_check.py, duplicated for
# portability -- this file is meant to be copied standalone)
# --------------------------------------------------------------------------- #

def format_text(findings: list[Finding], cluster_label: str) -> str:
    if not findings:
        return f"BIO baseline check ({cluster_label}): no findings. \u2713"
    lines = [f"BIO baseline check ({cluster_label}): {len(findings)} finding(s)\n"]
    for f in sorted(findings, key=lambda x: -x.severity.value):
        lines.append(f"[{f.severity}] {f.check_id} ({f.control_category}) - {f.location}")
        lines.append(f"    {f.message}")
    return "\n".join(lines)


def format_json(findings: list[Finding], cluster_label: str) -> str:
    payload = {
        "cluster": cluster_label,
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


def format_html(findings: list[Finding], cluster_label: str) -> str:
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
<title>BIO baseline rapport - {cluster_label}</title>
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
  <h1>BIO baseline rapport - OpenShift</h1>
  <div class="meta">Cluster: <strong>{cluster_label}</strong> &middot; Gegenereerd: {generated} &middot; {len(findings)} bevinding(en)</div>
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
        description="BIO2-style baseline checker for a live OpenShift cluster (uses oc/kubectl)."
    )
    parser.add_argument("--binary", help="Path to oc or kubectl binary (default: auto-detect on PATH)")
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

    client = ClusterClient(args.binary)
    if not client.available():
        print("ERROR: neither 'oc' nor 'kubectl' found on PATH. Install one and log in "
              "('oc login ...') before running this check.", file=sys.stderr)
        return 2

    ok, whoami = client.whoami()
    cluster_label = whoami if ok and whoami else client.binary
    if not ok:
        print(f"WARNING: '{client.binary} whoami' failed; you may not be logged in. "
              f"Checks that fail will be reported as INFO findings.", file=sys.stderr)

    try:
        findings = run_all_checks(client)
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"ERROR running BIO checks: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        report = format_json(findings, cluster_label)
    elif args.format == "html":
        report = format_html(findings, cluster_label)
    else:
        report = format_text(findings, cluster_label)

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
