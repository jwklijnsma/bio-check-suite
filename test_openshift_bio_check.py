"""
Tests for openshift_bio_check.py

These tests never touch a real cluster: ClusterClient.get_json is mocked
via a fake in-memory implementation keyed on the `get` sub-resource.

Run with:
    pytest -v test_openshift_bio_check.py
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from openshift_bio_check import (
    ApiServerConfigChecker,
    ClusterAdminBindingChecker,
    ClusterClient,
    Finding,
    KubeadminChecker,
    NetworkPolicyChecker,
    RouteTlsChecker,
    SccChecker,
    Severity,
    WorkloadHardeningChecker,
    format_html,
    format_json,
    format_text,
    is_system_namespace,
    main,
    run_all_checks,
)


class FakeClusterClient:
    """Stands in for ClusterClient; routes get_json(args) to canned responses
    keyed by the resource kind (args[1]) so tests don't need a real cluster."""

    def __init__(self, responses: dict[str, tuple[bool, object, str]]):
        self.responses = responses
        self.binary = "oc"

    def available(self) -> bool:
        return True

    def get_json(self, args, timeout=30):
        # args like ["get", "clusterrolebindings"] or ["get", "secret", "kubeadmin", "-n", "kube-system"]
        key = args[1]
        if key not in self.responses:
            return False, None, f"no fake response configured for {key}"
        return self.responses[key]

    def whoami(self):
        return True, "test-user"


def items(*objs) -> dict:
    return {"items": list(objs)}


# --------------------------------------------------------------------------- #
# Namespace helper
# --------------------------------------------------------------------------- #

class TestIsSystemNamespace:
    def test_openshift_prefixed_is_system(self):
        assert is_system_namespace("openshift-monitoring") is True

    def test_kube_prefixed_is_system(self):
        assert is_system_namespace("kube-system") is True

    def test_default_is_system(self):
        assert is_system_namespace("default") is True

    def test_app_namespace_is_not_system(self):
        assert is_system_namespace("my-app") is False


# --------------------------------------------------------------------------- #
# KubeadminChecker
# --------------------------------------------------------------------------- #

class TestKubeadminChecker:
    def test_kubeadmin_present_is_critical(self):
        client = FakeClusterClient({"secret": (True, {"kind": "Secret"}, "")})
        findings = KubeadminChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL001")
        assert f.severity == Severity.CRITICAL

    def test_kubeadmin_not_found_has_no_findings(self):
        client = FakeClusterClient({"secret": (False, None, "secrets \"kubeadmin\" not found")})
        findings = KubeadminChecker().check(client)
        assert findings == []

    def test_query_error_produces_info(self):
        client = FakeClusterClient({"secret": (False, None, "Forbidden: user cannot get secrets")})
        findings = KubeadminChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL001")
        assert f.severity == Severity.INFO


# --------------------------------------------------------------------------- #
# ClusterAdminBindingChecker
# --------------------------------------------------------------------------- #

class TestClusterAdminBindingChecker:
    def test_only_system_subjects_has_no_findings(self):
        binding = {
            "metadata": {"name": "cluster-admin"},
            "roleRef": {"name": "cluster-admin"},
            "subjects": [{"kind": "Group", "name": "system:masters"}],
        }
        client = FakeClusterClient({"clusterrolebindings": (True, items(binding), "")})
        findings = ClusterAdminBindingChecker().check(client)
        assert findings == []

    def test_non_system_subject_is_flagged(self):
        binding = {
            "metadata": {"name": "danger-binding"},
            "roleRef": {"name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "jan.developer"}],
        }
        client = FakeClusterClient({"clusterrolebindings": (True, items(binding), "")})
        findings = ClusterAdminBindingChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL002")
        assert f.severity == Severity.HIGH
        assert "jan.developer" in f.message

    def test_non_cluster_admin_role_is_ignored(self):
        binding = {
            "metadata": {"name": "viewer-binding"},
            "roleRef": {"name": "view"},
            "subjects": [{"kind": "User", "name": "jan.developer"}],
        }
        client = FakeClusterClient({"clusterrolebindings": (True, items(binding), "")})
        findings = ClusterAdminBindingChecker().check(client)
        assert findings == []

    def test_query_failure_produces_info(self):
        client = FakeClusterClient({"clusterrolebindings": (False, None, "connection refused")})
        findings = ClusterAdminBindingChecker().check(client)
        assert findings[0].severity == Severity.INFO


# --------------------------------------------------------------------------- #
# ApiServerConfigChecker
# --------------------------------------------------------------------------- #

class TestApiServerConfigChecker:
    def test_good_config_has_no_findings(self):
        apiserver = {"spec": {"audit": {"profile": "WriteRequestBodies"}, "encryption": {"type": "aescbc"}}}
        client = FakeClusterClient({"apiserver": (True, apiserver, "")})
        findings = ApiServerConfigChecker().check(client)
        assert findings == []

    def test_missing_audit_profile_is_high(self):
        apiserver = {"spec": {"encryption": {"type": "aescbc"}}}
        client = FakeClusterClient({"apiserver": (True, apiserver, "")})
        findings = ApiServerConfigChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL003")
        assert f.severity == Severity.HIGH

    def test_no_encryption_is_high(self):
        apiserver = {"spec": {"audit": {"profile": "Default"}}}
        client = FakeClusterClient({"apiserver": (True, apiserver, "")})
        findings = ApiServerConfigChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL004")
        assert f.severity == Severity.HIGH

    def test_identity_encryption_is_flagged(self):
        apiserver = {"spec": {"audit": {"profile": "Default"}, "encryption": {"type": "identity"}}}
        client = FakeClusterClient({"apiserver": (True, apiserver, "")})
        findings = ApiServerConfigChecker().check(client)
        assert any(f.check_id == "OCPL004" for f in findings)


# --------------------------------------------------------------------------- #
# SccChecker
# --------------------------------------------------------------------------- #

class TestSccChecker:
    def test_builtin_privileged_scc_is_not_flagged(self):
        scc = {"metadata": {"name": "privileged"}, "allowPrivilegedContainer": True}
        client = FakeClusterClient({"scc": (True, items(scc), "")})
        findings = SccChecker().check(client)
        assert findings == []

    def test_custom_permissive_scc_is_flagged(self):
        scc = {"metadata": {"name": "custom-permissive"}, "allowPrivilegedContainer": True}
        client = FakeClusterClient({"scc": (True, items(scc), "")})
        findings = SccChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL005")
        assert f.severity == Severity.MEDIUM
        assert "custom-permissive" in f.message

    def test_custom_restricted_scc_is_not_flagged(self):
        scc = {"metadata": {"name": "custom-restricted"}, "allowPrivilegedContainer": False}
        client = FakeClusterClient({"scc": (True, items(scc), "")})
        findings = SccChecker().check(client)
        assert findings == []


# --------------------------------------------------------------------------- #
# NetworkPolicyChecker
# --------------------------------------------------------------------------- #

class TestNetworkPolicyChecker:
    def test_all_namespaces_covered_has_no_findings(self):
        ns_data = items(
            {"metadata": {"name": "team-a"}},
            {"metadata": {"name": "openshift-monitoring"}},
        )
        np_data = items({"metadata": {"namespace": "team-a", "name": "default-deny"}})
        client = FakeClusterClient({
            "namespaces": (True, ns_data, ""),
            "networkpolicy": (True, np_data, ""),
        })
        findings = NetworkPolicyChecker().check(client)
        assert findings == []

    def test_namespace_missing_policy_is_flagged(self):
        ns_data = items({"metadata": {"name": "team-a"}}, {"metadata": {"name": "team-b"}})
        np_data = items({"metadata": {"namespace": "team-a", "name": "default-deny"}})
        client = FakeClusterClient({
            "namespaces": (True, ns_data, ""),
            "networkpolicy": (True, np_data, ""),
        })
        findings = NetworkPolicyChecker().check(client)
        assert len(findings) == 1
        assert "team-b" in findings[0].message
        assert "team-a" not in findings[0].message

    def test_system_namespaces_excluded(self):
        ns_data = items({"metadata": {"name": "openshift-monitoring"}}, {"metadata": {"name": "kube-system"}})
        np_data = items()
        client = FakeClusterClient({
            "namespaces": (True, ns_data, ""),
            "networkpolicy": (True, np_data, ""),
        })
        findings = NetworkPolicyChecker().check(client)
        assert findings == []


# --------------------------------------------------------------------------- #
# RouteTlsChecker
# --------------------------------------------------------------------------- #

class TestRouteTlsChecker:
    def test_route_with_tls_redirect_has_no_findings(self):
        route = {
            "metadata": {"name": "myapp", "namespace": "team-a"},
            "spec": {"tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"}},
        }
        client = FakeClusterClient({"routes": (True, items(route), "")})
        findings = RouteTlsChecker().check(client)
        assert findings == []

    def test_route_without_tls_is_high(self):
        route = {"metadata": {"name": "myapp", "namespace": "team-a"}, "spec": {}}
        client = FakeClusterClient({"routes": (True, items(route), "")})
        findings = RouteTlsChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL007")
        assert f.severity == Severity.HIGH

    def test_route_insecure_allow_is_medium(self):
        route = {
            "metadata": {"name": "myapp", "namespace": "team-a"},
            "spec": {"tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Allow"}},
        }
        client = FakeClusterClient({"routes": (True, items(route), "")})
        findings = RouteTlsChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL007")
        assert f.severity == Severity.MEDIUM


# --------------------------------------------------------------------------- #
# WorkloadHardeningChecker
# --------------------------------------------------------------------------- #

class TestWorkloadHardeningChecker:
    def test_no_risky_pods_has_no_findings(self):
        pod = {
            "metadata": {"name": "myapp", "namespace": "team-a"},
            "spec": {"containers": [{"name": "app", "securityContext": {"privileged": False}}]},
        }
        client = FakeClusterClient({"pods": (True, items(pod), "")})
        findings = WorkloadHardeningChecker().check(client)
        assert findings == []

    def test_privileged_pod_outside_system_namespace_is_critical(self):
        pod = {
            "metadata": {"name": "myapp", "namespace": "team-a"},
            "spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]},
        }
        client = FakeClusterClient({"pods": (True, items(pod), "")})
        findings = WorkloadHardeningChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL008")
        assert f.severity == Severity.CRITICAL
        assert "team-a/myapp" in f.message

    def test_privileged_pod_in_system_namespace_is_ignored(self):
        pod = {
            "metadata": {"name": "sdn-agent", "namespace": "openshift-sdn"},
            "spec": {"containers": [{"name": "sdn", "securityContext": {"privileged": True}}]},
        }
        client = FakeClusterClient({"pods": (True, items(pod), "")})
        findings = WorkloadHardeningChecker().check(client)
        assert findings == []

    def test_host_network_pod_is_high(self):
        pod = {
            "metadata": {"name": "myapp", "namespace": "team-a"},
            "spec": {"hostNetwork": True, "containers": [{"name": "app"}]},
        }
        client = FakeClusterClient({"pods": (True, items(pod), "")})
        findings = WorkloadHardeningChecker().check(client)
        f = next(f for f in findings if f.check_id == "OCPL009")
        assert f.severity == Severity.HIGH

    def test_query_failure_produces_info(self):
        client = FakeClusterClient({"pods": (False, None, "Forbidden")})
        findings = WorkloadHardeningChecker().check(client)
        assert findings[0].severity == Severity.INFO


# --------------------------------------------------------------------------- #
# Output formatting
# --------------------------------------------------------------------------- #

class TestOutputFormatting:
    def test_format_text_no_findings(self):
        assert "no findings" in format_text([], "my-cluster")

    def test_format_json_structure(self):
        f = Finding("OCPL001", "Toegangsbeveiliging", Severity.CRITICAL, "kubeadmin present", "secret/kubeadmin")
        data = json.loads(format_json([f], "my-cluster"))
        assert data["cluster"] == "my-cluster"
        assert data["findings"][0]["check_id"] == "OCPL001"

    def test_format_html_contains_disclaimer_and_findings(self):
        f = Finding("OCPL001", "Toegangsbeveiliging", Severity.CRITICAL, "kubeadmin present", "secret/kubeadmin")
        html = format_html([f], "my-cluster")
        assert "OCPL001" in html
        assert "BIO2" in html
        assert "my-cluster" in html


# --------------------------------------------------------------------------- #
# run_all_checks integration
# --------------------------------------------------------------------------- #

class TestRunAllChecks:
    def test_combines_all_checkers(self):
        binding = {
            "metadata": {"name": "danger"}, "roleRef": {"name": "cluster-admin"},
            "subjects": [{"kind": "User", "name": "someone"}],
        }
        client = FakeClusterClient({
            "secret": (False, None, "not found"),
            "clusterrolebindings": (True, items(binding), ""),
            "apiserver": (True, {"spec": {"audit": {"profile": "Default"}, "encryption": {"type": "aescbc"}}}, ""),
            "scc": (True, items(), ""),
            "namespaces": (True, items({"metadata": {"name": "team-a"}}), ""),
            "networkpolicy": (True, items(), ""),
            "routes": (True, items(), ""),
            "pods": (True, items(), ""),
        })
        findings = run_all_checks(client)
        ids = {f.check_id for f in findings}
        assert "OCPL002" in ids
        assert "OCPL006" in ids  # team-a has no network policy


# --------------------------------------------------------------------------- #
# ClusterClient (real class, no live cluster)
# --------------------------------------------------------------------------- #

class TestClusterClient:
    def test_no_binary_available(self):
        with mock.patch("openshift_bio_check.shutil.which", return_value=None):
            client = ClusterClient()
        assert client.available() is False

    def test_prefers_oc_over_kubectl(self):
        with mock.patch("openshift_bio_check.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
            client = ClusterClient()
        assert client.binary == "oc"

    def test_explicit_binary_overrides_detection(self):
        client = ClusterClient(binary="/custom/path/oc")
        assert client.binary == "/custom/path/oc"

    def test_get_json_without_binary_fails_gracefully(self):
        with mock.patch("openshift_bio_check.shutil.which", return_value=None):
            client = ClusterClient()
        ok, data, err = client.get_json(["get", "pods"])
        assert ok is False
        assert "not found" in err


# --------------------------------------------------------------------------- #
# CLI / main
# --------------------------------------------------------------------------- #

class TestCli:
    def test_main_exits_2_when_no_binary_found(self, tmp_path):
        with mock.patch("openshift_bio_check.shutil.which", return_value=None):
            exit_code = main(["--format", "json", "-o", str(tmp_path / "out.json")])
        assert exit_code == 2

    def test_main_runs_end_to_end_with_fake_client(self, tmp_path):
        fake_client = FakeClusterClient({
            "secret": (False, None, "not found"),
            "clusterrolebindings": (True, items(), ""),
            "apiserver": (True, {"spec": {"audit": {"profile": "Default"}, "encryption": {"type": "aescbc"}}}, ""),
            "scc": (True, items(), ""),
            "namespaces": (True, items(), ""),
            "networkpolicy": (True, items(), ""),
            "routes": (True, items(), ""),
            "pods": (True, items(), ""),
        })
        with mock.patch("openshift_bio_check.ClusterClient", return_value=fake_client):
            out_file = tmp_path / "report.html"
            exit_code = main(["--format", "html", "-o", str(out_file), "--fail-on", "critical"])
        assert exit_code == 0
        assert "<html" in out_file.read_text(encoding="utf-8")
