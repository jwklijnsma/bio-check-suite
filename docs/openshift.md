# OpenShift cluster

## Usage

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

## What it checks

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
