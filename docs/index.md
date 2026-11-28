# BIO Runtime Checks

**Check the live state of RHEL 10 hosts and OpenShift clusters** against a practical
hardening baseline inspired by the Baseline Informatiebeveiliging Overheid (BIO2).
Two standalone scripts, Python 3 standard library only — copy the one you need.

<div class="grid cards" markdown>

-   :simple-redhat: **[RHEL 10 host](rhel10.md)**

    SSH, firewall, SELinux, auditd, updates and accounts.

-   :simple-redhatopenshift: **[OpenShift cluster](openshift.md)**

    kubeadmin, RBAC, audit logging, encryption, SCCs, network policies, Route TLS.

-   :material-console: **[CLI options](cli.md)**

    JSON or text output, severity filters.

-   :material-numeric: **[Exit codes](exit-codes.md)**

    Use the scripts as a gate in automation.

</div>

| Script | Runs on | Checks |
|---|---|---|
| `rhel10_bio_check.py` | A RHEL 10 host, directly | SSH, firewall, SELinux, auditd, updates, accounts |
| `openshift_bio_check.py` | Anywhere with `oc`/`kubectl` logged into a cluster | kubeadmin, RBAC, audit logging, encryption, SCCs, network policies, Route TLS, workload hardening |

!!! warning "Heuristic checks, not an attestation"
    `control_category` values (*Toegangsbeveiliging*, *Hardening*, *Cryptografie*, …) are
    generic BIO2 categories, not official article or measure numbers. Cross-check findings
    against the BIO2 documents on [bio-overheid.nl](https://www.bio-overheid.nl/).
