# Limitations

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
