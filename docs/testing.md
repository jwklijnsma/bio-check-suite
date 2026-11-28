# Testing

```bash
pip install pytest
pytest -v test_rhel10_bio_check.py test_openshift_bio_check.py
```

Tests mock `subprocess`/the cluster client so they run without a real RHEL
host or OpenShift cluster.
