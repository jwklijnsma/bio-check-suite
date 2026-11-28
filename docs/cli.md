# CLI options

| Flag | Description |
|---|---|
| `--format {text,json,html}` | Output format (default: `text`) |
| `-o, --output FILE` | Write report to a file instead of stdout |
| `--fail-on {low,medium,high,critical}` | Minimum severity that triggers exit code 1 (default: `high`) |

`openshift_bio_check.py` additionally accepts `--binary` to point at a
specific `oc`/`kubectl` path.
