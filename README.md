# Gatekeeper

A Python security policy gate that turns scanner reports into an explicit build decision and a readable HTML evidence report.

[Case study](https://security-vu.netlify.app/gatekeeper.html) · [Policy implementation](security_gate.py) · [Reusable action](action.yml) · [Demonstration report](examples/security-dashboard.html)

## Policy

| Evidence | Decision |
| --- | --- |
| Any Bandit High finding | Block, exit `1` |
| Any Safety vulnerability, including ignored findings | Block, exit `1` |
| Missing, malformed or error reports | Block, exit `2` |
| Bandit Medium / Low only | Pass, with findings visible |
| Valid required reports with no blocking findings | Pass, exit `0` |
| OWASP ZAP | Optional report context; does not decide this gate |

Bandit findings are counted directly and checked against reported severity totals. Safety JSON must include completed scan metadata and scanned-package evidence. The old workflow fallback `{"vulnerabilities": []}` is rejected, so a scanner failure cannot establish a clean result.

The parser supports the `safety check --json` report shape with `report_meta` (or compatible `meta`), `scanned_packages` and `vulnerabilities`. It does not support every newer `safety scan` output schema; unsupported formats fail closed. See [Safety output documentation](https://docs.safetycli.com/safety-2/safety-cli-2-scanner/output-formats).

## Run locally

Python 3.10+:

```bash
git clone https://github.com/vukhanh732/gatekeeper-devsecops.git
cd gatekeeper-devsecops
python3 -m venv .venv
. .venv/bin/activate
pip install bandit 'safety>=3,<4'
bandit -r . -x .venv -f json -o bandit-report.json || true
safety check --file requirements.txt --json > safety-report.json 2>&1 || true
python security_gate.py --bandit bandit-report.json --safety safety-report.json
```

Scanner nonzero exits are retained as report evidence; **the gate's exit status must be enforced**. Safety may require authentication/API access. An authentication error blocks the decision rather than being replaced with an empty scan.

Generate the report separately, including after a blocked decision:

```bash
python generate_security_dashboard.py
```

Open `security-dashboard.html`. Missing required evidence is visibly marked **SCAN INCOMPLETE**. Report fields are escaped and the HTML has no scripts. Suggested remediation requires reviewing the actual advisory; no universal patched version is invented.

## Use in GitHub Actions

After checkout and Python setup, use `vukhanh732/gatekeeper-devsecops@main` as a composite action with `requirements-file: requirements.txt` (or the target file). For a stable integration, pin it to a reviewed commit SHA. Supply any required Safety credentials through the job environment.

The action scans the caller checkout and declared requirements file, runs the bundled policy script, then generates and uploads the report even if the gate fails. It does not fetch executable Python from a mutable raw URL. It does not start or scan a running web app.

The repository's existing standalone workflow also calls the hardened gate, but its later DAST steps are skipped when the blocking gate fails. Its legacy empty-report fallback is now rejected by the parser.

## Demonstration fixture

[`examples/`](examples/) contains synthetic Bandit/Safety findings and an HTML report with a visible **Demonstration data** banner. It illustrates a blocked build, not a current scan of production software.

Rebuild it without scanner accounts:

```bash
(cd examples && python ../generate_security_dashboard.py --sample-label 'Synthetic regression fixture')
```

## Verify

```bash
python3 -m unittest discover -s tests -v
```

Tests exercise clean/blocked decisions, findings without metrics, ignored vulnerabilities, scanner errors, the legacy fabricated fallback, mixed notice/JSON output, and HTML escaping.

`app.py` and its old Flask requirements are a deliberately vulnerable scanner target. Do not deploy that demo as a public application. A failing pipeline can be the expected policy outcome; it is not evidence of a successful production deployment.

## Limits

This is an educational CI integration. Report validation cannot prove that an upstream scanner is trustworthy or complete. No organization-wide rollout, universal vulnerability coverage or measured business impact is claimed.
