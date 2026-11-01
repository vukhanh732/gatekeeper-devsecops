# Gatekeeper

A Python security policy gate that turns scanner reports into an explicit build decision and a readable HTML evidence report.

[Case study](https://security-vu.netlify.app/gatekeeper.html) · [Policy implementation](security_gate.py) · [Reusable action](action.yml) · [Demonstration report](examples/security-dashboard.html)

## Try the offline demo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install bandit
python scripts/policy_demo.py
```

This scans the deliberately vulnerable `app.py` and checks that the gate **blocks** it. Safety input in this offline demo is a labelled synthetic fixture; no Safety account is needed. The [sample HTML report](examples/security-dashboard.html) shows what a reviewer sees.

## Policy

| Evidence | Decision |
| --- | --- |
| Any Bandit High finding | Block, exit `1` |
| Any Safety vulnerability, including ignored findings | Block, exit `1` |
| Missing, malformed or error reports | Block, exit `2` |
| Bandit Medium / Low only | Pass, with findings visible |
| Valid required reports with no blocking findings | Pass, exit `0` |
| OWASP ZAP | Optional report context; does not decide this gate |

Missing or invalid scanner evidence never counts as a clean scan.

The parser supports `safety check` JSON with scan metadata and package evidence. Other Safety schemas may fail closed. See [Safety output formats](https://docs.safetycli.com/safety-2/safety-cli-2-scanner/output-formats).

## Run locally

Python 3.10+:

```bash
git clone https://github.com/vukhanh732/gatekeeper-devsecops.git
cd gatekeeper-devsecops
python3 -m venv .venv
. .venv/bin/activate
pip install bandit 'safety>=3,<4'
bandit -r . -x .venv -f json -o bandit-report.json || true
safety check --file requirements.txt --save-json safety-report.json > safety-scan.log 2>&1 || true
python security_gate.py --bandit bandit-report.json --safety safety-report.json
```

Use the gate's exit status as the build decision. Safety may require credentials; an authentication error blocks the scan.

The reusable action saves structured Safety JSON separately from console output in `safety-scan.log`.

Generate the report separately, including after a blocked decision:

```bash
python generate_security_dashboard.py
```

Open `security-dashboard.html`. Missing evidence is marked **SCAN INCOMPLETE**.

## Use in GitHub Actions

After checkout and Python setup, use `vukhanh732/gatekeeper-devsecops@main` as a composite action with `requirements-file: requirements.txt` (or the target file). For a stable integration, pin it to a reviewed commit SHA. Supply any required Safety credentials through the job environment.

The action scans the caller checkout and declared requirements file, runs the bundled policy script, then generates and uploads the report even if the gate fails. It does not fetch executable Python from a mutable raw URL. It does not start or scan a running web app.

On pushes and pull requests, CI checks that the vulnerable demo is blocked and uploads a labelled report. A green CI run means the policy worked; the demo app is still vulnerable. A manual `workflow_dispatch` also runs the full scanner action with the `SAFETY_API_KEY` repository secret.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

Tests cover clean and blocked decisions, invalid reports and HTML escaping.

`app.py` is deliberately vulnerable. Do not deploy it as a public application.

## Limits

This is an educational CI integration. Report validation cannot prove that an upstream scanner is trustworthy or complete. No organization-wide rollout, universal vulnerability coverage or measured business impact is claimed.
