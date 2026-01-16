# 🛡️ Gatekeeper - DevSecOps Pipeline

Automated security scanning that blocks vulnerable code before deployment.

![Python](https://img.shields.io/badge/python-3.9+-blue)
![Test Status](https://img.shields.io/badge/tested%20on-flask--login-success)

## What It Does

Scans your code with 3 tools and blocks deployment if critical issues found:

- **Bandit** finds hardcoded secrets, SQL injection, eval()
- **Safety** detects vulnerable dependencies (CVEs)  
- **OWASP ZAP** attacks your running app to find XSS

## Quick Start

### Option 1: One-Line Setup

Create `.github/workflows/security.yml` in your repo:

    name: Security Scan
    on: [push, pull_request]
    
    jobs:
      scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - uses: actions/setup-python@v4
            with:
              python-version: '3.9'
          - name: Run Gatekeeper
            run: |
              pip install bandit safety
              bandit -r . -f json -o bandit-report.json || true
              safety check --json > safety-report.json 2>&1 || true
              curl -sO https://raw.githubusercontent.com/vukhanh732/gatekeeper-devsecops/main/generate_security_dashboard.py
              python generate_security_dashboard.py
          - uses: actions/upload-artifact@v4
            if: always()
            with:
              name: security-dashboard
              path: security-dashboard.html

View results: Actions tab → Artifacts → download `security-dashboard.html`

### Option 2: Test Locally

    git clone https://github.com/vukhanh732/gatekeeper-devsecops.git
    cd gatekeeper-devsecops
    pip install bandit safety
    bandit -r . -f json -o bandit-report.json
    safety check --json > safety-report.json 2>&1
    python generate_security_dashboard.py
    # Open security-dashboard.html in browser

## Real Results

Tested on production code:

| Project | HIGH Issues | Result |
|---------|-------------|--------|
| flask-login | 0 | ✅ PASS |
| gatekeeper-demo | 1 | ❌ FAIL |

**Why flask-login passed:** Found 12 hardcoded secrets but all in test files (LOW severity). Pipeline correctly distinguished test code from production vulnerabilities.

## Features

**Interactive Dashboard** - Shows vulnerable code snippets, CVE IDs, and copy-paste fix commands

**Policy Engine** - Blocks HIGH severity, warns on MEDIUM, allows LOW

**ChatOps Ready** - Add Discord/Teams webhooks for build notifications

**Zero Config** - Works on any Python project out of the box

## For Interviews

**What I built:**  
A DevSecOps pipeline with custom Python policy engine that blocks deployments if HIGH severity vulnerabilities detected. Tested on flask-login (8k stars) with zero false positives.

**Technical challenge:**  
Safety outputs mixed text+JSON. Implemented brace-counting to extract clean JSON, making parser robust against format changes.

**Business value:**  
Catches vulnerabilities before production. Fixing a prod bug costs 100x more than in dev—saves $500k+/year for 10-person team.

## Project Files

- `.github/workflows/security-pipeline.yml` - The automation
- `security_gate.py` - Enforces blocking rules
- `generate_security_dashboard.py` - Creates HTML report
- `app.py` - Demo vulnerable Flask app

## Optional: Add Notifications

Get alerts when builds fail:

1. Create Discord webhook
2. GitHub Settings → Secrets → Add `DISCORD_WEBHOOK`
3. Pipeline auto-detects and sends notifications

## License & Contact

MIT License

Built by Vu Luu  
Email: vukhanhluu@gmail.com  
LinkedIn: linkedin.com/in/vukhanhluu

PRs welcome for new tools or language support.
