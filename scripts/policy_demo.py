#!/usr/bin/env python3
"""Run the bounded, offline policy demonstration using a real Bandit scan."""
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command, *, cwd=None):
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def main():
    if shutil.which("bandit") is None:
        print("Bandit is required. Install it with: python -m pip install bandit", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="gatekeeper-policy-demo-") as temp:
        work = Path(temp)
        bandit_report = work / "bandit-report.json"
        safety_report = work / "safety-report.json"
        shutil.copyfile(ROOT / "examples" / "safety-report.json", safety_report)

        scan = run([
            "bandit", "-r", str(ROOT / "app.py"), "-f", "json", "-o", str(bandit_report),
        ])
        if scan.returncode != 1:
            print(f"Expected Bandit to find issues and exit 1; got {scan.returncode}.\n{scan.stderr}", file=sys.stderr)
            return 1
        bandit_data = json.loads(bandit_report.read_text(encoding="utf-8"))
        high_findings = [
            item for item in bandit_data.get("results", [])
            if item.get("issue_severity") == "HIGH"
        ]
        if not high_findings:
            print("Bandit exited 1, but the report has no HIGH finding to exercise this policy.", file=sys.stderr)
            return 1

        gate = run([
            sys.executable, str(ROOT / "security_gate.py"),
            "--bandit", str(bandit_report), "--safety", str(safety_report),
        ])
        print(gate.stdout, end="")
        if gate.returncode != 1:
            print(f"Expected policy gate exit 1; got {gate.returncode}.\n{gate.stderr}", file=sys.stderr)
            return 1

        label = "Current Bandit scan of vulnerable app.py; synthetic Safety fixture"
        dashboard = run([
            sys.executable, str(ROOT / "generate_security_dashboard.py"),
            "--sample-label", label,
        ], cwd=work)
        print(dashboard.stdout, end="")
        html_path = work / "security-dashboard.html"
        if dashboard.returncode != 0 or not html_path.is_file():
            print(f"Dashboard generation failed.\n{dashboard.stderr}", file=sys.stderr)
            return 1
        html = html_path.read_text(encoding="utf-8")
        for expected in ("POLICY BLOCKED", "Demonstration data", label):
            if expected not in html:
                print(f"Dashboard is missing expected evidence: {expected}", file=sys.stderr)
                return 1

        print("Offline policy demo passed: Bandit HIGH finding, synthetic Safety evidence, expected gate block, labelled dashboard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
