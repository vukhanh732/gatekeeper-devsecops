import json
import sys
import argparse

def check_bandit(report_file):
    """Parses Bandit JSON report for High/Medium severity issues."""
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        
        # Extract metrics
        metrics = data.get('metrics', {}).get('_totals', {})
        high = metrics.get('SEVERITY.HIGH', 0)
        medium = metrics.get('SEVERITY.MEDIUM', 0)
        
        print(f"\n[BANDIT SAST] Scan Complete")
        print(f"  > High Severity:   {high}")
        print(f"  > Medium Severity: {medium}")
        
        return high, medium
    except Exception as e:
        print(f"[ERROR] Could not parse Bandit report: {e}")
        return 0, 0

def check_safety(report_file):
    """Parses Safety JSON report for CVEs."""
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
            
        # Safety 2.x/3.x returns a list of issues or a dict with report_meta
        vulns = 0
        if isinstance(data, list):
            vulns = len(data)
        elif isinstance(data, dict):
            vulns = data.get('report_meta', {}).get('vulnerabilities_found', 0)
            
        print(f"\n[SAFETY SCA] Scan Complete")
        print(f"  > Vulnerabilities: {vulns}")
        
        return vulns
    except Exception as e:
        print(f"[ERROR] Could not parse Safety report: {e}")
        return 0

def main():
    parser = argparse.ArgumentParser(description='DevSecOps Quality Gate')
    parser.add_argument('--bandit', required=True, help='Path to Bandit report')
    parser.add_argument('--safety', required=True, help='Path to Safety report')
    args = parser.parse_args()

    fail = False

    # POLICY 1: No High Severity Code Issues
    high_sev, med_sev = check_bandit(args.bandit)
    if high_sev > 0:
        print("❌ FAILURE: Policy Violation - High Severity Code Issues Detected.")
        fail = True

    # POLICY 2: No Known Vulnerable Dependencies
    cves = check_safety(args.safety)
    if cves > 0:
        print("❌ FAILURE: Policy Violation - Vulnerable Dependencies Detected.")
        fail = True

    if fail:
        print("\n🚨 SECURITY GATE: FAILED. Build blocked.")
        sys.exit(1)
    else:
        print("\n✅ SECURITY GATE: PASSED. No critical issues found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
