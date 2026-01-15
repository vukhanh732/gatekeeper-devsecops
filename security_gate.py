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
    """Parses Safety JSON report - extracts JSON from mixed text output."""
    try:
        with open(report_file, 'r') as f:
            content = f.read()
        
        # Find the JSON object boundaries
        start = content.find('{')
        if start == -1:
            print(f"\n[SAFETY SCA] No JSON found in report")
            return 0
        
        # Find the matching closing brace by counting braces
        brace_count = 0
        end = start
        for i in range(start, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end = i + 1
                    break
        
        if brace_count != 0:
            print(f"\n[SAFETY SCA] Malformed JSON in report")
            return 0
        
        json_content = content[start:end]
        data = json.loads(json_content)
        
        # Safety 3.x format
        vulns_array = data.get('vulnerabilities', [])
        vulns = len(vulns_array)
        
        # Fallback: check report_meta
        if vulns == 0 and 'report_meta' in data:
            vulns = data.get('report_meta', {}).get('vulnerabilities_found', 0)
            
        print(f"\n[SAFETY SCA] Scan Complete")
        print(f"  > Vulnerabilities: {vulns}")
        
        return vulns
    except Exception as e:
        print(f"[ERROR] Could not parse Safety report: {e}")
        import traceback
        traceback.print_exc()
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
