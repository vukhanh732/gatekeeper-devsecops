"""Exit 0 for clean evidence, 1 for policy violations, 2 for report failures."""
import argparse
from report_io import ReportError, bandit_counts, load_report, safety_count

def check_bandit(report_file):
    counts = bandit_counts(load_report(report_file, 'Bandit'))
    print(f"Bandit: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}")
    return counts['HIGH'], counts['MEDIUM']

def check_safety(report_file):
    count = safety_count(load_report(report_file, 'Safety'))
    print(f'Safety: {count} reported vulnerabilities (including ignored findings)')
    return count

def main(argv=None):
    parser = argparse.ArgumentParser(description='Fail-closed SAST/dependency quality gate')
    parser.add_argument('--bandit', required=True)
    parser.add_argument('--safety', required=True)
    args = parser.parse_args(argv)
    try:
        high, medium = check_bandit(args.bandit)
        vulnerabilities = check_safety(args.safety)
    except ReportError as exc:
        print(f'REPORT ERROR: {exc}. Build blocked; no clean scan can be established.')
        return 2
    if high or vulnerabilities:
        print('POLICY FAILED: HIGH Bandit findings or dependency vulnerabilities block delivery.')
        return 1
    print('POLICY PASSED' + ('; MEDIUM findings require review.' if medium else '.'))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
