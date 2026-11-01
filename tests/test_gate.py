import json
import tempfile
import unittest
from pathlib import Path
from security_gate import main
from report_io import load_report, ReportError

def safety(findings=None, **extra):
    report={'vulnerabilities':findings or [],'report_meta':{'vulnerabilities_found':len(findings or [])},'scanned_packages':{}}
    report.update(extra)
    return report

class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bandit = Path(self.temp.name)/'bandit.json'
        self.safety = Path(self.temp.name)/'safety.json'
        self.write({'results': []}, safety())
    def write(self, bandit, safety):
        self.bandit.write_text(json.dumps(bandit))
        self.safety.write_text(json.dumps(safety))
    def gate(self):
        return main(['--bandit',str(self.bandit),'--safety',str(self.safety)])
    def test_clean_and_medium(self):
        self.assertEqual(self.gate(),0)
        self.write({'results':[{'issue_severity':'MEDIUM'}]}, safety())
        self.assertEqual(self.gate(),0)
    def test_high_without_metrics_blocks(self):
        self.write({'results':[{'issue_severity':'HIGH'}]}, safety())
        self.assertEqual(self.gate(),1)
    def test_metadata_and_ignored_findings_block(self):
        for report in [safety(report_meta={'vulnerabilities_found':1}), safety(ignored_vulnerabilities=[{}])]:
            self.safety.write_text(json.dumps(report));self.assertEqual(self.gate(),1)
    def test_missing_malformed_unknown_or_error_is_not_clean(self):
        for report in ['', '{"vulnerabilities":[]}', 'not logged in', '{', '{}', '{"vulnerabilities":[],"errors":["scan failed"]}', '{"vulnerabilities":"bad"}', '{"vulnerabilities":[]} garbage']:
            self.safety.write_text(report);self.assertEqual(self.gate(),2)
        self.safety.unlink();self.assertEqual(self.gate(),2)
    def test_notice_and_braces_in_advisory(self):
        self.safety.write_text('Notice: scan follows\n'+json.dumps(safety([{'advisory':'use {safe} syntax'}])))
        self.assertEqual(self.gate(),1)
    def test_invalid_bandit_shapes_and_scan_errors(self):
        for report in [{'results':[],'errors':[{'reason':'parse failure'}]}, {'results':[{'issue_severity':'UNKNOWN'}]}, {'results':[], 'metrics':{'_totals':{'SEVERITY.HIGH':-1}}}]:
            self.bandit.write_text(json.dumps(report));self.assertEqual(self.gate(),2)

if __name__ == '__main__':unittest.main()
