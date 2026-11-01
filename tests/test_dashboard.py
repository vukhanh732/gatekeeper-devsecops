import json
import os
from pathlib import Path
import tempfile
import unittest
from generate_security_dashboard import generate_html_dashboard

class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        previous = Path.cwd()
        os.chdir(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.chdir, previous)
    def test_missing_reports_never_claim_clean(self):
        html = generate_html_dashboard()
        self.assertIn('SCAN INCOMPLETE', html)
        self.assertNotIn('POLICY PASSED', html)
    def test_report_fields_are_text_and_sample_label_visible(self):
        payload = '<script>alert("x")</script>'
        Path('bandit-report.json').write_text(json.dumps({'results':[{'issue_severity':'HIGH','filename':payload,'code':payload}]}))
        Path('safety-report.json').write_text(json.dumps({'vulnerabilities':[{'advisory':payload}], 'scanned_packages':{}, 'report_meta':{'vulnerabilities_found':1}}))
        html = generate_html_dashboard('Synthetic fixture')
        self.assertIn('POLICY BLOCKED', html)
        self.assertIn('Demonstration data', html)
        self.assertNotIn('<script>', html)
        self.assertIn('&lt;script&gt;', html)

if __name__ == '__main__': unittest.main()
