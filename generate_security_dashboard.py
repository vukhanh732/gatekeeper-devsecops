#!/usr/bin/env python3
"""Render scanner evidence as a standalone, script-free HTML report."""
import argparse
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from report_io import ReportError, load_report, bandit_counts, safety_count


def load_bandit_report():
    try:
        data = load_report('bandit-report.json', 'Bandit')
        counts = bandit_counts(data)
        return {**{k.lower(): v for k, v in counts.items()}, 'issues': data['results'], 'error': None}
    except ReportError as exc:
        return {'high': 0, 'medium': 0, 'low': 0, 'issues': [], 'error': str(exc)}


def load_safety_report():
    try:
        data = load_report('safety-report.json', 'Safety')
        count = safety_count(data)
        return {'count': count, 'vulns': data['vulnerabilities'] + data.get('ignored_vulnerabilities', []), 'error': None}
    except ReportError as exc:
        return {'count': 0, 'vulns': [], 'error': str(exc)}


def load_zap_report():
    """ZAP is optional context; it is not an input to the blocking policy."""
    try:
        data = json.loads(Path('zap_report.json').read_text(encoding='utf-8'))
        sites = data['site']
        if not isinstance(sites, list):
            raise ValueError('site must be an array')
        alerts = []
        for site in sites:
            if not isinstance(site, dict) or not isinstance(site.get('alerts'), list):
                raise ValueError('invalid site alerts')
            for alert in site['alerts']:
                if not isinstance(alert, dict):
                    raise ValueError('invalid alert')
                alerts.append(alert)
        return {'alerts': alerts, 'error': None}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        return {'alerts': [], 'error': str(exc)}


def text(value):
    return escape(str(value), quote=True)


def generate_vulnerability_cards(bandit, safety, zap):
    cards = []
    def card(kind, title, location, description, code=''):
        cards.append(f'<article class="finding"><span class="kind">{text(kind)}</span>'
                     f'<h3>{text(title)}</h3><p class="location">{text(location)}</p>'
                     f'<p>{text(description)}</p>' + (f'<pre>{text(code)}</pre>' if code else '') + '</article>')
    for issue in bandit['issues'][:20]:
        card('SAST · ' + str(issue.get('issue_severity', 'unknown')), issue.get('test_name', 'Code finding'),
             f"{issue.get('filename', 'unknown')}:{issue.get('line_number', '?')}",
             issue.get('issue_text', ''), issue.get('code', ''))
    for issue in safety['vulns'][:20]:
        card('DEPENDENCY', issue.get('package_name', 'Unknown package'),
             'Analysed version: ' + str(issue.get('analyzed_version', 'unknown')),
             str(issue.get('advisory', 'Review the scanner advisory.')) +
             ' Review the advisory and select a compatible patched release; no universal upgrade version is assumed.')
    for alert in zap['alerts'][:20]:
        card('DAST · INFORMATIONAL TO POLICY', alert.get('name', 'ZAP alert'),
             alert.get('riskdesc', 'Unspecified risk'),
             str(alert.get('desc', '')) + '\n' + str(alert.get('solution', '')))
    return '\n'.join(cards) or '<p>No detailed findings available. Check scan availability above.</p>'


def generate_html_dashboard(label=None):
    bandit, safety, zap = load_bandit_report(), load_safety_report(), load_zap_report()
    if bandit['error'] or safety['error']:
        status, state = 'SCAN INCOMPLETE', 'unknown'
    elif bandit['high'] or safety['count']:
        status, state = 'POLICY BLOCKED', 'blocked'
    else:
        status, state = 'POLICY PASSED', 'passed'
    def summary(name, error, description):
        return f'<section class="scanner"><h3>{name}</h3><p>{text(error) if error else text(description)}</p></section>'
    summaries = summary('Bandit / code', bandit['error'],
                        f"High {bandit['high']} · Medium {bandit['medium']} · Low {bandit['low']}")
    summaries += summary('Safety / dependencies', safety['error'], f"{safety['count']} findings, including ignored vulnerabilities")
    summaries += summary('ZAP / optional context', zap['error'] and 'Report unavailable. Not part of the blocking policy.',
                         f"{len(zap['alerts'])} alert types. Not part of the blocking policy.")
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>Gatekeeper / Security evidence</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#edece6;color:#202e34;font:16px/1.6 system-ui,sans-serif}}
main{{max-width:1180px;margin:auto;padding:50px 36px}}header{{border-top:5px solid #244954;padding:28px 0 32px;border-bottom:1px solid #b9c3c2}}
.eyebrow,.kind{{font:12px/1.5 monospace;letter-spacing:.08em;color:#48616a}}h1{{font-size:clamp(32px,5vw,56px);line-height:1.1;letter-spacing:-2px;margin:16px 0}}h2{{font-size:25px;margin:38px 0 20px}}h3{{font-size:18px;margin:8px 0}}
.meta,.location{{font-size:13px;color:#53676c}}.status{{display:inline-block;padding:8px 14px;border:1px solid currentColor;font:600 14px monospace}}
.blocked{{color:#9b3b2d}}.unknown{{color:#7a5320}}.passed{{color:#246342}}.sample{{background:#f4e4bf;border:1px solid #c9a45f;padding:12px 16px;margin-bottom:24px}}
.scanners{{display:grid;grid-template-columns:repeat(3,1fr);border-block:1px solid #b9c3c2}}.scanner{{padding:20px 24px 20px 0}}.scanner p{{margin-bottom:0;font-size:14px;overflow-wrap:anywhere}}
.findings{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px}}.finding{{background:#fafaf6;border:1px solid #c9d0cc;padding:24px;overflow-wrap:anywhere}}.finding p{{font-size:14px}}pre{{font:13px/1.7 monospace;white-space:pre-wrap;background:#e6ece8;padding:16px;overflow-wrap:anywhere}}
footer{{border-top:1px solid #b9c3c2;margin-top:36px;padding-top:20px;font-size:13px;color:#53676c}}
@media(max-width:650px){{main{{padding:24px 20px}}.scanners,.findings{{grid-template-columns:1fr}}.scanner{{padding:16px 0;border-bottom:1px solid #ccd3cf}}}}
</style></head><body><main>
{f'<aside class="sample">Demonstration data · {text(label)}</aside>' if label else ''}
<header><span class="eyebrow">GATEKEEPER / SECURITY EVIDENCE</span><h1>A build decision,<br>with the evidence attached.</h1>
<p class="meta">Generated {generated}</p><p class="status {state}">{status}</p>
<p>Block on any Bandit High finding or Safety vulnerability. Missing or invalid required reports block the decision.</p></header>
<h2>Scan coverage</h2><div class="scanners">{summaries}</div>
<h2>Findings to investigate</h2><div class="findings">{generate_vulnerability_cards(bandit, safety, zap)}</div>
<footer>Gatekeeper DevSecOps · This report records scanner evidence, not a guarantee of security. At most 20 details per scanner are shown; full counts and evidence remain in the JSON artifacts.</footer>
</main></body></html>'''
    Path('security-dashboard.html').write_text(html, encoding='utf-8')
    print(f'{status}: security-dashboard.html')
    return html


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample-label', help='Visible demonstration-data banner for fixture reports')
    generate_html_dashboard(parser.parse_args().sample_label)
