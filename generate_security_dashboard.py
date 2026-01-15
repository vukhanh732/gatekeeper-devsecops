#!/usr/bin/env python3
"""
Enterprise Security Dashboard Generator
Provides detailed remediation guidance for all vulnerabilities.
"""
import json
import os
from datetime import datetime

def load_bandit_report():
    """Parse Bandit SAST results with full details."""
    try:
        with open('bandit-report.json', 'r') as f:
            data = json.load(f)
            metrics = data.get('metrics', {}).get('_totals', {})
            results = data.get('results', [])
            
            # Enrich with remediation info
            for issue in results:
                issue['remediation'] = get_bandit_remediation(issue.get('test_id'))
            
            return {
                'high': metrics.get('SEVERITY.HIGH', 0),
                'medium': metrics.get('SEVERITY.MEDIUM', 0),
                'low': metrics.get('SEVERITY.LOW', 0),
                'issues': results,
                'total': len(results)
            }
    except Exception as e:
        print(f"[DEBUG] Bandit error: {e}")
        return {'high': 0, 'medium': 0, 'low': 0, 'issues': [], 'total': 0}

def get_bandit_remediation(test_id):
    """Provide specific remediation steps for Bandit findings."""
    remediation_map = {
        'B201': {
            'fix': 'Set debug=False in production or use environment variables',
            'code': 'app.run(debug=False)  # or debug=os.getenv("DEBUG", "False") == "True"'
        },
        'B608': {
            'fix': 'Use parameterized queries instead of string concatenation',
            'code': 'cursor.execute("SELECT * FROM users WHERE name = ?", (query,))'
        },
        'B105': {
            'fix': 'Store secrets in environment variables or a secrets manager',
            'code': 'API_KEY = os.getenv("API_KEY")'
        }
    }
    return remediation_map.get(test_id, {'fix': 'Review code and apply security best practices', 'code': ''})

def load_safety_report():
    """Parse Safety SCA results with better error handling."""
    try:
        with open('safety-report.json', 'r') as f:
            content = f.read()
        
        print(f"[DEBUG] Safety file size: {len(content)} bytes")
        
        if not content.strip() or '{' not in content:
            print("[DEBUG] Safety report is empty or invalid")
            return {'count': 0, 'vulns': [], 'total_packages': {}}
            
        json_start = content.find('{')
        data = json.loads(content[json_start:])
        
        print(f"[DEBUG] Safety JSON keys: {list(data.keys())}")
        
        # Safety 3.x has 'vulnerabilities' array
        vulns_array = data.get('vulnerabilities', [])
        
        print(f"[DEBUG] Found {len(vulns_array)} vulnerabilities")
        
        if not vulns_array:
            # Maybe it's in 'report_meta'?
            meta = data.get('report_meta', {})
            vuln_count = meta.get('vulnerabilities_found', 0)
            if vuln_count > 0:
                print(f"[DEBUG] report_meta says {vuln_count} vulns but array is empty")
        
        cve_list = []
        for v in vulns_array:
            cve_data = v.get('CVE', {})
            cve_id = cve_data.get('CVE', 'No CVE') if isinstance(cve_data, dict) else 'No CVE'
            
            pkg_name = v.get('package_name', 'Unknown')
            current_ver = v.get('analyzed_version', 'N/A')
            
            cve_list.append({
                'package': pkg_name,
                'version': current_ver,
                'cve': cve_id,
                'advisory': v.get('advisory', 'No advisory')[:250] + '...',
                'fix_command': f'pip install --upgrade {pkg_name}',
                'file': 'requirements.txt'
            })
        
        return {
            'count': len(vulns_array),
            'vulns': cve_list,
            'total_packages': data.get('scanned_packages', {})
        }
    except Exception as e:
        print(f"[DEBUG] Safety parse error: {e}")
        import traceback
        traceback.print_exc()
        return {'count': 0, 'vulns': [], 'total_packages': {}}


def load_zap_report():
    """Parse ZAP DAST results with detailed remediation."""
    try:
        with open('zap_report.json', 'r') as f:
            data = json.load(f)
            site = data.get('site', [{}])[0]
            alerts = site.get('alerts', [])
            
            risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            detailed_alerts = []
            
            for alert in alerts:
                risk_desc = alert.get('riskdesc', 'Informational')
                risk = risk_desc.split()[0] if ' ' in risk_desc else risk_desc
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                
                instances = alert.get('instances', [])
                affected_urls = [inst.get('uri', 'Unknown URL') for inst in instances[:3]]
                
                detailed_alerts.append({
                    'name': alert.get('name', 'Unknown'),
                    'risk': risk,
                    'desc': alert.get('desc', 'No description')[:200] + '...',
                    'solution': alert.get('solution', 'No solution')[:300] + '...',
                    'reference': alert.get('reference', ''),
                    'cwe_id': alert.get('cweid', 'N/A'),
                    'urls': affected_urls
                })
                
            return {
                'alerts': detailed_alerts,
                'counts': risk_counts,
                'total': len(alerts)
            }
    except Exception as e:
        print(f"[DEBUG] ZAP error: {e}")
        return {'alerts': [], 'counts': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}, 'total': 0}

def generate_vulnerability_cards(bandit, safety, zap):
    """Generate detailed HTML cards with remediation steps."""
    cards_html = ""
    
    # Bandit Issues with Remediation
    for issue in bandit['issues'][:10]:
        severity = issue.get('issue_severity', 'MEDIUM').lower()
        remediation = issue.get('remediation', {})
        
        cards_html += f"""
        <div class="vuln-card severity-{severity}">
            <div class="vuln-header">
                <span class="vuln-type">SAST</span>
                <span class="severity-badge {severity}">{issue.get('issue_severity', 'MEDIUM')}</span>
            </div>
            <h4>{issue.get('test_name', 'Unknown Issue').replace('_', ' ').title()}</h4>
            
            <div class="vuln-section">
                <strong>📍 Location:</strong>
                de>{issue.get('filename', 'N/A')}:{issue.get('line_number', '?')}</code>
            </div>
            
            <div class="vuln-section">
                <strong>⚠️ Issue:</strong>
                <p>{issue.get('issue_text', 'No description')}</p>
            </div>
            
            <div class="vuln-section">
                <strong>🔧 How to Fix:</strong>
                <p>{remediation.get('fix', 'Apply security best practices')}</p>
                {'<pre>' + remediation.get('code', '') + '</pre>' if remediation.get('code') else ''}
            </div>
            
            <div class="vuln-section">
                <strong>🔗 Reference:</strong>
                <a href="{issue.get('more_info', '#')}" target="_blank">Bandit Documentation</a>
            </div>
        </div>
        """
    
    # Safety CVEs with Fix Commands
    for vuln in safety['vulns'][:10]:
        cards_html += f"""
        <div class="vuln-card severity-high">
            <div class="vuln-header">
                <span class="vuln-type">SCA</span>
                <span class="severity-badge high">CVE</span>
            </div>
            <h4>{vuln['cve']}: {vuln['package']}</h4>
            
            <div class="vuln-section">
                <strong>📦 Package:</strong> {vuln['package']} v{vuln['version']}
            </div>
            
            <div class="vuln-section">
                <strong>📍 Found in:</strong> de>{vuln['file']}</code>
            </div>
            
            <div class="vuln-section">
                <strong>⚠️ Vulnerability:</strong>
                <p>{vuln['advisory']}</p>
            </div>
            
            <div class="vuln-section">
                <strong>🔧 Fix Command:</strong>
                <pre>{vuln['fix_command']}</pre>
                <p style="font-size: 0.85em; color: #6c757d;">Run this command to upgrade to a secure version</p>
            </div>
        </div>
        """
    
    # ZAP Alerts with URLs
    for alert in zap['alerts'][:10]:
        cards_html += f"""
        <div class="vuln-card severity-{alert['risk'].lower()}">
            <div class="vuln-header">
                <span class="vuln-type">DAST</span>
                <span class="severity-badge {alert['risk'].lower()}">{alert['risk']}</span>
            </div>
            <h4>{alert['name']}</h4>
            
            <div class="vuln-section">
                <strong>🌐 Affected URLs:</strong>
                {''.join([f'<div>de>{url}</code></div>' for url in alert['urls'][:3]])}
            </div>
            
            <div class="vuln-section">
                <strong>⚠️ Description:</strong>
                <p>{alert['desc']}</p>
            </div>
            
            <div class="vuln-section">
                <strong>🔧 Remediation:</strong>
                <p>{alert['solution']}</p>
            </div>
            
            <div class="vuln-section">
                <strong>🔗 CWE ID:</strong> {alert['cwe_id']}
                {f'<br><strong>Reference:</strong> <a href="{alert["reference"]}" target="_blank">More Info</a>' if alert['reference'] else ''}
            </div>
        </div>
        """
    
    return cards_html if cards_html else '<p style="text-align:center; color: #28a745;">✅ No detailed findings to display</p>'

def generate_html_dashboard(simulate_complex=False):
    """Generate enterprise dashboard with full remediation guidance."""
    
    bandit = load_bandit_report()
    safety = load_safety_report()
    zap = load_zap_report()
    
    if simulate_complex or os.getenv('SIMULATE_COMPLEX_APP') == 'true':
        bandit['high'] = 12
        bandit['medium'] = 28
        safety['count'] = 37
        zap['counts'] = {'High': 8, 'Medium': 22, 'Low': 31, 'Informational': 15}
    
    total_critical = bandit['high'] + zap['counts'].get('High', 0)
    total_high = bandit['medium'] + zap['counts'].get('Medium', 0)
    total_medium = bandit['low'] + zap['counts'].get('Low', 0) + safety['count']
    total_findings = total_critical + total_high + total_medium
    
    if total_critical > 0:
        status = "CRITICAL"
        status_color = "#dc3545"
    elif total_high > 0:
        status = "HIGH RISK"
        status_color = "#fd7e14"
    elif total_medium > 0:
        status = "MEDIUM RISK"
        status_color = "#ffc107"
    else:
        status = "SECURE"
        status_color = "#28a745"
    
    vuln_cards = generate_vulnerability_cards(bandit, safety, zap)
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gatekeeper Security Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
                        max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .timestamp {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        .status-badge {{
            display: inline-block;
            background: {status_color};
            color: white;
            padding: 10px 30px;
            border-radius: 25px;
            font-weight: bold;
            margin-top: 15px;
            font-size: 1.2em;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        .metric-card:hover {{
            transform: translateY(-5px);
        }}
        .metric-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .metric-card .label {{
            color: #6c757d;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .section {{
            padding: 30px;
        }}
        .section h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .tool-result {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }}
        .tool-result h3 {{
            color: #2a5298;
            margin-bottom: 10px;
        }}
        .vuln-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .vuln-card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .vuln-card.severity-high {{
            border-left-color: #dc3545;
        }}
        .vuln-card.severity-medium {{
            border-left-color: #fd7e14;
        }}
        .vuln-card.severity-low {{
            border-left-color: #ffc107;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 15px;
        }}
        .vuln-type {{
            background: #667eea;
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .severity-badge {{
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            color: white;
        }}
        .severity-badge.high {{
            background: #dc3545;
        }}
        .severity-badge.medium {{
            background: #fd7e14;
        }}
        .severity-badge.low {{
            background: #ffc107;
        }}
        .vuln-card h4 {{
            color: #212529;
            margin: 0 0 15px 0;
            font-size: 1.1em;
        }}
        .vuln-section {{
            margin: 15px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        .vuln-section strong {{
            color: #2a5298;
            display: block;
            margin-bottom: 5px;
        }}
        .vuln-section p {{
            color: #495057;
            font-size: 0.9em;
            line-height: 1.6;
            margin: 5px 0;
        }}
        .vuln-section code {{
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }}
        .vuln-section pre {{
            background: #212529;
            color: #00ff00;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.85em;
            margin-top: 5px;
        }}
        .vuln-section a {{
            color: #667eea;
            text-decoration: none;
        }}
        .vuln-section a:hover {{
            text-decoration: underline;
        }}
        .footer {{
            background: #212529;
            color: white;
            text-align: center;
            padding: 20px;
        }}
        .footer p {{
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Gatekeeper Security Dashboard</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <div class="status-badge">{status}</div>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="label">Critical Issues</div>
                <div class="number critical">{total_critical}</div>
            </div>
            <div class="metric-card">
                <div class="label">High Severity</div>
                <div class="number high">{total_high}</div>
            </div>
            <div class="metric-card">
                <div class="label">Medium Severity</div>
                <div class="number medium">{total_medium}</div>
            </div>
            <div class="metric-card">
                <div class="label">Total Findings</div>
                <div class="number">{total_findings}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Scan Summary</h2>
            
            <div class="tool-result">
                <h3>🔍 SAST Scan (Bandit)</h3>
                <p><strong>High:</strong> {bandit['high']} | <strong>Medium:</strong> {bandit['medium']} | <strong>Low:</strong> {bandit['low']}</p>
                {'<p style="color: #28a745; margin-top: 10px;">✅ No critical code vulnerabilities detected</p>' if bandit['high'] == 0 else '<p style="color: #dc3545; margin-top: 10px;">❌ Critical code issues found!</p>'}
            </div>
            
            <div class="tool-result">
                <h3>📦 SCA Scan (Safety)</h3>
                <p><strong>Vulnerable Dependencies:</strong> {safety['count']}</p>
                {'<p style="color: #28a745; margin-top: 10px;">✅ All dependencies are secure</p>' if safety['count'] == 0 else '<p style="color: #ffc107; margin-top: 10px;">⚠️ Dependencies with known CVEs detected - upgrade required</p>'}
            </div>
            
            <div class="tool-result">
                <h3>🎯 DAST Scan (OWASP ZAP)</h3>
                <p><strong>High:</strong> {zap['counts']['High']} | <strong>Medium:</strong> {zap['counts']['Medium']} | <strong>Low:</strong> {zap['counts']['Low']}</p>
                <p style="margin-top: 10px;"><strong>Total Alerts:</strong> {zap['total']}</p>
            </div>
        </div>
        
        <div class="section">
            <h2>🔎 Detailed Vulnerability Analysis</h2>
            <p style="margin-bottom: 20px; color: #6c757d;">Each finding includes location, description, and remediation guidance</p>
            <div class="vuln-grid">
                {vuln_cards}
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Generated by Gatekeeper DevSecOps Pipeline</strong></p>
            <p style="margin-top: 5px; font-size: 0.9em;">© 2026 - Automated Security Scanning & Remediation</p>
        </div>
    </div>
</body>
</html>
    """
    
    with open('security-dashboard.html', 'w') as f:
        f.write(html)
    
    print("=" * 70)
    print("✅ Enhanced Security Dashboard generated: security-dashboard.html")
    print(f"📊 Status: {status}")
    print(f"🔢 Total Findings: {total_findings}")
    print(f"   - Critical: {total_critical}")
    print(f"   - High: {total_high}")
    print(f"   - Medium: {total_medium}")
    print("=" * 70)

if __name__ == "__main__":
    generate_html_dashboard()

