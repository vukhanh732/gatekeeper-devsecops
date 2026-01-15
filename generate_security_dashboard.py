#!/usr/bin/env python3
"""
Security Dashboard Generator
Aggregates SAST, SCA, and DAST results into a single HTML report.
"""
import json
import os
from datetime import datetime

def load_bandit_report():
    """Parse Bandit SAST results."""
    try:
        with open('bandit-report.json', 'r') as f:
            data = json.load(f)
            metrics = data.get('metrics', {}).get('_totals', {})
            return {
                'high': metrics.get('SEVERITY.HIGH', 0),
                'medium': metrics.get('SEVERITY.MEDIUM', 0),
                'low': metrics.get('SEVERITY.LOW', 0),
                'issues': data.get('results', [])
            }
    except:
        return {'high': 0, 'medium': 0, 'low': 0, 'issues': []}

def load_safety_report():
    """Parse Safety SCA results."""
    try:
        with open('safety-report.json', 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return {'count': len(data), 'vulns': data}
            return {'count': 0, 'vulns': []}
    except:
        return {'count': 0, 'vulns': []}

def load_zap_report():
    """Parse ZAP DAST results."""
    try:
        with open('zap_report.json', 'r') as f:
            data = json.load(f)
            site = data.get('site', [{}])[0]
            alerts = site.get('alerts', [])
            
            risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            for alert in alerts:
                risk = alert.get('riskdesc', '').split()[0]
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                
            return {'alerts': alerts, 'counts': risk_counts}
    except:
        return {'alerts': [], 'counts': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}}

def generate_html_dashboard():
    """Generate the HTML dashboard."""
    
    # Load all reports
    bandit = load_bandit_report()
    safety = load_safety_report()
    zap = load_zap_report()
    
    # Calculate overall risk score
    total_critical = bandit['high'] + zap['counts']['High']
    total_high = bandit['medium'] + zap['counts']['Medium']
    total_medium = bandit['low'] + zap['counts']['Low'] + safety['count']
    
    # Determine status
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
            max-width: 1200px;
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
        .finding {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid #ffc107;
        }}
        .finding-title {{
            font-weight: bold;
            color: #212529;
            margin-bottom: 5px;
        }}
        .finding-desc {{
            color: #6c757d;
            font-size: 0.9em;
        }}
        .footer {{
            background: #212529;
            color: white;
            text-align: center;
            padding: 20px;
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
                <div class="number">{total_critical + total_high + total_medium}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📋 Detailed Findings</h2>
            
            <div class="tool-result">
                <h3>🔍 SAST Scan (Bandit)</h3>
                <p><strong>High:</strong> {bandit['high']} | <strong>Medium:</strong> {bandit['medium']} | <strong>Low:</strong> {bandit['low']}</p>
                {'<p style="color: #28a745; margin-top: 10px;">✅ No critical code vulnerabilities detected</p>' if bandit['high'] == 0 else ''}
            </div>
            
            <div class="tool-result">
                <h3>📦 SCA Scan (Safety)</h3>
                <p><strong>Vulnerable Dependencies:</strong> {safety['count']}</p>
                {'<p style="color: #28a745; margin-top: 10px;">✅ All dependencies are secure</p>' if safety['count'] == 0 else '<p style="color: #ffc107; margin-top: 10px;">⚠️ Some dependencies have known CVEs</p>'}
            </div>
            
            <div class="tool-result">
                <h3>🎯 DAST Scan (OWASP ZAP)</h3>
                <p><strong>High:</strong> {zap['counts']['High']} | <strong>Medium:</strong> {zap['counts']['Medium']} | <strong>Low:</strong> {zap['counts']['Low']}</p>
                <p style="margin-top: 10px;"><strong>Alerts Found:</strong> {len(zap['alerts'])}</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Gatekeeper DevSecOps Pipeline</p>
            <p style="margin-top: 5px; font-size: 0.9em;">© 2026 - Automated Security Scanning</p>
        </div>
    </div>
</body>
</html>
    """
    
    with open('security-dashboard.html', 'w') as f:
        f.write(html)
    
    print("✅ Security Dashboard generated: security-dashboard.html")
    print(f"📊 Status: {status}")
    print(f"🔢 Total Issues: {total_critical + total_high + total_medium}")

if __name__ == "__main__":
    generate_html_dashboard()
