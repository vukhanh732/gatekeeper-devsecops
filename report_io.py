"""Strict scanner report loading. Unavailable evidence is never a clean scan."""
import json
from pathlib import Path

class ReportError(ValueError):
    pass

def _count(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReportError(f'{name} must be a non-negative integer')
    return value

def load_report(path, scanner):
    try:
        text = Path(path).read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        raise ReportError(f'{scanner}: cannot read {path}: {exc}') from exc
    if scanner == 'Bandit':
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ReportError('Bandit: invalid JSON') from exc
    else:
        # Safety can prepend notices. raw_decode respects braces inside strings.
        data = None
        decoder = json.JSONDecoder()
        for index, char in enumerate(text):
            if char != '{':
                continue
            try:
                candidate, end = decoder.raw_decode(text[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(candidate, dict) and 'vulnerabilities' in candidate:
                if text[index + end:].strip():
                    raise ReportError('Safety: unexpected content after JSON report')
                data = candidate
                break
        if data is None:
            raise ReportError('Safety: no complete supported JSON report')
    if not isinstance(data, dict) or data.get('errors') or data.get('error'):
        raise ReportError(f'{scanner}: report contains scan errors or an invalid root')
    key = 'results' if scanner == 'Bandit' else 'vulnerabilities'
    if not isinstance(data.get(key), list) or any(not isinstance(v, dict) for v in data[key]):
        raise ReportError(f'{scanner}: {key} must be an array of findings')
    if scanner == 'Safety':
        meta = data.get('report_meta', data.get('meta'))
        if not isinstance(meta, dict) or 'vulnerabilities_found' not in meta:
            raise ReportError('Safety: completed scan metadata is required')
        _count(meta['vulnerabilities_found'], 'Safety vulnerability count')
        if not isinstance(data.get('scanned_packages'), (dict, list)):
            raise ReportError('Safety: scanned package evidence is required')
    return data

def bandit_counts(data):
    counts = {level: 0 for level in ('HIGH', 'MEDIUM', 'LOW')}
    for issue in data['results']:
        level = issue.get('issue_severity')
        if level not in counts:
            raise ReportError('Bandit: finding has an unknown severity')
        counts[level] += 1
    metrics = data.get('metrics', {})
    if not isinstance(metrics, dict) or not isinstance(metrics.get('_totals', {}), dict):
        raise ReportError('Bandit: invalid metrics')
    for level in counts:
        reported = metrics.get('_totals', {}).get('SEVERITY.' + level, 0)
        counts[level] = max(counts[level], _count(reported, 'Bandit severity count'))
    return counts

def safety_count(data):
    ignored = data.get('ignored_vulnerabilities', [])
    if not isinstance(ignored, list) or any(not isinstance(v, dict) for v in ignored):
        raise ReportError('Safety: invalid ignored vulnerabilities')
    count = len(data['vulnerabilities']) + len(ignored)
    for key in ('report_meta', 'meta'):
        meta = data.get(key, {})
        if not isinstance(meta, dict):
            raise ReportError('Safety: invalid metadata')
        if 'vulnerabilities_found' in meta:
            count = max(count, _count(meta['vulnerabilities_found'], 'Safety vulnerability count'))
    return count
