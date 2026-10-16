"""Descarga las fuentes de ThreatWatch y las deja como JSON pequeños.

Lo ejecuta la Action cada hora. Estas fuentes no se pueden leer desde el
navegador (no envían cabeceras CORS), así que se descargan aquí y la web lee
el resultado desde la rama `data`.

Si una fuente falla se conserva su último JSON bueno y se anota el error en
status.json: la web nunca enseña datos inventados.

Uso:  python scripts/fetch_feeds.py <carpeta de salida>
Solo usa la biblioteca estándar.
"""
import collections, csv, html, io, json, os, re, sys, time
import urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

UA = 'ThreatWatch/2.0 (+https://github.com/unfantasmaenelsistema/ThreatWatch)'
NOW = datetime.now(timezone.utc)
ISO = lambda d: d.strftime('%Y-%m-%dT%H:%M:%SZ')


def get(url, timeout=60):
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def clean(s, n=None):
    s = html.unescape(re.sub(r'<[^>]+>', ' ', s or ''))
    s = re.sub(r'\s+', ' ', s).strip()
    return s[:n].rstrip() + '…' if n and len(s) > n else s


# ── CISA KEV ──────────────────────────────────────────────────────────────
def kev():
    d = json.loads(get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'))
    items = [{
        'id': v['cveID'], 'vendor': v.get('vendorProject', ''), 'product': v.get('product', ''),
        'name': v.get('vulnerabilityName', ''), 'added': v.get('dateAdded', ''), 'due': v.get('dueDate', ''),
        'ransomware': v.get('knownRansomwareCampaignUse', '') == 'Known',
        'desc': clean(v.get('shortDescription', ''), 400), 'cwes': v.get('cwes', []),
    } for v in d['vulnerabilities']]
    items.sort(key=lambda x: x['added'], reverse=True)
    return {'catalogVersion': d.get('catalogVersion'), 'count': len(items), 'items': items}


# ── NVD (últimos 30 días) ─────────────────────────────────────────────────
def nvd_metric(cve):
    m = cve.get('metrics', {})
    for k in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        if m.get(k):
            e = next((x for x in m[k] if x.get('type') == 'Primary'), m[k][0])
            c = e['cvssData']
            sev = c.get('baseSeverity') or e.get('baseSeverity') or ''
            return c.get('baseScore'), sev.upper(), k[10:].replace('V', 'v')
    return None, '', ''


def nvd():
    start = NOW - timedelta(days=30)
    base = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    q = {'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
         'pubEndDate': NOW.strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'resultsPerPage': 2000}
    items, idx, total = [], 0, None
    while total is None or idx < total:
        q['startIndex'] = idx
        for attempt in range(4):
            try:
                d = json.loads(get(base + '?' + urllib.parse.urlencode(q), timeout=120))
                break
            except Exception:
                if attempt == 3:
                    raise
                time.sleep(15)
        total = d['totalResults']
        for v in d['vulnerabilities']:
            c = v['cve']
            if c.get('vulnStatus') == 'Rejected':
                continue
            score, sev, ver = nvd_metric(c)
            desc = next((x['value'] for x in c.get('descriptions', []) if x['lang'] == 'en'), '')
            cwe = next((x['value'] for w in c.get('weaknesses', []) for x in w.get('description', [])
                        if x['value'].startswith('CWE-')), '')
            items.append({'id': c['id'], 'pub': c['published'][:19] + 'Z', 'score': score, 'sev': sev,
                          'cvss': ver, 'cwe': cwe, 'desc': clean(desc, 260)})
        idx += d['resultsPerPage'] or 2000
        time.sleep(7)  # sin API key: 5 peticiones cada 30 s
    items.sort(key=lambda x: x['pub'], reverse=True)
    # 30 días son >15.000 CVE: se guardan los totales de 30 días y el detalle de 7.
    sevs = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    by_day = collections.defaultdict(lambda: dict.fromkeys(sevs + ('NA',), 0))
    for i in items:
        by_day[i['pub'][:10]][i['sev'] if i['sev'] in sevs else 'NA'] += 1
    cutoff = ISO(NOW - timedelta(days=7))
    recent = [i for i in items if i['pub'] >= cutoff]
    return {'from': ISO(start), 'to': ISO(NOW), 'count': len(items),
            'bySev': collections.Counter(i['sev'] if i['sev'] in sevs else 'NA' for i in items),
            'byDay': dict(sorted(by_day.items())),
            'cwes': collections.Counter(i['cwe'] for i in items if i['cwe']).most_common(12),
            'recentDays': 7, 'items': recent}


# ── URLhaus (últimos 30 días) ─────────────────────────────────────────────
def urlhaus():
    raw = get('https://urlhaus.abuse.ch/downloads/csv_recent/', timeout=120).decode('utf-8', 'replace')
    rows = [r for r in csv.reader(io.StringIO('\n'.join(l for l in raw.splitlines() if not l.startswith('#'))))
            if len(r) >= 9]
    by_day, threats, tags, hosts = collections.Counter(), collections.Counter(), collections.Counter(), collections.Counter()
    online = ip_hosts = 0
    for r in rows:
        by_day[r[1][:10]] += 1
        threats[r[5]] += 1
        for t in r[6].split(','):
            if t and t != 'None':
                tags[t] += 1
        host = urllib.parse.urlsplit(r[2]).hostname or ''
        hosts[host] += 1
        if re.fullmatch(r'[\d.]+|\[?[0-9a-f:]+\]?', host):
            ip_hosts += 1
        if r[3] == 'online':
            online += 1
    rows.sort(key=lambda r: r[1], reverse=True)
    latest = [{'id': r[0], 'added': r[1], 'url': r[2], 'status': r[3], 'threat': r[5],
               'tags': [t for t in r[6].split(',') if t and t != 'None'], 'link': r[7], 'reporter': r[8]}
              for r in rows[:400]]
    return {'total': len(rows), 'online': online, 'ipShare': round(ip_hosts / max(len(rows), 1), 3),
            'byDay': dict(sorted(by_day.items())), 'threats': dict(threats.most_common()),
            'tags': tags.most_common(20), 'hosts': hosts.most_common(15), 'latest': latest}


# ── Feodo Tracker ─────────────────────────────────────────────────────────
def feodo():
    full = json.loads(get('https://feodotracker.abuse.ch/downloads/ipblocklist.json'))
    rec = json.loads(get('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json'))
    keep = ('ip_address', 'port', 'status', 'hostname', 'as_number', 'as_name', 'country', 'first_seen', 'last_online', 'malware')
    seen, items = set(), []
    for src, rows in (('recommended', rec), ('blocklist', full)):
        for x in rows:
            key = (x.get('ip_address'), x.get('port'))
            if key in seen:
                continue
            seen.add(key)
            items.append(dict({k: x.get(k) for k in keep}, list=src))
    return {'count': len(items), 'recommended': len(rec), 'items': items}


# ── ransomware.live ───────────────────────────────────────────────────────
def ransomware():
    d = json.loads(get('https://api.ransomware.live/v2/recentvictims'))
    items = [{'victim': clean(x.get('victim'), 120), 'group': x.get('group', ''), 'country': x.get('country') or '',
              'sector': x.get('activity') or '', 'discovered': x.get('discovered', '')[:19] + 'Z',
              'attack': (x.get('attackdate') or '')[:10], 'domain': x.get('domain') or '', 'page': x.get('url') or ''}
             for x in d]
    items.sort(key=lambda x: x['discovered'], reverse=True)
    c = lambda k: collections.Counter(i[k] for i in items if i[k] and i[k] != 'Not Found').most_common(12)
    return {'count': len(items), 'groups': c('group'), 'sectors': c('sector'), 'countries': c('country'), 'items': items}


# ── Noticias (RSS/Atom) ───────────────────────────────────────────────────
FEEDS = [
    ('The Hacker News', 'en', 'https://feeds.feedburner.com/TheHackersNews'),
    ('BleepingComputer', 'en', 'https://www.bleepingcomputer.com/feed/'),
    ('Krebs on Security', 'en', 'https://krebsonsecurity.com/feed/'),
    ('INCIBE-CERT', 'es', 'https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed'),
    ('Una al día', 'es', 'https://unaaldia.hispasec.com/feed'),
    ('WeLiveSecurity', 'es', 'https://www.welivesecurity.com/es/rss/feed/'),
]


def parse_date(s):
    if not s:
        return None
    try:
        return parsedate_to_datetime(s).astimezone(timezone.utc)
    except Exception:
        try:
            return datetime.fromisoformat(s.replace('Z', '+00:00')).astimezone(timezone.utc)
        except Exception:
            return None


def news():
    items, errors = [], {}
    for name, lang, url in FEEDS:
        try:
            root = ET.fromstring(get(url, timeout=40))
            n = 0
            for it in root.iter():
                tag = it.tag.split('}')[-1]
                if tag not in ('item', 'entry'):
                    continue
                f = {c.tag.split('}')[-1]: c for c in it}
                link = f.get('link')
                href = (link.get('href') or link.text or '').strip() if link is not None else ''
                date = parse_date((f.get('pubDate') if f.get('pubDate') is not None else f.get('updated', f.get('published'))).text
                                  if any(k in f for k in ('pubDate', 'updated', 'published')) else '')
                title = clean(f['title'].text if 'title' in f else '', 200)
                if not title or not href.startswith('http') or not date:
                    continue
                items.append({'title': title, 'link': href, 'date': ISO(date), 'source': name, 'lang': lang})
                n += 1
                if n >= 15:
                    break
        except Exception as e:
            errors[name] = str(e)[:120]
    items.sort(key=lambda x: x['date'], reverse=True)
    return {'count': len(items), 'errors': errors, 'items': items[:80]}


def main(out):
    os.makedirs(out, exist_ok=True)
    status_path = os.path.join(out, 'status.json')
    try:
        status = json.load(open(status_path, encoding='utf-8'))
    except Exception:
        status = {'feeds': {}}
    for name, fn in (('kev', kev), ('nvd', nvd), ('urlhaus', urlhaus), ('feodo', feodo),
                     ('ransomware', ransomware), ('news', news)):
        st = status['feeds'].get(name, {})
        t0 = time.time()
        try:
            data = fn()
            data['updated'] = ISO(datetime.now(timezone.utc))
            with open(os.path.join(out, name + '.json'), 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, separators=(',', ':'))
            st = {'ok': True, 'updated': data['updated'], 'count': data.get('count', data.get('total'))}
            print(f'{name}: ok ({time.time() - t0:.0f}s)')
        except Exception as e:
            st.update(ok=False, error=f'{type(e).__name__}: {e}'[:200], tried=ISO(datetime.now(timezone.utc)))
            print(f'{name}: ERROR {e}')
        status['feeds'][name] = st
    status['updated'] = ISO(datetime.now(timezone.utc))
    with open(status_path, 'w', encoding='utf-8') as f:
        json.dump(status, f, ensure_ascii=False, indent=1)
    if not any(s.get('ok') for s in status['feeds'].values()):
        sys.exit('Ninguna fuente ha funcionado')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'data')
