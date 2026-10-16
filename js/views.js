(() => {
  'use strict';
  const { $, esc, num } = TW;
  const t = () => TW.t();
  const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NA'];
  const SEV_COL = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', NA: 'var(--na)' };
  const sevKey = s => (SEVS.includes(s) ? s : 'NA');
  const sevTag = s => `<span class="sev s-${sevKey(s)}">${esc(t().sevNames[sevKey(s)])}</span>`;
  const nvdLink = id => `<a class="mono" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}" target="_blank" rel="noopener">${esc(id)}</a>`;
  const safeLink = (u, prefix) => (typeof u === 'string' && u.startsWith(prefix) ? u : null);
  const unavailable = () => `<section class="panel"><p class="empty">${esc(t().unavailable)}</p></section>`;
  const kpi = (label, value, sub, cls = '') => `<div class="kpi ${cls}"><small>${esc(label)}</small><b class="${/^[\d.,\s%+→—-]+$/.test(String(value)) ? '' : 'txt'}">${value}</b>${sub ? `<span>${esc(sub)}</span>` : ''}</div>`;
  const panel = (title, body, extra = '') => `<section class="panel"><h2><span>${esc(title)}</span>${extra}</h2>${body}</section>`;
  const intro = (text, title) => `<section class="panel intro">${title ? `<h1>${esc(title)}</h1>` : ''}<p class="lead">${esc(text)}</p></section>`;
  const updated = f => (TW.data[f] ? `<small>${esc(t().updatedAt(TW.dateTime(TW.data[f].updated)))}</small>` : '');
  const table = (heads, rows) => `<div class="tablewrap"><table><thead><tr>${heads.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
  const moreBtn = (shown, total, id) => (total > shown ? `<div class="more"><button class="btn" type="button" id="${id}">${esc(t().showMore)} (${num(total - shown)})</button></div>` : '');
  const kevSet = () => new Set(((TW.data.kev && TW.data.kev.items) || []).map(k => k.id));
  const st = TW.st = {
    cve: { range: '7', sev: 'ALL', kev: false, q: '', limit: 100, nvd: null, nvdQ: '', msg: '' },
    kev: { q: '', rw: false, limit: 100 },
    ssl: { domain: '', sub: true, expired: false, filter: 'all', res: null, msg: '', busy: false, limit: 200 },
    uh: { q: '', online: false, limit: 100 },
    rw: { q: '', limit: 100 },
    news: { lang: 'all', src: 'all' }
  };
  const has = (q, ...fields) => !q || fields.some(f => String(f || '').toLowerCase().includes(q));

  // ── Panel ──────────────────────────────────────────────────────────────
  const panelView = {
    html() {
      const d = TW.data, T = t();
      const kev = d.kev, nvd = d.nvd, uh = d.urlhaus, rw = d.ransomware, fd = d.feodo, nw = d.news;
      const since30 = TW.daysAgo(30).slice(0, 10);
      const k = [];
      if (kev) k.push(kpi(T.kKev, num(kev.count), T.kKevSub(num(kev.items.filter(x => x.added >= since30).length)), 'c'));
      if (nvd) k.push(kpi(T.kCve, num(nvd.count), T.kCveSub(num(nvd.bySev.CRITICAL || 0)), 'h'));
      if (uh) k.push(kpi(T.kUrl, num(uh.total), T.kUrlSub(num(uh.online))));
      if (rw) k.push(kpi(T.kRw, num(rw.count), T.kRwSub(TW.date(rw.items[rw.items.length - 1].discovered))));
      if (fd) k.push(kpi(T.kC2, num(fd.count), T.kC2Sub(num(fd.items.filter(x => x.status === 'online').length)), 'g'));
      const days = nvd ? Object.entries(nvd.byDay).slice(-30) : [];
      const legend = `<div class="legend">${SEVS.map(s => `<span><i style="background:${SEV_COL[s]}"></i>${esc(T.sevNames[s])}</span>`).join('')}</div>`;
      const seeAll = tab => `<a href="#${tab}">${esc(T.seeAll)}</a>`;
      const kevList = kev ? `<div class="list">${kev.items.slice(0, 5).map(x => `<div class="it">
          <span>${nvdLink(x.id)} ${x.ransomware ? '<span class="tag rw">ransomware</span>' : ''}</span>
          <span>${esc(x.vendor)} · ${esc(x.product)} — ${esc(x.name)}</span>
          <span class="meta">${esc(TW.date(x.added))}</span></div>`).join('')}</div>` : `<p class="empty">${esc(T.unavailable)}</p>`;
      const rwList = rw ? `<div class="list">${rw.items.slice(0, 7).map(x => `<div class="it">
          <span><b>${esc(x.victim)}</b></span>
          <span class="meta">${esc(x.group)} · ${x.sector && x.sector !== 'Not Found' ? esc(x.sector) + ' · ' : ''}${TW.flag(x.country)} · ${esc(TW.ago(x.discovered))}</span></div>`).join('')}</div>` : `<p class="empty">${esc(T.unavailable)}</p>`;
      const nwList = nw ? `<div class="list">${nw.items.slice(0, 7).map(x => `<div class="it">
          <a href="${esc(x.link)}" target="_blank" rel="noopener">${esc(x.title)}</a>
          <span class="meta">${esc(x.source)} · ${esc(TW.ago(x.date))}</span></div>`).join('')}</div>` : `<p class="empty">${esc(T.unavailable)}</p>`;
      const uhList = uh ? `<div class="list">${uh.latest.slice(0, 7).map(x => `<div class="it">
          <span class="mono break" style="word-break:break-all">${esc(TW.defang(x.url))}</span>
          <span class="meta">${x.status === 'online' ? `<span class="tag on">${esc(T.online)}</span>` : `<span class="tag off">${esc(T.offline)}</span>`} ${x.tags.slice(0, 3).map(g => `<span class="tag">${esc(g)}</span>`).join('')} · ${esc(TW.ago(x.added.replace(' ', 'T') + 'Z'))}</span></div>`).join('')}</div>` : `<p class="empty">${esc(T.unavailable)}</p>`;
      return intro(T.introLead, T.introTitle)
        + (k.length ? `<div class="kpis">${k.join('')}</div>` : '')
        + `<div class="grid g2">${panel(T.pCvesDay, TW.stacked(days, SEVS.map(s => [s, SEV_COL[s]])) + legend + (nvd ? TW.bars(SEVS.map(s => [s, nvd.bySev[s] || 0]), { cls: s => s, label: s => T.sevNames[s] }) : ''), seeAll('cve'))}${panel(T.pKevLatest, kevList, seeAll('kev'))}</div>`
        + `<div class="grid g3">${panel(T.pRwLatest, rwList, seeAll('ransomware'))}${panel(T.pNews, nwList, seeAll('news'))}${panel(T.pUrl, uhList, seeAll('urlhaus'))}</div>`;
    }
  };

  // ── CVE ────────────────────────────────────────────────────────────────
  const epss = new Map();
  const epssTxt = id => { const v = epss.get(id); return v == null ? '…' : isNaN(v) ? '—' : (v * 100).toFixed(v < 0.01 ? 2 : 1) + ' %'; };
  function cveMetric(c) {
    const m = c.metrics || {};
    for (const k of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']) {
      if (m[k] && m[k].length) {
        const e = m[k].find(x => x.type === 'Primary') || m[k][0];
        return { score: e.cvssData.baseScore, sev: String(e.cvssData.baseSeverity || e.baseSeverity || '').toUpperCase() };
      }
    }
    return { score: null, sev: '' };
  }
  function nvdItem(v) {
    const c = v.cve, m = cveMetric(c);
    const desc = ((c.descriptions || []).find(x => x.lang === 'en') || {}).value || '';
    const cwe = ((c.weaknesses || []).flatMap(w => w.description || []).find(x => /^CWE-/.test(x.value)) || {}).value || '';
    return { id: c.id, pub: c.published.slice(0, 19) + 'Z', score: m.score, sev: m.sev, cwe, desc: desc.length > 260 ? desc.slice(0, 259) + '…' : desc };
  }
  async function nvdSearch(q) {
    const base = 'https://services.nvd.nist.gov/rest/json/cves/2.0?';
    const p = /^CVE-\d{4}-\d{4,}$/i.test(q) ? 'cveId=' + encodeURIComponent(q.toUpperCase()) : 'keywordSearch=' + encodeURIComponent(q);
    const first = await TW.fetchJSON(base + p + '&resultsPerPage=1', { timeout: 45000 });
    const total = first.totalResults;
    const per = 100, start = Math.max(0, total - per);
    const page = total <= 1 ? first : await TW.fetchJSON(`${base}${p}&resultsPerPage=${per}&startIndex=${start}`, { timeout: 45000 });
    return { total, items: page.vulnerabilities.map(nvdItem).sort((a, b) => b.pub.localeCompare(a.pub)) };
  }
  function cveRows() {
    const s = st.cve, ks = kevSet(), q = s.q.toLowerCase();
    const src = s.nvd ? s.nvd.items : ((TW.data.nvd && TW.data.nvd.items) || []);
    const since = s.range === '1' ? TW.daysAgo(1) : '';
    return src.filter(x => (s.nvd || !since || x.pub >= since)
      && (s.sev === 'ALL' || sevKey(x.sev) === s.sev)
      && (!s.kev || ks.has(x.id))
      && has(q, x.id, x.desc, x.cwe));
  }
  async function loadEpss(ids) {
    const need = ids.filter(id => !epss.has(id)).slice(0, 100);
    if (!need.length) return;
    need.forEach(id => epss.set(id, null));
    try {
      const d = await TW.fetchJSON('https://api.first.org/data/v1/epss?cve=' + need.join(','), { timeout: 20000 });
      for (const r of d.data || []) epss.set(r.cve, parseFloat(r.epss));
      need.forEach(id => { if (epss.get(id) == null) epss.set(id, NaN); }); // CVE demasiado nuevo para EPSS
    } catch (e) { need.forEach(id => epss.delete(id)); }
    document.querySelectorAll('[data-epss]').forEach(el => {
      if (epss.get(el.dataset.epss) != null) el.textContent = epssTxt(el.dataset.epss);
    });
  }
  const cveView = {
    html() {
      const T = t(), s = st.cve, nvd = TW.data.nvd;
      if (!nvd && !s.nvd) return intro(T.cveIntro) + unavailable();
      const seg = (name, opts, cur) => `<span class="seg" data-seg="${name}">${opts.map(([v, l]) => `<button type="button" data-v="${v}" class="${v === cur ? 'on' : ''}">${esc(l)}</button>`).join('')}</span>`;
      const side = nvd ? `<div class="grid g2">
          ${panel(T.sev30, TW.bars(SEVS.map(k => [k, nvd.bySev[k] || 0]), { cls: k => k, label: k => T.sevNames[k] }), updated('nvd'))}
          ${panel(T.cwe30, TW.bars(nvd.cwes.slice(0, 10), { html: k => `<a href="https://cwe.mitre.org/data/definitions/${esc(k.slice(4))}.html" target="_blank" rel="noopener">${esc(k)}</a>` }))}
        </div>` : '';
      return intro(T.cveIntro) + side + `<section class="panel">
        <div class="toolbar">
          <input class="input grow" id="nvdQ" type="search" placeholder="${esc(T.nvdSearchPh)}" value="${esc(s.nvdQ)}" autocomplete="off" spellcheck="false">
          <button class="btn" type="button" id="nvdGo">${esc(T.nvdSearch)}</button>
          ${s.nvd ? `<button class="chip" type="button" id="nvdBack">${esc(T.backToRecent)}</button>` : ''}
        </div>
        <div class="toolbar">
          ${s.nvd ? '' : seg('range', [['1', T.range24], ['7', T.range7]], s.range)}
          ${seg('sev', [['ALL', T.all], ...SEVS.slice(0, 4).map(k => [k, T.sevNames[k]])], s.sev)}
          <label class="check"><input type="checkbox" id="cveKev" ${s.kev ? 'checked' : ''}> ${esc(T.onlyKev)}</label>
          <input class="input grow" id="cveQ" type="search" placeholder="${esc(T.filterPh)}" value="${esc(s.q)}" autocomplete="off" spellcheck="false">
        </div>
        <p class="hint" id="cveMsg">${esc(s.msg)}</p>
        <div id="cveOut"></div>
        <p class="hint">${esc(T.epssHint)}</p>
      </section>`;
    },
    fill() {
      const T = t(), s = st.cve, rows = cveRows(), ks = kevSet(), shown = rows.slice(0, s.limit);
      const out = $('cveOut');
      if (!out) return;
      out.innerHTML = `<p class="hint">${esc(T.results(num(rows.length)))}</p>` + table(
        [T.thCve, T.thScore, T.thSev, T.thDesc, T.thCwe, T.thPub, T.thEpss],
        shown.map(x => `<tr><td class="nw">${nvdLink(x.id)}${ks.has(x.id) ? ' <span class="tag kev">KEV</span>' : ''}</td>
          <td class="n mono">${x.score != null ? esc(x.score) : '—'}</td><td>${sevTag(x.sev)}</td>
          <td class="desc">${esc(x.desc)}</td><td class="mono nw">${esc(x.cwe || '—')}</td>
          <td class="mono nw">${esc(TW.dateTime(x.pub))}</td><td class="mono n" data-epss="${esc(x.id)}">${epssTxt(x.id)}</td></tr>`)
      ) + moreBtn(shown.length, rows.length, 'cveMore');
      const more = $('cveMore');
      if (more) more.onclick = () => { s.limit += 100; cveView.fill(); };
      loadEpss(shown.map(x => x.id));
    },
    after() {
      const s = st.cve;
      if (!$('cveOut')) return; // sin datos todavía
      document.querySelectorAll('[data-seg]').forEach(g => g.addEventListener('click', e => {
        const b = e.target.closest('button'); if (!b) return;
        s[g.dataset.seg] = b.dataset.v; s.limit = 100;
        g.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
        cveView.fill();
      }));
      $('cveKev').onchange = e => { s.kev = e.target.checked; s.limit = 100; cveView.fill(); };
      $('cveQ').oninput = e => { s.q = e.target.value; s.limit = 100; cveView.fill(); };
      const go = async () => {
        const q = $('nvdQ').value.trim();
        if (!q) return;
        s.nvdQ = q; $('nvdGo').disabled = true; $('cveMsg').textContent = t().nvdSearching;
        try {
          const r = await nvdSearch(q);
          s.nvd = r; s.limit = 100; s.msg = t().nvdResults(num(r.items.length), num(r.total));
        } catch (e) { s.msg = t().nvdErr; }
        TW.render();
      };
      $('nvdGo').onclick = go;
      $('nvdQ').onkeydown = e => { if (e.key === 'Enter') go(); };
      if ($('nvdBack')) $('nvdBack').onclick = () => { s.nvd = null; s.nvdQ = ''; s.msg = ''; s.limit = 100; TW.render(); };
      cveView.fill();
    }
  };

  // ── KEV ────────────────────────────────────────────────────────────────
  const kevView = {
    html() {
      const T = t(), kev = TW.data.kev;
      if (!kev) return intro(T.kevIntro) + unavailable();
      const since30 = TW.daysAgo(30).slice(0, 10);
      return intro(T.kevIntro) + `<div class="kpis">
          ${kpi(T.kTotal, num(kev.count), 'CISA · ' + (kev.catalogVersion || ''), 'c')}
          ${kpi(T.k30, num(kev.items.filter(x => x.added >= since30).length), '')}
          ${kpi(T.kRwUse, num(kev.items.filter(x => x.ransomware).length), '', 'h')}
        </div>
        <div class="grid g2">
          ${panel(T.topVendors, TW.bars(TW.count(kev.items, x => x.vendor).slice(0, 10)), updated('kev'))}
          ${panel(T.pKevLatest + ' · 30 d', TW.bars(TW.count(kev.items.filter(x => x.added >= since30), x => x.vendor).slice(0, 10)))}
        </div>
        <section class="panel">
          <div class="toolbar">
            <input class="input grow" id="kevQ" type="search" placeholder="${esc(T.kevFilterPh)}" value="${esc(st.kev.q)}" autocomplete="off" spellcheck="false">
            <label class="check"><input type="checkbox" id="kevRw" ${st.kev.rw ? 'checked' : ''}> ${esc(T.onlyRw)}</label>
          </div>
          <div id="kevOut"></div>
        </section>`;
    },
    fill() {
      const T = t(), s = st.kev, q = s.q.toLowerCase();
      const rows = TW.data.kev.items.filter(x => (!s.rw || x.ransomware) && has(q, x.id, x.vendor, x.product, x.name, x.desc));
      const shown = rows.slice(0, s.limit);
      $('kevOut').innerHTML = `<p class="hint">${esc(T.results(num(rows.length)))}</p>` + table(
        [T.thCve, T.thVendor, T.thProduct, T.thName, T.thAdded, T.thDue],
        shown.map(x => `<tr><td class="nw">${nvdLink(x.id)}${x.ransomware ? ' <span class="tag rw">ransomware</span>' : ''}</td>
          <td>${esc(x.vendor)}</td><td>${esc(x.product)}</td>
          <td class="desc"><b style="color:var(--text)">${esc(x.name)}</b><br>${esc(x.desc)}</td>
          <td class="mono nw">${esc(TW.date(x.added))}</td><td class="mono nw">${esc(TW.date(x.due))}</td></tr>`)
      ) + moreBtn(shown.length, rows.length, 'kevMore');
      if ($('kevMore')) $('kevMore').onclick = () => { s.limit += 100; kevView.fill(); };
    },
    after() {
      if (!TW.data.kev) return;
      $('kevQ').oninput = e => { st.kev.q = e.target.value; st.kev.limit = 100; kevView.fill(); };
      $('kevRw').onchange = e => { st.kev.rw = e.target.checked; st.kev.limit = 100; kevView.fill(); };
      kevView.fill();
    }
  };

  // ── Certificados SSL (crt.sh, en directo) ─────────────────────────────
  const shortCA = s => { const m = /O=("?)([^,"]+)\1/.exec(s || '') || /CN=([^,]+)/.exec(s || ''); return m ? (m[2] || m[1]).trim() : (s || '—'); };
  function cleanDomain(v) {
    let d = String(v || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/?#:].*$/, '').replace(/^(%|\*)\./, '');
    return /^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d) && d.length <= 253 ? d : null;
  }
  async function sslSearch() {
    const s = st.ssl, T = t();
    const d = cleanDomain($('sslQ').value);
    if (!d) { s.msg = T.sslBad; $('sslMsg').textContent = s.msg; return; }
    s.domain = d; s.busy = true; s.res = null; s.msg = T.sslSearching; s.filter = 'all'; s.limit = 200;
    TW.render();
    try {
      const q = (s.sub ? '%.' : '') + d;
      const data = await TW.fetchJSON(`https://crt.sh/?q=${encodeURIComponent(q)}&output=json${s.expired ? '' : '&exclude=expired'}&deduplicate=Y`, { timeout: 90000 });
      const certs = data.map(c => ({ id: c.id, ca: shortCA(c.issuer_name), names: [...new Set(String(c.name_value || c.common_name || '').toLowerCase().split('\n').filter(Boolean))], from: c.not_before, to: c.not_after }));
      certs.sort((a, b) => b.from.localeCompare(a.from));
      s.res = certs; s.msg = '';
    } catch (e) { s.msg = T.sslErr; }
    s.busy = false;
    TW.render();
  }
  const sslView = {
    html() {
      const T = t(), s = st.ssl;
      const ex = ['unfantasmaenelsistema.com', 'incibe.es', 'hackthebox.com', 'tryhackme.com'];
      let res = '';
      if (s.res) {
        const week = TW.daysAgo(7);
        const names = new Set();
        s.res.forEach(c => c.names.forEach(n => { const h = n.replace(/^\*\./, ''); if (h === s.domain || h.endsWith('.' + s.domain)) names.add(n); }));
        res = `<div class="kpis">
            ${kpi(T.sCerts, num(s.res.length), s.domain)}
            ${kpi(T.sWild, num(s.res.filter(c => c.names.some(n => n.startsWith('*.'))).length), '')}
            ${kpi(T.sNew, num(s.res.filter(c => c.from >= week.slice(0, 19)).length), '', 'g')}
            ${kpi(T.sCas, num(new Set(s.res.map(c => c.ca)).size), '')}
          </div>
          <div class="grid g2">
            ${panel(T.topCas, TW.bars(TW.count(s.res, c => c.ca).slice(0, 8)))}
            ${panel(T.subdomains(num(names.size)), `<div class="pills">${[...names].sort().slice(0, 600).map(n => `<span class="tag mono">${esc(n)}</span>`).join('')}</div>`)}
          </div>
          <section class="panel">
            <div class="toolbar"><span class="seg" id="sslF">${[['all', T.fAll], ['wild', T.fWild], ['new', T.fNew], ['le', T.fLe], ['valid', T.fValid]].map(([v, l]) => `<button type="button" data-v="${v}" class="${s.filter === v ? 'on' : ''}">${esc(l)}</button>`).join('')}</span></div>
            <div id="sslOut"></div>
          </section>`;
      }
      return intro(T.sslIntro) + `<section class="panel">
          <div class="toolbar">
            <input class="input grow" id="sslQ" type="search" placeholder="${esc(T.sslPh)}" value="${esc(s.domain)}" autocomplete="off" spellcheck="false" autocapitalize="off">
            <label class="check"><input type="checkbox" id="sslSub" ${s.sub ? 'checked' : ''}> ${esc(T.sslSub)}</label>
            <label class="check"><input type="checkbox" id="sslExp" ${s.expired ? 'checked' : ''}> ${esc(T.sslExpired)}</label>
            <button class="btn" type="button" id="sslGo" ${s.busy ? 'disabled' : ''}>${esc(T.sslSearch)}</button>
          </div>
          <div class="toolbar"><span class="hint" style="margin:0">${esc(T.sslExamples)}</span>${ex.map(d => `<button class="chip" type="button" data-ex="${esc(d)}">${esc(d)}</button>`).join('')}</div>
          <p class="hint ${s.msg && !s.busy ? 'err' : ''}" id="sslMsg">${esc(s.msg)}</p>
        </section>` + res;
    },
    fill() {
      const T = t(), s = st.ssl, now = new Date().toISOString().slice(0, 19), week = TW.daysAgo(7).slice(0, 19);
      const f = { all: () => true, wild: c => c.names.some(n => n.startsWith('*.')), new: c => c.from >= week, le: c => /let's encrypt/i.test(c.ca), valid: c => c.to >= now }[s.filter];
      const rows = s.res.filter(f), shown = rows.slice(0, s.limit);
      $('sslOut').innerHTML = `<p class="hint">${esc(T.results(num(rows.length)))}</p>` + table(
        [T.thNames, T.thCa, T.thFrom, T.thTo, T.thState, 'crt.sh'],
        shown.map(c => `<tr><td class="mono break">${c.names.slice(0, 6).map(esc).join('<br>')}${c.names.length > 6 ? `<br>+${c.names.length - 6}` : ''}</td>
          <td>${esc(c.ca)}</td><td class="mono nw">${esc(TW.date(c.from))}</td><td class="mono nw">${esc(TW.date(c.to))}</td>
          <td>${c.to >= now ? `<span class="tag" style="color:var(--ok);border-color:var(--ok)">${esc(T.valid)}</span>` : `<span class="tag off">${esc(T.expired)}</span>`}</td>
          <td><a class="mono" href="https://crt.sh/?id=${encodeURIComponent(c.id)}" target="_blank" rel="noopener">#${esc(c.id)}</a></td></tr>`)
      ) + moreBtn(shown.length, rows.length, 'sslMore');
      if ($('sslMore')) $('sslMore').onclick = () => { s.limit += 200; sslView.fill(); };
    },
    after() {
      const s = st.ssl;
      $('sslGo').onclick = sslSearch;
      $('sslQ').onkeydown = e => { if (e.key === 'Enter') sslSearch(); };
      $('sslSub').onchange = e => { s.sub = e.target.checked; };
      $('sslExp').onchange = e => { s.expired = e.target.checked; };
      document.querySelectorAll('[data-ex]').forEach(b => b.onclick = () => { $('sslQ').value = b.dataset.ex; sslSearch(); });
      if (s.res) {
        $('sslF').onclick = e => {
          const b = e.target.closest('button'); if (!b) return;
          s.filter = b.dataset.v; s.limit = 200;
          $('sslF').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
          sslView.fill();
        };
        sslView.fill();
      }
    }
  };

  // ── URLhaus ────────────────────────────────────────────────────────────
  const uhTime = s => s.replace(' ', 'T') + 'Z';
  const uhView = {
    html() {
      const T = t(), uh = TW.data.urlhaus;
      if (!uh) return intro(T.uhIntro) + unavailable();
      const top = Object.entries(uh.threats)[0] || ['—', 0];
      return intro(T.uhIntro) + `<div class="kpis">
          ${kpi(T.uTotal, num(uh.total), '')}
          ${kpi(T.uOnline, num(uh.online), (uh.online / Math.max(uh.total, 1) * 100).toFixed(1) + ' %', 'c')}
          ${kpi(T.uIp, (uh.ipShare * 100).toFixed(0) + ' %', '')}
          ${kpi(T.uTop, esc(top[0]), num(top[1]), 'h')}
        </div>
        <div class="grid g2">
          ${panel(T.uDay, TW.stacked(Object.entries(uh.byDay).map(([d, n]) => [d, { n }]), [['n', 'var(--accent)']]), updated('urlhaus'))}
          ${panel(T.uTags, TW.bars(uh.tags.slice(0, 12)))}
        </div>
        ${panel(T.uHosts, TW.bars(uh.hosts.slice(0, 10), { label: k => TW.defang(k) }))}
        <section class="panel">
          <h2><span>${esc(T.uLatest(num(uh.latest.length)))}</span></h2>
          <div class="toolbar">
            <input class="input grow" id="uhQ" type="search" placeholder="${esc(T.uFilterPh)}" value="${esc(st.uh.q)}" autocomplete="off" spellcheck="false">
            <label class="check"><input type="checkbox" id="uhOn" ${st.uh.online ? 'checked' : ''}> ${esc(T.uOnlineOnly)}</label>
          </div>
          <div id="uhOut"></div>
        </section>`;
    },
    fill() {
      const T = t(), s = st.uh, q = s.q.toLowerCase();
      const rows = TW.data.urlhaus.latest.filter(x => (!s.online || x.status === 'online') && has(q, x.url, x.tags.join(' '), x.reporter, x.threat));
      const shown = rows.slice(0, s.limit);
      $('uhOut').innerHTML = `<p class="hint">${esc(T.results(num(rows.length)))}</p>` + table(
        [T.thAdded2, T.thUrl, T.thStatus, T.thThreat, T.thTags, T.thReporter, 'URLhaus'],
        shown.map(x => {
          const link = safeLink(x.link, 'https://urlhaus.abuse.ch/');
          return `<tr><td class="mono nw">${esc(TW.dateTime(uhTime(x.added)))}</td><td class="mono break">${esc(TW.defang(x.url))}</td>
          <td>${x.status === 'online' ? `<span class="tag on">${esc(T.online)}</span>` : `<span class="tag off">${esc(T.offline)}</span>`}</td>
          <td class="mono">${esc(x.threat)}</td><td>${x.tags.map(g => `<span class="tag">${esc(g)}</span>`).join('')}</td>
          <td class="mono">${esc(x.reporter)}</td><td>${link ? `<a class="mono" href="${esc(link)}" target="_blank" rel="noopener">#${esc(x.id)}</a>` : ''}</td></tr>`;
        })
      ) + moreBtn(shown.length, rows.length, 'uhMore');
      if ($('uhMore')) $('uhMore').onclick = () => { s.limit += 100; uhView.fill(); };
    },
    after() {
      if (!TW.data.urlhaus) return;
      $('uhQ').oninput = e => { st.uh.q = e.target.value; st.uh.limit = 100; uhView.fill(); };
      $('uhOn').onchange = e => { st.uh.online = e.target.checked; st.uh.limit = 100; uhView.fill(); };
      uhView.fill();
    }
  };

  // ── Feodo Tracker ──────────────────────────────────────────────────────
  const feodoView = {
    html() {
      const T = t(), fd = TW.data.feodo;
      if (!fd) return intro(T.fdIntro) + unavailable();
      const items = fd.items;
      return intro(T.fdIntro) + `<div class="kpis">
          ${kpi(T.fTotal, num(fd.count), '')}
          ${kpi(T.fOnline, num(items.filter(x => x.status === 'online').length), '', 'c')}
          ${kpi(T.fFam, num(new Set(items.map(x => x.malware)).size), '')}
          ${kpi(T.fCountries, num(new Set(items.map(x => x.country)).size), '')}
        </div>
        ${fd.count < 50 ? `<p class="note">${esc(T.fdNote)}</p>` : ''}
        <div class="grid g2">
          ${panel(T.fByMal, TW.bars(TW.count(items, x => x.malware)), updated('feodo'))}
          ${panel(T.fByCountry, TW.bars(TW.count(items, x => x.country), { html: k => TW.flag(k) }))}
        </div>
        <section class="panel">${table(
          [T.thIp, T.thPort, T.thStatus, T.thMalware, T.thCountry, T.thAs, T.thFirst, T.thLast, T.thList],
          items.map(x => `<tr><td class="mono nw">${esc(x.ip_address)}</td><td class="mono n">${esc(x.port)}</td>
            <td>${x.status === 'online' ? `<span class="tag on">${esc(T.online)}</span>` : `<span class="tag off">${esc(T.offline)}</span>`}</td>
            <td>${esc(x.malware)}</td><td class="nw">${TW.flag(x.country)}</td>
            <td class="mono">AS${esc(x.as_number)} ${esc(x.as_name)}</td><td class="mono nw">${esc(TW.date((x.first_seen || '').slice(0, 10)))}</td>
            <td class="mono nw">${esc(TW.date(x.last_online))}</td><td>${esc(x.list === 'recommended' ? T.recommended : T.blocklist)}</td></tr>`))}
        </section>`;
    }
  };

  // ── Ransomware ─────────────────────────────────────────────────────────
  const rwView = {
    html() {
      const T = t(), rw = TW.data.ransomware;
      if (!rw) return intro(T.rwIntro) + unavailable();
      const first = rw.items[rw.items.length - 1], last = rw.items[0];
      return intro(T.rwIntro) + `<div class="kpis">
          ${kpi(T.rVictims, num(rw.count), '', 'c')}
          ${kpi(T.rGroups, num(new Set(rw.items.map(x => x.group)).size), '')}
          ${kpi(T.rCountries, num(new Set(rw.items.map(x => x.country).filter(Boolean)).size), '')}
          ${kpi(T.rRange, esc(TW.date(first.discovered)), '→ ' + TW.date(last.discovered), 'h')}
        </div>
        <div class="grid g3">
          ${panel(T.rByGroup, TW.bars(rw.groups.slice(0, 10)), updated('ransomware'))}
          ${panel(T.rBySector, TW.bars(rw.sectors.slice(0, 10)))}
          ${panel(T.rByCountry, TW.bars(rw.countries.slice(0, 10), { html: k => TW.flag(k) }))}
        </div>
        <section class="panel">
          <div class="toolbar"><input class="input grow" id="rwQ" type="search" placeholder="${esc(T.rFilterPh)}" value="${esc(st.rw.q)}" autocomplete="off" spellcheck="false"></div>
          <div id="rwOut"></div>
        </section>`;
    },
    fill() {
      const T = t(), q = st.rw.q.toLowerCase();
      const rows = TW.data.ransomware.items.filter(x => has(q, x.victim, x.domain, x.group, x.sector, x.country));
      $('rwOut').innerHTML = `<p class="hint">${esc(T.results(num(rows.length)))}</p>` + table(
        [T.thVictim, T.thGroup, T.thSector, T.thCountry, T.thDisc, T.thMore],
        rows.map(x => {
          const page = safeLink(x.page, 'https://www.ransomware.live/');
          return `<tr><td><b>${esc(x.victim)}</b>${x.domain && x.domain.toLowerCase() !== x.victim.toLowerCase() ? `<br><span class="mono" style="color:var(--muted)">${esc(x.domain)}</span>` : ''}</td>
          <td class="mono">${esc(x.group)}</td><td>${x.sector && x.sector !== 'Not Found' ? esc(x.sector) : '—'}</td>
          <td class="nw">${TW.flag(x.country)}</td><td class="mono nw">${esc(TW.dateTime(x.discovered))}</td>
          <td>${page ? `<a href="${esc(page)}" target="_blank" rel="noopener">ransomware.live</a>` : ''}</td></tr>`;
        }));
    },
    after() {
      if (!TW.data.ransomware) return;
      $('rwQ').oninput = e => { st.rw.q = e.target.value; rwView.fill(); };
      rwView.fill();
    }
  };

  // ── Noticias ───────────────────────────────────────────────────────────
  const newsView = {
    html() {
      const T = t(), nw = TW.data.news, s = st.news;
      if (!nw) return intro(T.nwIntro) + unavailable();
      const sources = [...new Set(nw.items.map(x => x.source))];
      const items = nw.items.filter(x => (s.lang === 'all' || x.lang === s.lang) && (s.src === 'all' || x.source === s.src));
      return intro(T.nwIntro) + `<section class="panel">
          <div class="toolbar">
            <span class="seg" id="nwLang">${[['all', T.nwAll], ['es', T.nwEs], ['en', T.nwEn]].map(([v, l]) => `<button type="button" data-v="${v}" class="${s.lang === v ? 'on' : ''}">${esc(l)}</button>`).join('')}</span>
            <select class="input" id="nwSrc"><option value="all">${esc(T.nwAll)}</option>${sources.map(x => `<option ${s.src === x ? 'selected' : ''}>${esc(x)}</option>`).join('')}</select>
            ${updated('news')}
          </div>
          <div class="list">${items.map(x => `<div class="it">
            <a href="${esc(x.link)}" target="_blank" rel="noopener">${esc(x.title)}</a>
            <span class="meta">${esc(x.source)} · ${esc(TW.dateTime(x.date))} · ${esc(TW.ago(x.date))}</span></div>`).join('') || `<p class="empty">${esc(T.noData)}</p>`}</div>
        </section>`;
    },
    after() {
      if (!TW.data.news) return;
      $('nwLang').onclick = e => { const b = e.target.closest('button'); if (b) { st.news.lang = b.dataset.v; TW.render(); } };
      $('nwSrc').onchange = e => { st.news.src = e.target.value; TW.render(); };
    }
  };

  TW.views = { panel: panelView, cve: cveView, kev: kevView, ssl: sslView, urlhaus: uhView, feodo: feodoView, ransomware: rwView, news: newsView };
  TW.start();
})();
