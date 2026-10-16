(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  };

  // Los datos los genera la Action en la rama `data`. En local (python -m
  // http.server) se leen de ./data/, que crea scripts/fetch_feeds.py.
  const LOCAL = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname);
  const DATA = new URLSearchParams(location.search).get('data') === 'raw' || !LOCAL
    ? 'https://raw.githubusercontent.com/unfantasmaenelsistema/ThreatWatch/data/'
    : 'data/';
  const FEEDS = ['kev', 'nvd', 'urlhaus', 'feodo', 'ransomware', 'news'];

  TW.lang = store.get('tw_lang') || ((navigator.language || 'es').toLowerCase().startsWith('es') ? 'es' : 'en');
  TW.t = () => TW.TXT[TW.lang];
  TW.data = {};
  TW.status = null;
  TW.$ = $;
  TW.store = store;

  // ── Utilidades ─────────────────────────────────────────────────────────
  TW.esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  TW.loc = () => (TW.lang === 'es' ? 'es-ES' : 'en-GB');
  TW.num = n => (n == null || isNaN(n) ? '—' : Number(n).toLocaleString(TW.loc()));
  TW.date = s => {
    if (!s) return '—';
    const d = new Date(s.length <= 10 ? s + 'T00:00:00Z' : s);
    return isNaN(d) ? s : d.toLocaleDateString(TW.loc(), { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' });
  };
  TW.dateTime = s => {
    const d = new Date(s);
    return isNaN(d) ? (s || '—') : d.toLocaleString(TW.loc(), { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
  };
  TW.ago = s => {
    const d = new Date(s);
    if (isNaN(d)) return '—';
    const sec = (d - Date.now()) / 1000;
    if (Math.abs(sec) < 60) return TW.t().dur.now;
    const rtf = new Intl.RelativeTimeFormat(TW.lang, { numeric: 'auto' });
    for (const [u, n] of [['day', 86400], ['hour', 3600], ['minute', 60]]) {
      if (Math.abs(sec) >= n) return rtf.format(Math.round(sec / n), u);
    }
    return TW.t().dur.now;
  };
  TW.daysAgo = n => new Date(Date.now() - n * 86400000).toISOString();
  // Desactiva una URL maliciosa para que no se pueda abrir con un clic.
  TW.defang = u => String(u).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  // Código de país con el nombre al pasar el ratón (Windows no dibuja los emojis de bandera).
  TW.flag = cc => {
    if (!/^[A-Z]{2}$/.test(cc || '')) return TW.esc(cc || '—');
    let name = cc;
    try { name = new Intl.DisplayNames([TW.lang], { type: 'region' }).of(cc); } catch (e) {}
    return `<abbr title="${TW.esc(name)}" class="mono">${cc}</abbr>`;
  };
  TW.count = (arr, fn) => {
    const m = new Map();
    for (const x of arr) { const k = fn(x); if (k) m.set(k, (m.get(k) || 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };

  // Barras horizontales a partir de pares [etiqueta, valor].
  TW.bars = (pairs, opts = {}) => {
    if (!pairs || !pairs.length) return `<p class="empty">${TW.t().noData}</p>`;
    const max = Math.max(...pairs.map(p => p[1]), 1);
    return `<div class="bars">${pairs.map(([k, v]) => `<div class="bar ${opts.cls ? TW.esc(opts.cls(k)) : ''}">
      <span class="lbl" title="${TW.esc(opts.label ? opts.label(k) : k)}">${opts.html ? opts.html(k) : TW.esc(opts.label ? opts.label(k) : k)}</span>
      <span class="trk"><i style="width:${(v / max * 100).toFixed(1)}%"></i></span>
      <span class="val">${TW.num(v)}</span></div>`).join('')}</div>`;
  };

  // Columnas apiladas por día: days = [[fecha, {serie: n}]], series = [[clave, color css]].
  TW.stacked = (days, series) => {
    if (!days.length) return `<p class="empty">${TW.t().noData}</p>`;
    const W = 720, H = 180, pad = 22, bw = (W - pad) / days.length;
    const tot = days.map(([, o]) => series.reduce((s, [k]) => s + (o[k] || 0), 0));
    const max = Math.max(...tot, 1);
    let out = '';
    days.forEach(([d, o], i) => {
      let y = H - 16;
      const x = pad + i * bw + 1;
      for (const [k, col] of series) {
        const h = (o[k] || 0) / max * (H - 30);
        if (h > 0) { y -= h; out += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(bw - 2, 1).toFixed(1)}" height="${h.toFixed(1)}" fill="${col}"><title>${TW.esc(d)} · ${k}: ${o[k]}</title></rect>`; }
      }
      if (i % Math.ceil(days.length / 8) === 0) out += `<text class="axis" x="${x.toFixed(1)}" y="${H - 3}">${TW.esc(d.slice(5))}</text>`;
    });
    out += `<text class="axis" x="0" y="12">${TW.num(max)}</text>`;
    return `<div class="chart"><svg viewBox="0 0 ${W} ${H}" role="img">${out}</svg></div>`;
  };

  TW.fetchJSON = async (url, opts = {}) => {
    const res = await fetch(url, Object.assign({ signal: AbortSignal.timeout(opts.timeout || 30000) }, opts));
    if (!res.ok) throw new Error('HTTP ' + res.status);
    return res.json();
  };

  // ── Carga de datos ─────────────────────────────────────────────────────
  async function loadAll() {
    const v = Math.floor(Date.now() / 600000); // la caché del navegador dura como mucho 10 min
    const [status, ...rest] = await Promise.allSettled(['status', ...FEEDS].map(f => TW.fetchJSON(`${DATA}${f}.json?v=${v}`)));
    TW.status = status.status === 'fulfilled' ? status.value : null;
    FEEDS.forEach((f, i) => { if (rest[i].status === 'fulfilled') TW.data[f] = rest[i].value; });
    renderStatus();
    TW.render();
  }

  function renderStatus() {
    const bar = $('statusbar'), t = TW.t();
    if (!TW.status && !Object.keys(TW.data).length) {
      bar.className = 'statusbar err'; $('statusText').textContent = t.statusErr; $('feedDots').innerHTML = ''; return;
    }
    const upd = TW.status ? TW.status.updated : null;
    const stale = upd && Date.now() - new Date(upd) > 3 * 3600000;
    bar.className = 'statusbar ' + (stale ? 'err' : 'ok');
    $('statusText').textContent = upd ? (stale ? t.statusStale(TW.ago(upd)) : t.status(TW.ago(upd))) : '';
    $('feedDots').innerHTML = FEEDS.map(f => {
      const s = TW.status && TW.status.feeds[f];
      const ok = s && s.ok && TW.data[f];
      const title = ok ? t.updatedAt(TW.dateTime(s.updated)) : (TW.data[f] ? t.feedErr : t.unavailable);
      return `<span title="${TW.esc(title)}"><i class="dot ${ok ? 'ok' : 'bad'}"></i>${TW.esc(t.feedNames[f])}</span>`;
    }).join('');
  }

  // ── Pestañas ───────────────────────────────────────────────────────────
  const TABS = ['panel', 'cve', 'kev', 'ssl', 'urlhaus', 'feodo', 'ransomware', 'news'];
  TW.tab = () => { const h = location.hash.slice(1); return TABS.includes(h) ? h : 'panel'; };
  TW.render = () => {
    const tab = TW.tab();
    document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-selected', b.dataset.tab === tab));
    const view = TW.views && TW.views[tab];
    if (!view) return;
    // Un fallo al pintar una pestaña no debe impedir que carguen los datos.
    try { $('view').innerHTML = view.html(); if (view.after) view.after(); } catch (e) { console.error(e); }
  };
  $('tabs').addEventListener('click', e => {
    const b = e.target.closest('button[data-tab]');
    if (b) location.hash = b.dataset.tab;
  });
  window.addEventListener('hashchange', () => { TW.render(); window.scrollTo({ top: 0 }); });

  // ── Idioma y tema ──────────────────────────────────────────────────────
  function applyTheme(th) {
    document.documentElement.setAttribute('data-theme', th);
    $('themeBtn').textContent = th === 'light' ? TW.t().themeDark : TW.t().themeLight;
  }
  function applyLang() {
    const t = TW.t();
    document.documentElement.lang = TW.lang;
    document.querySelectorAll('[data-t]').forEach(el => { const v = t[el.dataset.t]; if (typeof v === 'string') el.textContent = v; });
    $('langBtn').textContent = t.lang;
    applyTheme(document.documentElement.getAttribute('data-theme'));
    if (TW.status || Object.keys(TW.data).length) renderStatus();
  }
  $('langBtn').addEventListener('click', () => {
    TW.lang = TW.lang === 'es' ? 'en' : 'es'; store.set('tw_lang', TW.lang);
    applyLang(); TW.render();
  });
  $('themeBtn').addEventListener('click', () => {
    const th = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    store.set('tw_theme', th); applyTheme(th);
  });

  TW.start = () => {
    applyLang();
    TW.render();
    loadAll().catch(() => renderStatus());
    setInterval(() => { if (TW.status) renderStatus(); }, 60000);
  };
})();
