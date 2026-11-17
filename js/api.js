/* Datenquellen: NVD (CVE-Details), FIRST EPSS (Ausnutzungswahrscheinlichkeit), CISA KEV (aktiv ausgenutzt) */
(function () {
  'use strict';
  const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const NVD_CPE = 'https://services.nvd.nist.gov/rest/json/cpes/2.0';
  const EPSS = 'https://api.first.org/data/v1/epss';
  const KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';

  // NVD ohne API-Key: max. 5 Anfragen / 30 s
  const stamps = [];
  async function throttle(onWait) {
    for (;;) {
      const now = Date.now();
      while (stamps.length && now - stamps[0] > 31000) stamps.shift();
      if (stamps.length < 5) { stamps.push(now); return; }
      const wait = 31000 - (now - stamps[0]);
      onWait && onWait(Math.ceil(wait / 1000));
      await new Promise(r => setTimeout(r, Math.min(wait, 1000)));
    }
  }

  async function nvdGet(params, onWait, base) {
    const url = (base || NVD) + '?' + (typeof params === 'string' ? params : new URLSearchParams(params));
    for (let attempt = 0; attempt < 4; attempt++) {
      await throttle(onWait);
      let res;
      try { res = await fetch(url); } catch (e) { throw new Error('NVD nicht erreichbar (offline?)'); }
      if (res.ok) return res.json();
      if ([403, 429, 503].includes(res.status)) { await new Promise(r => setTimeout(r, 6000)); continue; }
      throw new Error('NVD-Fehler ' + res.status);
    }
    throw new Error('NVD überlastet – bitte später erneut versuchen');
  }

  function pickMetric(m) {
    if (!m) return null;
    for (const key of ['cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2']) {
      const arr = m[key];
      if (arr && arr.length) {
        const x = arr.find(a => a.type === 'Primary') || arr[0];
        return { score: x.cvssData.baseScore, vector: x.cvssData.vectorString, version: x.cvssData.version, severity: x.cvssData.baseSeverity || x.baseSeverity };
      }
    }
    return null;
  }

  function mapCve(cve) {
    const desc = (cve.descriptions || []).find(d => d.lang === 'en');
    const cwe = [...new Set((cve.weaknesses || []).flatMap(w => w.description.map(d => d.value)).filter(v => v.startsWith('CWE-')))];
    const refs = (cve.references || []).map(r => ({ url: r.url, tags: r.tags || [] }));
    return {
      cve: cve.id,
      description: desc ? desc.value : '',
      published: cve.published,
      cvss: pickMetric(cve.metrics),
      cwe,
      references: refs.slice(0, 15),
      patchAvailable: refs.some(r => r.tags.includes('Patch')),
      kev: !!cve.cisaExploitAdd
    };
  }

  async function getCve(id, onWait) {
    const data = await nvdGet({ cveId: id.trim().toUpperCase() }, onWait);
    const v = data.vulnerabilities && data.vulnerabilities[0];
    if (!v) throw new Error(id + ' nicht in der NVD gefunden');
    return mapCve(v.cve);
  }

  // Trennt an ":" – ein maskierter Doppelpunkt "\:" bleibt erhalten (ohne Lookbehind, wegen älterer iOS-Versionen)
  const cpeParts = cpe => String(cpe || '').replace(/\\:/g, '\u0000').split(':').map(s => s.replace(/\u0000/g, '\\:'));
  /** Versionsgenau prüfbar: gültige CPE mit konkreter Version (kein Platzhalter) */
  const isPrecise = cpe => { const p = cpeParts(cpe); return p[0] === 'cpe' && p.length >= 6 && !!p[5] && p[5] !== '*'; };

  const sortNewest = items => items.sort((a, b) => (b.published || '').localeCompare(a.published || ''));
  const MAX = 500;

  async function search(comp, onWait) {
    if (isPrecise(comp.cpe)) {
      // NVD prüft hier die Versionsbereiche der CVE – liefert nur, was diese Version wirklich betrifft
      const q = 'cpeName=' + encodeURIComponent(comp.cpe) + '&isVulnerable&resultsPerPage=' + MAX;
      let data = await nvdGet(q, onWait);
      const total = data.totalResults;
      if (total > MAX) data = await nvdGet(q + '&startIndex=' + (total - MAX), onWait); // die neuesten
      return { total, precise: true, items: sortNewest((data.vulnerabilities || []).map(v => Object.assign(mapCve(v.cve), { source: 'NVD' }))) };
    }
    let params;
    if (comp.cpe && comp.cpe.startsWith('cpe:2.3')) params = { virtualMatchString: comp.cpe, resultsPerPage: 100 };
    else params = { keywordSearch: [comp.vendor, comp.name].filter(Boolean).join(' '), resultsPerPage: 100 };
    const data = await nvdGet(params, onWait);
    return { total: data.totalResults, precise: false, items: sortNewest((data.vulnerabilities || []).map(v => Object.assign(mapCve(v.cve), { source: 'NVD' }))) };
  }

  /** Produktsuche im NVD-Produktverzeichnis (CPE Dictionary), gruppiert nach Produkt */
  async function products(keyword, onWait) {
    const data = await nvdGet({ keywordSearch: keyword.trim(), resultsPerPage: 2000 }, onWait, NVD_CPE);
    const groups = new Map();
    (data.products || []).forEach(x => {
      const c = x.cpe; if (!c || c.deprecated) return;
      const p = cpeParts(c.cpeName);
      const key = p.slice(2, 5).join(':');
      const ver = p[5], upd = p[6];
      let title = ((c.titles || []).find(t => t.lang === 'en') || {}).title || p[4].replace(/\\/g, '').replace(/_/g, ' ');
      const verLabel = [ver !== '-' && ver !== '*' ? ver : '', upd && upd !== '*' && upd !== '-' ? upd : ''].filter(Boolean).join(' ');
      if (ver && ver !== '-' && ver !== '*') { const i = title.toLowerCase().lastIndexOf(ver.toLowerCase()); if (i > 0) title = title.slice(0, i).trim(); }
      if (!groups.has(key)) groups.set(key, { key, part: p[2], vendor: p[3], product: p[4], title, versions: [] });
      const g = groups.get(key);
      if (title.length < g.title.length) g.title = title;
      if (verLabel && !g.versions.some(v => v.cpe === c.cpeName)) g.versions.push({ label: verLabel, cpe: c.cpeName });
    });
    const cmp = (a, b) => b.label.localeCompare(a.label, undefined, { numeric: true });
    let list = [...groups.values()];
    list.forEach(g => g.versions.sort(cmp));
    // Hardware-Einträge (h) sind für die CVE-Suche meist ungeeignet – nur zeigen, wenn es nichts anderes gibt
    if (list.some(g => g.part !== 'h')) list = list.filter(g => g.part !== 'h');
    const order = { o: 0, a: 1, h: 2 };
    list.sort((a, b) => order[a.part] - order[b.part] || b.versions.length - a.versions.length);
    return { total: data.totalResults, truncated: data.totalResults > (data.products || []).length, items: list };
  }

  /** CPE aus Produkt + frei eingegebener Version bauen */
  function buildCpe(productKey, version) {
    const v = String(version || '').trim().replace(/^v(?=\d)/i, '').toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9._\-]/g, '');
    return `cpe:2.3:${productKey}:${v || '*'}:*:*:*:*:*:*:*`;
  }

  async function epss(ids) {
    const out = {};
    for (let i = 0; i < ids.length; i += 80) {
      const chunk = ids.slice(i, i + 80);
      try {
        const r = await fetch(EPSS + '?cve=' + chunk.join(','));
        if (!r.ok) continue;
        const j = await r.json();
        (j.data || []).forEach(d => { out[d.cve] = { epss: parseFloat(d.epss), percentile: parseFloat(d.percentile) }; });
      } catch (e) { /* offline */ }
    }
    return out;
  }

  let kevCache = null;
  async function kev(force) {
    if (kevCache && !force) return kevCache;
    try {
      const raw = localStorage.getItem('otr.kev');
      if (raw && !force) {
        const c = JSON.parse(raw);
        if (Date.now() - c.at < 24 * 3600e3) { kevCache = c; return c; }
      }
    } catch (e) { /* ignore */ }
    const r = await fetch(KEV);
    if (!r.ok) throw new Error('KEV-Katalog nicht erreichbar');
    const j = await r.json();
    const map = {};
    (j.vulnerabilities || []).forEach(v => { map[v.cveID] = { added: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known', action: v.requiredAction }; });
    kevCache = { at: Date.now(), version: j.catalogVersion, map };
    try { localStorage.setItem('otr.kev', JSON.stringify(kevCache)); } catch (e) { /* Speicher voll */ }
    return kevCache;
  }

  window.Api = { getCve, search, products, buildCpe, isPrecise, cpeParts, epss, kev };
})();
