/* OT Risk Analysis – user interface & state (English edition).
 * Data lives in the browser (localStorage) and – when the app runs via the start file – additionally as a file on the PC.
 * Internal keys (component types, statuses, risk levels) stay German: both language editions share the same stored data. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => Math.random().toString(36).slice(2, 10);
  const fmtDate = d => d ? new Date(d).toLocaleDateString('en-GB') : '–';
  const pct = e => e >= 0.999 ? '> 99.9%' : (e * 100).toFixed(1) + '%';
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const plural = (n, one, many) => n === 1 ? one : (many || one + 's');
  const STORE = 'otr.state.v1';
  const COMP_TYPES = ['SPS', 'HMI', 'IPC', 'Betriebssystem', 'Firmware', 'Antrieb', 'Netzwerk', 'Bibliothek', 'Anwendung', 'Sonstiges'];
  const TYPE_LABEL = { SPS: 'PLC', HMI: 'HMI', IPC: 'IPC', Betriebssystem: 'Operating system', Firmware: 'Firmware', Antrieb: 'Drive', Netzwerk: 'Network', Bibliothek: 'Library', Anwendung: 'Application', Sonstiges: 'Other' };
  const typeLabel = t => TYPE_LABEL[t] || t || '';
  const STATUS = { offen: 'Open', umsetzung: 'In progress', mitigiert: 'Mitigated', akzeptiert: 'Risk accepted', nb: 'Not affected' };
  const LEVELS = [{ key: 'krit', label: 'Critical' }, { key: 'hoch', label: 'High' }, { key: 'mittel', label: 'Medium' }, { key: 'niedrig', label: 'Low' }];
  const PAGE = 100;

  const PRESETS = {
    isoliert: { label: 'Stand-alone machine without network', hint: 'Not connected to the company or production network, no remote maintenance', ctx: { exposure: 1, remoteAccess: false } },
    vernetzt: { label: 'Machine in the production network with remote maintenance', hint: 'The most common case: network/MES connection, service by remote access', ctx: { exposure: 3, remoteAccess: true } },
    cloud: { label: 'Machine with internet or cloud connection', hint: 'Data goes to a cloud or the machine is reachable from outside', ctx: { exposure: 4, remoteAccess: true } }
  };
  const defaultCtx = () => ({ exposure: 3, remoteAccess: true, physical: 2, safety: 2, availability: 3, confidentiality: 2, slT: 2, patchable: false, acceptance: 4 });

  let state = load();
  let ui = { tab: 'kontext', matrixMode: 'vorher', cell: null, filter: '', open: new Set(), limit: PAGE, job: null, scan: null, prodVersions: null };

  function load() {
    try { const s = JSON.parse(localStorage.getItem(STORE)); if (s && s.projects) return s; } catch (e) { /* empty */ }
    return { projects: [], currentId: null };
  }
  let saveT;
  function save() {
    state.savedAt = Date.now();
    try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { toast('Saving in the browser failed: ' + e.message); }
    if (Local.available) {
      clearTimeout(saveT);
      saveT = setTimeout(() => Local.saveData(JSON.stringify(state)).catch(() => toast('Saving to file failed – is the start window still open?')), 700);
    }
  }
  const project = () => state.projects.find(p => p.id === state.currentId);

  function newProject(name, machine, preset) {
    const ctx = Object.assign(defaultCtx(), (PRESETS[preset] || {}).ctx);
    const p = { id: uid(), name: name || 'New machine', machine: machine || '', customer: '', description: '', created: new Date().toISOString(), ctx, components: [], findings: [] };
    state.projects.push(p); state.currentId = p.id; save(); return p;
  }

  // ---------- Assessment ----------
  function compOf(p, f) { return p.components.find(c => c.id === f.componentId); }
  function evaluate(p, f) {
    const base = Risk.assess(f, p.ctx);
    const comp = compOf(p, f);
    const options = MITIGATIONS.map(m => ({ m, rel: m.applies(f, base.v, comp, p.ctx) })).filter(o => o.rel > 0)
      .sort((a, b) => b.rel - a.rel || (b.m.eliminates ? 1 : 0) - (a.m.eliminates ? 1 : 0));
    const r = recommend(p, f, base, options);
    const res = Risk.residual(f, p.ctx, base, f.mitigations || []);
    return {
      base, comp, options, res,
      rec: r.all, recNow: r.now, recLater: r.later, reach: r.reach,
      recRes: Risk.residual(f, p.ctx, base, r.all),       // after full implementation (incl. patch/replacement)
      recResNow: Risk.residual(f, p.ctx, base, r.now),    // after the immediate measures
      over: res.score > p.ctx.acceptance
    };
  }

  /** Smallest combination of measures until residual risk ≤ acceptance threshold.
   *  reach: 'now'   = reached with immediate measures
   *         'later' = reached only with patch/replacement
   *         'none'  = not reachable with the catalogue → decision needed */
  function recommend(p, f, base, options) {
    const target = p.ctx.acceptance;
    const now = [];
    if (f.kev) now.push('kev');
    let cur = Risk.residual(f, p.ctx, base, now).score;
    // Patch counts as an immediate measure only if it can be installed promptly; replacement never does
    const patchNow = f.patchAvailable && p.ctx.patchable !== false;
    const pool = options.filter(o => o.m.id !== 'kev' && o.m.id !== 'replace' && (o.m.id !== 'patch' || patchNow));
    while (cur > target) {
      let best = null, bestVal = 0;
      for (const o of pool) {
        if (now.includes(o.m.id)) continue;
        const s = Risk.residual(f, p.ctx, base, [...now, o.m.id]).score;
        const gain = cur - s;
        if (gain <= 0) continue;
        const val = gain * (0.5 + o.rel / 2) / o.m.effort;
        if (val > bestVal) { bestVal = val; best = { id: o.m.id, s }; }
      }
      if (!best) break; // no further measure lowers the risk
      now.push(best.id); cur = best.s;
    }
    const later = [];
    if (f.patchAvailable && !now.includes('patch')) later.push('patch');
    if (!f.patchAvailable) {
      if (!now.includes('vendor')) now.push('vendor');
      if (cur > target && options.some(o => o.m.id === 'replace')) later.push('replace');
    }
    const all = [...now, ...later];
    const fin = Risk.residual(f, p.ctx, base, all).score;
    return { now, later, all, reach: cur <= target ? 'now' : fin <= target ? 'later' : 'none' };
  }

  function activeFindings(p) { return p.findings.filter(f => f.status !== 'nb'); }
  const isOpenItem = f => !['nb', 'mitigiert', 'akzeptiert'].includes(f.status);
  /** How can a component be checked automatically? */
  const checkKind = c => Api.isPrecise(c.cpe) ? 'nvd' : c.purl ? 'trivy' : 'none';
  const prettyCpe = cpe => { const p = Api.cpeParts(cpe); return [p[3], p[4]].filter(Boolean).join(' ').replace(/\\/g, '').replace(/_/g, ' '); };

  // ---------- Rendering ----------
  function render() {
    const sel = $('#projectSelect');
    sel.innerHTML = state.projects.map(p => `<option value="${p.id}" ${p.id === state.currentId ? 'selected' : ''}>${esc(p.name)}</option>`).join('') || '<option>– no analysis yet –</option>';
    document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-selected', b.dataset.tab === ui.tab));
    document.documentElement.style.setProperty('--topbar-h', $('.topbar').offsetHeight + 'px');
    const p = project();
    $('#tabs').hidden = !p;
    const v = $('#view');
    // The app was used via the start file before, but the helper is not running right now (start window closed)
    const banner = ui.noHelper ? '<div class="callout warn no-print"><strong>The start window is closed.</strong> Please double-click “OT-Risikoanalyse starten” again and reload this page. Until then, “Scan software” and saving to a file are not available; your entries stay in the browser.</div>' : '';
    if (!p) { v.innerHTML = banner + viewWelcome(); return; }
    v.innerHTML = banner + { kontext: viewContext, sbom: viewSbom, cves: viewCves, matrix: viewMatrix, plan: viewPlan }[ui.tab](p);
  }

  function storageNote() {
    return Local.available
      ? `Your data is saved automatically – in the browser and as a file on this PC: <code>${esc(Local.dataFile)}</code>`
      : 'Your data is saved automatically in this browser on this device. Use “⋯” to create a backup regularly.';
  }

  function viewWelcome() {
    return `<div class="card hero">
      <h2>Welcome to OT Risk Analysis</h2>
      <p>Five steps from a machine's component list to a finished action plan: record components, search for known vulnerabilities (CVEs) automatically, assess the risk in the context of the machine, and get measures aligned with IEC 62443.</p>
      <div class="choice-grid">
        <button class="choice main" data-action="project-new"><strong>Start a new analysis</strong><span>Create a machine and get going</span></button>
        <button class="choice" data-action="demo"><strong>View the example</strong><span>A fully filled-in demo machine to try things out</span></button>
        <a class="choice" href="guide.html" target="_blank" rel="noopener"><strong>Open the guide</strong><span>Explained step by step</span></a>
      </div>
      <p class="small muted" style="margin-top:16px">${storageNote()}</p>
      <p class="small muted">A working aid without warranty; it does not replace an expert review. This product uses the NVD API but is not endorsed or certified by the NVD. <a href="legal.html" target="_blank" rel="noopener">Privacy and legal notes</a></p>
    </div>`;
  }

  function opt(val, cur, label) { return `<option value="${val}" ${String(val) === String(cur) ? 'selected' : ''}>${esc(label)}</option>`; }

  function viewContext(p) {
    const c = p.ctx;
    return `
    <div class="card">
      <h2>Quick choice: how is the machine connected?</h2>
      <div class="choice-grid">${Object.entries(PRESETS).map(([k, pr]) => {
        const on = pr.ctx.exposure === c.exposure && pr.ctx.remoteAccess === c.remoteAccess;
        return `<button class="choice ${on ? 'on' : ''}" data-action="preset" data-k="${k}"><strong>${on ? '✓ ' : ''}${esc(pr.label)}</strong><span>${esc(pr.hint)}</span></button>`;
      }).join('')}</div>
      <p class="small muted" style="margin-top:10px">The choice sets network exposure and remote maintenance. Everything can be refined below – changes take effect at once on the rating of all vulnerabilities.</p>
    </div>
    <div class="card">
      <h2>Project & machine</h2>
      <div class="grid two">
        <label class="field">Project name<input data-bind="name" value="${esc(p.name)}"></label>
        <label class="field">Machine / plant <span class="hint">type, serial number, year built</span><input data-bind="machine" value="${esc(p.machine)}"></label>
        <label class="field">Customer / site<input data-bind="customer" value="${esc(p.customer)}"></label>
        <label class="field">Author<input data-bind="author" value="${esc(p.author || '')}"></label>
      </div>
      <label class="field" style="margin-top:14px">Description / system boundary<textarea data-bind="description">${esc(p.description)}</textarea></label>
    </div>
    <div class="card">
      <h2>Operating context in detail</h2>
      <div class="grid two">
        <label class="field">Network exposure of the machine<span class="hint">How far can the machine be reached over the network?</span>
          <select data-ctx="exposure">${[1, 2, 3, 4].map(i => opt(i, c.exposure, Risk.EXPOSURE[i])).join('')}</select></label>
        <label class="field">Physical access<span class="hint">Who can get to the control cabinet, USB and network ports?</span>
          <select data-ctx="physical">${[1, 2, 3].map(i => opt(i, c.physical, Risk.PHYSICAL[i])).join('')}</select></label>
        <label class="field">Safety relevance<span class="hint">Danger to people if the machine is manipulated</span>
          <select data-ctx="safety">${opt(1, c.safety, 'low')}${opt(2, c.safety, 'medium – injury possible')}${opt(3, c.safety, 'high – serious injury possible')}</select></label>
        <label class="field">Availability requirement<span class="hint">Consequences of a machine standstill</span>
          <select data-ctx="availability">${opt(1, c.availability, 'low')}${opt(2, c.availability, 'medium')}${opt(3, c.availability, 'high – bottleneck machine / line standstill')}</select></label>
        <label class="field">Confidentiality need<span class="hint">Recipes, process know-how, programs</span>
          <select data-ctx="confidentiality">${opt(1, c.confidentiality, 'low')}${opt(2, c.confidentiality, 'medium')}${opt(3, c.confidentiality, 'high')}</select></label>
        <label class="field">Target security level (SL-T) under IEC 62443-3-3
          <select data-ctx="slT">${opt(1, c.slT, 'SL 1 – protection against casual misuse')}${opt(2, c.slT, 'SL 2 – simple means, low motivation')}${opt(3, c.slT, 'SL 3 – sophisticated means, IACS skills')}${opt(4, c.slT, 'SL 4 – extended resources')}</select></label>
        <label class="field">Risk acceptance<span class="hint">Up to which risk value (likelihood × impact) is a risk considered tolerable?</span>
          <select data-ctx="acceptance">${opt(4, c.acceptance, '≤ 4 (only “Low” accepted) – recommended')}${opt(6, c.acceptance, '≤ 6')}${opt(9, c.acceptance, '≤ 9 (“Medium” accepted)')}</select></label>
      </div>
      <div class="grid two" style="margin-top:14px">
        <label class="check"><input type="checkbox" data-ctx="remoteAccess" ${c.remoteAccess ? 'checked' : ''}><span><strong>Remote maintenance access exists</strong><br><span class="muted small">Router/VPN for the machine builder's service</span></span></label>
        <label class="check"><input type="checkbox" data-ctx="patchable" ${c.patchable ? 'checked' : ''}><span><strong>Patches can be installed promptly</strong><br><span class="muted small">Unticked (usual in production), the app recommends immediate measures first and schedules the patch for the next maintenance window</span></span></label>
      </div>
    </div>
    <div class="row end"><button class="btn primary big" data-action="tab" data-tab="sbom">Continue to step 2: Components →</button></div>`;
  }

  function viewSbom(p) {
    const kinds = { nvd: 0, trivy: 0, none: 0 };
    const rows = p.components.map(c => {
      const n = p.findings.filter(f => f.componentId === c.id && f.status !== 'nb').length;
      const k = checkKind(c); kinds[k]++;
      const chk = k === 'nvd' ? '<span class="badge niedrig" title="Checked in the NVD for the exact version">✓ automatic check</span>'
        : k === 'trivy' ? `<span class="badge niedrig" title="Software package: checked with Trivy">✓ ${Local.trivy ? 'automatic check' : 'via Trivy scan'}</span>`
          : `<button class="btn small" data-action="comp-edit" data-id="${c.id}" title="Pick the product from the NVD product list so it can be checked automatically">Assign product</button>`;
      return `<tr>
        <td><strong>${esc(c.name)}</strong><div class="muted small">${esc(c.vendor)}${c.pkgType ? ' · ' + esc(c.pkgType) : ''}${c.parentId ? ' · in ' + esc((p.components.find(x => x.id === c.parentId) || {}).name || '?') : ''}</div></td>
        <td>${esc(c.version)}</td>
        <td class="hide-sm">${esc(typeLabel(c.type))}</td>
        <td>${chk}</td>
        <td>${n ? `<span class="badge">${n}</span>` : '<span class="muted">0</span>'}</td>
        <td><div class="row" style="justify-content:flex-end;gap:6px;flex-wrap:nowrap">
          <button class="btn small" data-action="comp-search" data-id="${c.id}" title="Search the NVD for this component and pick the hits">Search</button>
          <button class="btn small" data-action="comp-edit" data-id="${c.id}">Edit</button>
          <button class="btn small danger" data-action="comp-del" data-id="${c.id}" aria-label="Delete">✕</button></div></td>
      </tr>`;
    }).join('');
    return `
    <div class="card">
      <h2>Add components</h2>
      <div class="choice-grid">
        <button class="choice" data-action="comp-edit"><strong>Add a device</strong><span>PLC, HMI, drive, switch, operating system … simply pick it from the product list</span></button>
        <button class="choice" data-action="scan-open"><strong>Scan software</strong><span>${Local.trivy ? 'Trivy searches a folder on this PC for software packages and vulnerabilities' : 'Capture software packages with Trivy (only on a PC using the start file)'}</span></button>
        <button class="choice" data-action="sbom-import"><strong>Import a file</strong><span>Load a bill of materials (SBOM) in CycloneDX format or a Trivy result</span></button>
      </div>
    </div>
    <div class="card">
      <div class="row"><h2 style="margin:0">Component list (${p.components.length})</h2><span class="spacer"></span>
        <button class="btn" data-action="cdx-export" ${p.components.length ? '' : 'disabled'}>Export (CycloneDX)</button></div>
      ${p.components.length ? `<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th>Component</th><th>Version</th><th class="hide-sm">Type</th><th>Check</th><th>CVEs</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
        ${kinds.none ? `<p class="small muted" style="margin-top:10px">${kinds.none} ${plural(kinds.none, 'component')} cannot be checked automatically yet. Use “Assign product” to pick the matching product and version from the NVD product list – after that it works with one click.</p>` : ''}`
        : '<div class="empty">No components yet. Choose one of the three options above.</div>'}
    </div>
    ${p.components.length ? `<div class="row end">
      <button class="btn" data-action="tab" data-tab="cves">Continue without searching →</button>
      <button class="btn primary big" data-action="auto-check">Search for vulnerabilities now</button></div>` : ''}`;
  }

  function riskBadge(r, prefix) {
    if (r.eliminated) return `<span class="badge niedrig" title="Vulnerability removed by patch or replacement">${prefix || ''}✓ fixed</span>`;
    return `<span class="badge ${r.level.key}" title="Likelihood ${r.L} × impact ${r.I}">${prefix || ''}${r.score} · ${r.level.label}</span>`;
  }
  function stars(n) { return '<span class="stars" title="Relevance">' + '●'.repeat(n) + '○'.repeat(3 - n) + '</span>'; }

  function viewCves(p) {
    const all = p.findings.map(f => ({ f, e: evaluate(p, f) }));
    const list = all.filter(({ f, e }) => {
      if (ui.cell) { const r = ui.matrixMode === 'nachher' ? e.res : e.base; if (r.L !== ui.cell[0] || r.I !== ui.cell[1] || f.status === 'nb') return false; }
      if (!ui.filter) return true;
      const q = ui.filter.toLowerCase();
      return (f.cve + ' ' + f.description + ' ' + (e.comp ? e.comp.name + ' ' + e.comp.vendor : '')).toLowerCase().includes(q);
    }).sort((a, b) => (a.f.status === 'nb') - (b.f.status === 'nb') || b.e.base.score - a.e.base.score || (b.f.cvss?.score || 0) - (a.f.cvss?.score || 0));
    const shown = list.slice(0, ui.limit);
    const openItems = all.filter(x => isOpenItem(x.f));
    const noSel = openItems.filter(x => !(x.f.mitigations || []).length).length;

    return `
    ${p.findings.length ? `<div class="card no-print">
      <div class="row"><div><h2 style="margin:0">${p.findings.length} ${plural(p.findings.length, 'vulnerability', 'vulnerabilities')}</h2>
        <div class="small muted">Sorted by risk. Tap an entry to see the reasoning and the measures.</div></div><span class="spacer"></span>
        <button class="btn" data-action="auto-check">Search again</button>
        <button class="btn ${noSel ? 'primary' : ''}" data-action="rec-all">Apply all recommendations</button></div>
      ${noSel ? `<p class="small" style="margin:10px 0 0">No measures have been selected yet for ${noSel} open ${plural(noSel, 'vulnerability', 'vulnerabilities')}. One click on “Apply all recommendations” selects the app's proposal everywhere – you can adjust individual entries afterwards.</p>` : ''}
    </div>` : `<div class="card empty"><h2>No vulnerabilities yet</h2><p>The app searches for known vulnerabilities for all components automatically.</p>
      <button class="btn primary big" data-action="auto-check">Search for vulnerabilities now</button></div>`}
    <details class="card no-print"><summary style="cursor:pointer;font-weight:650">Add a single vulnerability by hand</summary>
      <div class="grid two" style="margin-top:12px">
        <label class="field">CVE numbers <span class="hint">separate several with a comma or space</span><input id="cveIds" placeholder="e.g. CVE-2022-38465, CVE-2021-44228"></label>
        <label class="field">Affected component<select id="cveComp">${p.components.map(c => `<option value="${c.id}">${esc(c.name)} ${esc(c.version)}</option>`).join('')}<option value="">– not assigned –</option></select></label>
      </div>
      <div class="row" style="margin-top:10px"><button class="btn primary" data-action="cve-fetch">Fetch</button>
        <button class="btn" data-action="cve-manual">Record without a CVE number</button>
        <button class="btn" data-action="enrich" title="Reload the exploitation probability (EPSS) and the list of actively exploited vulnerabilities (CISA KEV)">Update threat data</button>
        <span class="muted small" id="fetchStatus"></span></div>
    </details>
    ${p.findings.length ? `<div class="row no-print" style="margin-bottom:10px">
      <input type="search" id="filter" placeholder="Filter by CVE, component, text …" value="${esc(ui.filter)}" style="flex:1;min-width:200px">
      ${ui.cell ? `<span class="badge outline">Matrix cell L${ui.cell[0]} × I${ui.cell[1]} <button class="btn small" data-action="cell-clear" style="min-height:22px;padding:0 6px;border:0">✕</button></span>` : ''}
    </div>` : ''}
    ${shown.map(x => findingCard(p, x.f, x.e)).join('')}
    ${list.length > shown.length ? `<div class="row" style="justify-content:center;margin:12px 0"><button class="btn" data-action="more">Show ${Math.min(PAGE, list.length - shown.length)} more (${list.length - shown.length} left)</button></div>` : ''}
    ${p.findings.length && !list.length ? '<div class="card empty">No match for this filter.</div>' : ''}
    ${p.findings.length ? '<div class="row end no-print" style="margin-top:14px"><button class="btn" data-action="tab" data-tab="matrix">Risk matrix</button><button class="btn primary big" data-action="tab" data-tab="plan">Continue to the action plan →</button></div>' : ''}`;
  }

  function findingCard(p, f, e) {
    const nb = f.status === 'nb';
    const lv = nb ? 'nb' : e.base.level.key;
    const sev = f.cvss && f.cvss.score != null ? `CVSS ${f.cvss.score}` : 'no CVSS';
    const flagOver = !nb && e.over && f.status !== 'akzeptiert' && (f.mitigations || []).length;
    return `<details class="finding ${lv}" data-fid="${f.id}" ${ui.open.has(f.id) ? 'open' : ''}>
      <summary>
        <div>
          <div class="title">${esc(f.cve)} <span class="muted" style="font-weight:400">· ${esc(e.comp ? e.comp.name + ' ' + e.comp.version : 'no component')}</span></div>
          <div class="meta">
            <span class="badge outline">${sev}</span>
            ${f.kev ? '<span class="badge kev" title="Listed in the CISA catalogue of known exploited vulnerabilities (KEV)">actively exploited</span>' : ''}
            ${f.epss != null ? `<span class="badge outline" title="EPSS: probability of exploitation within the next 30 days">EPSS ${pct(f.epss)}</span>` : ''}
            ${f.patchAvailable ? '<span class="badge outline">patch available</span>' : ''}
            ${f.source ? `<span class="badge outline">Source: ${esc(f.source)}</span>` : ''}
            <span class="badge outline">${STATUS[f.status || 'offen']}</span>
            ${flagOver ? '<span class="badge hoch" title="The residual risk of the selected measures is above the acceptance threshold">above acceptance</span>' : ''}
            ${!nb && e.reach !== 'now' && isOpenItem(f) ? `<span class="badge ${e.reach === 'none' ? 'krit' : 'mittel'}" title="See the note in the details">${e.reach === 'none' ? 'decision needed' : 'acceptance only after patch/replacement'}</span>` : ''}
          </div>
        </div>
        <div class="riskflow">${nb ? '<span class="badge">not affected</span>' : `${riskBadge(e.base)} <span class="muted">→</span> ${riskBadge(e.res)}`}</div>
      </summary>
      <div class="body">${ui.open.has(f.id) ? findingBody(p, f, e) : ''}</div>
    </details>`;
  }

  function reachNote(p, f, e) {
    const t = p.ctx.acceptance;
    if (e.reach === 'now') return `<p class="small muted" style="margin:8px 0 0">The recommended measures reach the acceptance threshold (≤ ${t}): ${riskBadge(e.recResNow, 'residual risk ')}</p>`;
    if (e.reach === 'later') return `<div class="callout warn"><strong>Acceptance threshold (≤ ${t}) is reached only after ${e.recLater.includes('patch') ? 'the patch' : 'replacing the component'}.</strong>
      Until then the immediate measures leave ${riskBadge(e.recResNow, 'residual risk ')}. This interim risk should be decided on deliberately and justified in the note.</div>`;
    return `<div class="callout danger"><strong>Acceptance threshold (≤ ${t}) cannot be reached with the available measures.</strong>
      At best ${riskBadge(e.recRes, 'residual risk ')} remains. This needs a decision by those responsible: formally accept the risk (status “Risk accepted” with a justification) or replace the component.</div>`;
  }

  function findingBody(p, f, e) {
    const nb = f.status === 'nb';
    const chosen = f.mitigations || [];
    return `
        <p class="desc">${esc(f.description) || '<span class="muted">No description</span>'}</p>
        ${f.fix ? `<p class="small"><strong>Fix according to ${esc(f.source || 'scanner')}:</strong> ${esc(f.fix)}</p>` : ''}
        <div class="grid two">
          <div>
            <strong>Likelihood: ${e.base.L}/5</strong>
            <ul class="why">${e.base.whyL.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
          </div>
          <div>
            <strong>Impact: ${e.base.I}/5</strong>
            <ul class="why">${e.base.whyI.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
          </div>
        </div>
        <p class="small muted" style="margin:10px 0">${f.cvss && f.cvss.vector ? `<code>${esc(f.cvss.vector)}</code> · ` : ''}${(f.cwe || []).map(esc).join(', ') || 'CWE unknown'} · published ${fmtDate(f.published)}
          ${/^CVE-/i.test(f.cve) ? `· <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}" target="_blank" rel="noopener">Details in the NVD</a>` : ''}</p>
        <div class="grid two no-print">
          <label class="field">Status<select data-f="status">${Object.entries(STATUS).map(([k, l]) => opt(k, f.status || 'offen', l)).join('')}</select></label>
          <label class="field">Component<select data-f="componentId">${p.components.map(c => opt(c.id, f.componentId, c.name + ' ' + c.version)).join('')}${opt('', f.componentId || '', '– none –')}</select></label>
        </div>
        <label class="check no-print" style="margin:10px 0"><input type="checkbox" data-f="patchAvailable" ${f.patchAvailable ? 'checked' : ''}><span>Vendor patch / fixed version available</span></label>
        ${f.status === 'akzeptiert' && !(f.note || '').trim() ? '<div class="callout warn">For an accepted risk, please enter a justification below (who accepted it, when and why).</div>' : ''}
        ${nb ? '' : `
        <div class="row" style="margin-top:12px"><h3 style="margin:0">Measures</h3><span class="spacer"></span>
          <button class="btn small primary no-print" data-action="rec-apply">Apply recommendation</button></div>
        ${reachNote(p, f, e)}
        <div class="mit-list">${e.options.map(o => {
          const isNow = e.recNow.includes(o.m.id), isLater = e.recLater.includes(o.m.id);
          const mand = o.m.sl <= p.ctx.slT && o.m.cat === 'Technical';
          return `<div class="mit ${isNow || isLater ? 'rec' : ''}">
            <label class="h check"><input type="checkbox" data-mit="${o.m.id}" ${chosen.includes(o.m.id) ? 'checked' : ''}>
              <strong>${esc(o.m.title)}</strong>${stars(o.rel)}</label>
            <div class="small" style="margin:4px 0 0 26px">${esc(o.m.text)}</div>
            <div class="row small" style="margin:6px 0 0 26px;gap:6px">
              ${isNow ? '<span class="badge" style="background:var(--accent);color:#fff">recommended: now</span>' : ''}
              ${isLater ? '<span class="badge" style="background:var(--accent);color:#fff">recommended: schedule</span>' : ''}
              <span class="badge outline">${esc(o.m.cat)}</span>
              ${o.m.sr.map(s => `<span class="badge outline">${esc(s)}</span>`).join('')}
              ${mand ? `<span class="badge outline" title="This system requirement is relevant for the target security level">SL-T ${p.ctx.slT}</span>` : ''}
              <span class="muted">Effort ${'€'.repeat(o.m.effort)}</span>
            </div>
            <ul style="margin-left:26px">${o.m.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
          </div>`;
        }).join('')}</div>`}
        <label class="field no-print" style="margin-top:12px">Note / justification<textarea data-f="note" placeholder="e.g. the reason for accepting a risk or why the machine is not affected">${esc(f.note || '')}</textarea></label>
        <div class="row end no-print" style="margin-top:8px"><button class="btn small danger" data-action="finding-del">Remove vulnerability</button></div>`;
  }

  function matrixCounts(p, mode) {
    const m = {};
    activeFindings(p).forEach(f => { const e = evaluate(p, f); const r = mode === 'nachher' ? e.res : e.base; const k = r.L + '_' + r.I; m[k] = (m[k] || 0) + 1; });
    return m;
  }

  /* Axes: likelihood to the right, impact upwards – highest risk (25) at the top right */
  function matrixHtml(p, mode, interactive) {
    const counts = matrixCounts(p, mode);
    let cells = '';
    for (let I = 5; I >= 1; I--) for (let L = 1; L <= 5; L++) {
      const n = counts[L + '_' + I] || 0;
      const lv = Risk.level(L * I).key;
      const sel = ui.cell && ui.cell[0] === L && ui.cell[1] === I;
      cells += `<button class="cell ${lv} ${n ? '' : 'zero'} ${sel ? 'sel' : ''}" ${interactive ? `data-action="cell" data-l="${L}" data-i="${I}"` : 'tabindex="-1"'} aria-label="Likelihood ${L}, impact ${I}: ${n}"><span class="sc">${L * I}</span>${n || '·'}</button>`;
    }
    return `<div class="matrix-wrap">
      <div class="matrix-ylab">Impact →</div>
      <div><div class="matrix">${cells}</div><div class="axis" style="margin-top:4px"><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span></div></div>
      <div></div><div class="matrix-xlab">Likelihood →</div>
    </div>`;
  }

  function distribution(p, pick) {
    const d = { krit: 0, hoch: 0, mittel: 0, niedrig: 0 };
    activeFindings(p).forEach(f => { d[pick(evaluate(p, f)).level.key]++; });
    return d;
  }

  function distBar(d) {
    const tot = Object.values(d).reduce((a, b) => a + b, 0) || 1;
    return `<div class="bar">${LEVELS.map(l => `<span class="cell ${l.key}" style="width:${d[l.key] / tot * 100}%"></span>`).join('')}</div>
      <div class="row small" style="margin-top:6px;gap:12px">${LEVELS.map(l => `<span><span class="badge ${l.key}">${d[l.key]}</span> ${l.label}</span>`).join('')}</div>`;
  }

  function viewMatrix(p) {
    if (!activeFindings(p).length) return '<div class="card empty">No assessed vulnerabilities yet.</div>';
    return `
    <div class="card">
      <div class="row"><h2 style="margin:0">Risk matrix</h2><span class="spacer"></span>
        <div class="seg" role="group" aria-label="View"><button class="${ui.matrixMode === 'vorher' ? 'on' : ''}" data-action="mmode" data-m="vorher">Initial risk</button><button class="${ui.matrixMode === 'nachher' ? 'on' : ''}" data-action="mmode" data-m="nachher">Residual risk</button></div></div>
      <p class="muted small">The highest risk is at the top right. Residual risk = after the measures selected in step 3. Tap a cell to see the vulnerabilities in it.</p>
      <div class="grid two" style="align-items:start">
        ${matrixHtml(p, ui.matrixMode, true)}
        <div>
          <h3>Distribution – initial risk</h3>${distBar(distribution(p, e => e.base))}
          <h3 style="margin-top:18px">Distribution – residual risk</h3>${distBar(distribution(p, e => e.res))}
          <p class="small muted" style="margin-top:18px">Risk = likelihood (attack path, complexity, privileges required, network exposure, EPSS, CISA KEV) × impact (availability and integrity before confidentiality, safety relevance). Acceptance threshold: ≤ ${p.ctx.acceptance}.</p>
        </div>
      </div>
    </div>
    <div class="row end"><button class="btn primary big" data-action="tab" data-tab="plan">Continue to the action plan →</button></div>`;
  }

  /** Aggregated action plan across all vulnerabilities */
  function buildPlan(p, source) {
    const map = new Map();
    activeFindings(p).forEach(f => {
      if (['mitigiert', 'akzeptiert'].includes(f.status)) return;
      const e = evaluate(p, f);
      const ids = source === 'auswahl' && (f.mitigations || []).length ? f.mitigations : e.rec;
      ids.forEach(id => {
        const m = MITIGATIONS.find(x => x.id === id); if (!m) return;
        if (!map.has(id)) map.set(id, { m, findings: [], comps: new Set(), reduction: 0, maxRisk: 0, kev: false });
        const g = map.get(id);
        g.findings.push(f.cve);
        if (e.comp) g.comps.add(e.comp.name);
        g.maxRisk = Math.max(g.maxRisk, e.base.score);
        g.kev = g.kev || f.kev;
        const without = Risk.residual(f, p.ctx, e.base, ids.filter(x => x !== id)).score;
        const withAll = Risk.residual(f, p.ctx, e.base, ids).score;
        g.reduction += Math.max(0, without - withAll);
      });
    });
    return [...map.values()].map(g => {
      g.prio = g.kev || g.maxRisk >= 15 ? 1 : g.maxRisk >= 10 ? 2 : 3;
      // Permanent fix without a prompt maintenance window, or replacement: planned instead of immediate
      if (g.m.id === 'replace' || (g.m.id === 'patch' && p.ctx.patchable === false)) g.prio = Math.max(g.prio, 3);
      return g;
    }).sort((a, b) => a.prio - b.prio || (b.m.id === 'kev') - (a.m.id === 'kev') || b.reduction - a.reduction || b.findings.length - a.findings.length || a.m.effort - b.m.effort);
  }
  const PRIO = { 1: ['Immediate', 'krit', 'within 72 h – 2 weeks'], 2: ['Short term', 'hoch', 'within 3 months'], 3: ['Planned', 'mittel', 'in the next maintenance/release cycle'] };
  const short = (arr, n) => arr.length > n ? arr.slice(0, n).join(', ') + ` … (+${arr.length - n})` : arr.join(', ');
  const yesNo = b => b ? 'yes' : 'no';
  const vulnWord = n => plural(n, 'vulnerability', 'vulnerabilities');

  function viewPlan(p) {
    const act = activeFindings(p);
    if (!p.findings.length) return `<div class="card empty"><h2>No action plan yet</h2><p>First record components and search for vulnerabilities.</p><button class="btn primary big" data-action="tab" data-tab="sbom">Go to step 2: Components</button></div>`;
    const evs = act.map(f => ({ f, e: evaluate(p, f) }));
    const before = distribution(p, e => e.base), after = distribution(p, e => e.res);
    const recNow = distribution(p, e => e.recResNow), recFin = distribution(p, e => e.recRes);
    const plan = buildPlan(p, ui.planSource || 'empfehlung');
    const open = evs.filter(x => isOpenItem(x.f));
    const later = open.filter(x => x.e.reach === 'later'), none = open.filter(x => x.e.reach === 'none');
    const accNoNote = evs.filter(x => x.f.status === 'akzeptiert' && !(x.f.note || '').trim());
    const c = p.ctx;
    return `
    <div class="report-only">
      <h1>OT risk analysis: ${esc(p.name)}</h1>
      <p>${esc(p.machine)} ${p.customer ? '· ' + esc(p.customer) : ''} · as of ${new Date().toLocaleDateString('en-GB')} ${p.author ? '· author: ' + esc(p.author) : ''}</p>
      ${p.description ? `<p>${esc(p.description)}</p>` : ''}
      <p><strong>Context:</strong> network exposure ${esc(Risk.EXPOSURE[c.exposure])}; remote maintenance ${yesNo(c.remoteAccess)}; physical access ${esc(Risk.PHYSICAL[c.physical])}; safety ${c.safety}/3; availability ${c.availability}/3; confidentiality ${c.confidentiality}/3; SL-T ${c.slT}; patches can be installed promptly: ${yesNo(c.patchable)}; risk acceptance ≤ ${c.acceptance}.</p>
    </div>
    <div class="grid kpi" style="margin-bottom:16px">
      <div class="kpi-tile"><div class="v">${p.components.length}</div><div class="l">components</div></div>
      <div class="kpi-tile"><div class="v">${act.length}</div><div class="l">relevant vulnerabilities</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-krit)">${before.krit + before.hoch}</div><div class="l">critical/high initially</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-krit)">${act.filter(f => f.kev).length}</div><div class="l">actively exploited</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-hoch)">${recNow.krit + recNow.hoch}</div><div class="l">critical/high after immediate measures</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-niedrig)">${recFin.krit + recFin.hoch}</div><div class="l">critical/high after patch/replacement</div></div>
    </div>
    ${later.length || none.length || accNoNote.length ? `<div class="card">
      <h2>Decisions needed</h2>
      ${none.length ? `<div class="callout danger"><strong>${none.length} ${vulnWord(none.length)}: acceptance threshold (≤ ${c.acceptance}) cannot be reached.</strong> Formally accept the risk or replace the component: ${esc(short(none.map(x => x.f.cve), 8))}</div>` : ''}
      ${later.length ? `<div class="callout warn"><strong>${later.length} ${vulnWord(later.length)}: acceptance threshold is reached only after patch or replacement.</strong> Until then, despite the immediate measures, there is an increased interim risk that has to be carried deliberately: ${esc(short(later.map(x => x.f.cve), 8))}</div>` : ''}
      ${accNoNote.length ? `<div class="callout warn"><strong>${accNoNote.length} accepted ${plural(accNoNote.length, 'risk')} without a justification:</strong> ${esc(short(accNoNote.map(x => x.f.cve), 8))}</div>` : ''}
    </div>` : ''}
    <div class="card">
      <div class="row"><h2 style="margin:0">Action plan</h2><span class="spacer"></span>
        <div class="seg no-print"><button class="${(ui.planSource || 'empfehlung') === 'empfehlung' ? 'on' : ''}" data-action="psrc" data-s="empfehlung">App recommendation</button><button class="${ui.planSource === 'auswahl' ? 'on' : ''}" data-action="psrc" data-s="auswahl">My selection</button></div></div>
      <p class="muted small">For each vulnerability the smallest combination of measures that brings the risk below the acceptance threshold (≤ ${c.acceptance}) – combined and sorted by urgency. Mitigated and accepted vulnerabilities are left out.</p>
      ${plan.length ? plan.map((g, i) => `
        <div class="mit" style="margin-bottom:10px">
          <div class="h"><span class="badge ${PRIO[g.prio][1]}">${PRIO[g.prio][0]}</span><strong>${i + 1}. ${esc(g.m.title)}</strong><span class="muted small">Effort ${'€'.repeat(g.m.effort)}</span></div>
          <div class="small" style="margin-top:6px">${esc(g.m.text)}</div>
          <div class="row small" style="margin-top:6px;gap:6px">
            ${g.m.sr.map(s => `<span class="badge outline">${esc(s)}</span>`).join('')}
            <span class="muted">Implement ${PRIO[g.prio][2]} · affects ${g.findings.length} ${vulnWord(g.findings.length)}${g.reduction ? ' · risk reduction Σ ' + g.reduction : ''}</span>
          </div>
          <div class="small muted" style="margin-top:4px">Components: ${esc(short([...g.comps], 6) || '–')} · ${esc(short(g.findings, 10))}</div>
          <ul>${g.m.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
        </div>`).join('') : '<div class="empty">No open measures – all risks are within the acceptance threshold.</div>'}
    </div>
    <div class="card no-print">
      <h2>Output the result</h2>
      <div class="choice-grid">
        <button class="choice main" data-action="print"><strong>Print the report / save as PDF</strong><span>Choose “Save as PDF” in the print dialog</span></button>
        <button class="choice" data-action="csv"><strong>Table (CSV)</strong><span>All vulnerabilities for Excel</span></button>
        <button class="choice" data-action="cdx-vex"><strong>CycloneDX with VEX</strong><span>Bill of materials with status and rating for customers or other tools</span></button>
      </div>
    </div>
    <div class="grid two">
      <div class="card"><h3>Initial risk</h3>${matrixHtml(p, 'vorher', false)}<div style="margin-top:10px">${distBar(before)}</div></div>
      <div class="card"><h3>Residual risk (selected measures)</h3>${matrixHtml(p, 'nachher', false)}<div style="margin-top:10px">${distBar(after)}</div></div>
    </div>
    <div class="card">
      <h3>Vulnerability overview</h3>
      <div class="table-wrap"><table><thead><tr><th>CVE</th><th>Component</th><th>CVSS</th><th>L×I</th><th>Risk</th><th>Residual</th><th>Status</th></tr></thead><tbody>
      ${p.findings.map(f => ({ f, e: evaluate(p, f) })).sort((a, b) => b.e.base.score - a.e.base.score).map(({ f, e }) => `<tr>
        <td><strong>${esc(f.cve)}</strong>${f.kev ? ' <span class="badge kev">KEV</span>' : ''}</td>
        <td>${esc(e.comp ? e.comp.name + ' ' + e.comp.version : '–')}</td>
        <td>${f.cvss && f.cvss.score != null ? f.cvss.score : '–'}</td><td>${e.base.L}×${e.base.I}</td>
        <td>${f.status === 'nb' ? '–' : riskBadge(e.base)}</td><td>${f.status === 'nb' ? '–' : riskBadge(e.res)}</td>
        <td>${STATUS[f.status || 'offen']}</td></tr>`).join('')}
      </tbody></table></div>
    </div>
    <p class="small muted">Method: environmental rating of the CVSS base metrics in the context of the machine; threat data from FIRST EPSS and CISA KEV; measures mapped to IEC 62443-3-3 system requirements (SR) and IEC 62443-2-3. The automatic recommendation does not replace an expert review of the individual case.</p>`;
  }

  // ---------- Modals ----------
  function openModal(title, html) { $('#modalTitle').textContent = title; $('#modalBody').innerHTML = html; $('#modal').hidden = false; }
  function closeModal() {
    if (ui.job) ui.job.cancelled = true;
    $('#modal').hidden = true; $('#modalBody').innerHTML = '';
  }
  let toastT;
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('show'), 3600); }

  function projectForm() {
    openModal('New analysis', `
      <form id="projForm" class="grid" style="gap:14px">
        <label class="field">Name of the analysis*<input name="name" required placeholder="e.g. Wire drawing machine, customer Sample" autofocus></label>
        <label class="field">Machine / plant <span class="hint">optional: type, serial number, year built</span><input name="machine"></label>
        <div><div style="font-weight:550;font-size:.9rem;margin-bottom:6px">How is the machine connected?</div>
          <div class="grid" style="gap:8px">${Object.entries(PRESETS).map(([k, pr]) => `<label class="check radio-card"><input type="radio" name="preset" value="${k}" ${k === 'vernetzt' ? 'checked' : ''}><span><strong>${esc(pr.label)}</strong><br><span class="muted small">${esc(pr.hint)}</span></span></label>`).join('')}</div>
          <div class="small muted" style="margin-top:6px">Can be changed and refined at any time later in step 1.</div></div>
        <div class="row end"><button type="button" class="btn" data-action="modal-close">Cancel</button><button class="btn primary">Create</button></div>
      </form>`);
  }

  function assignedHtml(cpe, title) {
    if (!cpe) return '<span class="muted small">No product assigned yet. Without one, only an imprecise keyword search is possible.</span>';
    const ok = Api.isPrecise(cpe);
    return `<div class="callout ${ok ? 'ok' : 'warn'}" style="margin:0"><strong>${ok ? '✓' : '!'} Product assigned: ${esc(title || prettyCpe(cpe))}</strong> ${ok ? '– checked for the exact version.' : '– please also enter the version so the exact version can be checked.'}
      <button type="button" class="btn small" data-action="prod-clear" style="margin-left:6px">Remove assignment</button></div>`;
  }

  function compForm(c) {
    c = c || { name: '', vendor: '', version: '', type: 'SPS', cpe: '', purl: '' };
    ui.prodVersions = null;
    const key = c.cpe && c.cpe.startsWith('cpe:2.3:') ? Api.cpeParts(c.cpe).slice(2, 5).join(':') : '';
    openModal(c.id ? 'Edit component' : 'Add device / component', `
      <form id="compForm" class="grid two">
        <input type="hidden" name="id" value="${esc(c.id || '')}">
        <input type="hidden" name="cpeKey" value="${esc(key)}">
        <input type="hidden" name="product" value="${esc(c.product || '')}">
        <div style="grid-column:1/-1">
          <label class="field">1. Search the product in the NVD product list <span class="hint">A keyword is enough, e.g. “S7-1500”, “SCALANCE XC208”, “WinCC”, “Windows 10”</span></label>
          <div class="row" style="flex-wrap:nowrap;margin-top:4px"><input id="prodQ" type="search" value="${esc(c.id && !c.cpe ? c.name : '')}" placeholder="Search product …" style="flex:1"><button type="button" class="btn" data-action="prod-search">Search</button></div>
          <div id="prodResults" style="margin-top:8px"></div>
          <div id="prodChosen" style="margin-top:8px">${assignedHtml(c.cpe, c.product)}</div>
        </div>
        <label class="field">2. Version / firmware level<input name="version" list="verList" value="${esc(c.version)}" placeholder="e.g. 2.9.4" autocomplete="off"><datalist id="verList"></datalist></label>
        <label class="field">Type<select name="type">${COMP_TYPES.map(t => opt(t, c.type, typeLabel(t))).join('')}</select></label>
        <label class="field">Name*<input name="name" required value="${esc(c.name)}" placeholder="e.g. Main controller S7-1516"></label>
        <label class="field">Vendor<input name="vendor" value="${esc(c.vendor)}" placeholder="e.g. Siemens"></label>
        <details style="grid-column:1/-1"><summary class="small muted" style="cursor:pointer">For experts: edit identifiers directly (CPE / PURL)</summary>
          <div class="grid" style="margin-top:10px">
            <label class="field">CPE 2.3 <span class="hint">set automatically when you pick a product</span><input name="cpe" value="${esc(c.cpe)}"></label>
            <label class="field">Package URL (PURL) <span class="hint">for software packages, e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</span><input name="purl" value="${esc(c.purl || '')}"></label>
          </div></details>
        <div class="row end" style="grid-column:1/-1"><button type="button" class="btn" data-action="modal-close">Cancel</button><button class="btn primary">Save</button></div>
      </form>`);
  }

  // Note: always address fields through form.elements – fields named "id"/"name" would otherwise shadow the form's own properties
  function syncCpe(form) {
    const el = form.elements;
    const key = el.cpeKey.value;
    if (!key) return;
    const ver = el.version.value.trim();
    const hit = (ui.prodVersions || []).find(x => x.label.toLowerCase() === ver.toLowerCase());
    el.cpe.value = hit ? hit.cpe : Api.buildCpe(key, ver);
    $('#prodChosen').innerHTML = assignedHtml(el.cpe.value, el.product.value);
  }

  async function prodSearch() {
    const q = $('#prodQ').value.trim();
    const box = $('#prodResults');
    if (q.length < 3) { box.innerHTML = '<span class="small muted">Please enter at least 3 characters.</span>'; return; }
    box.innerHTML = '<span class="small muted">Searching the NVD product list …</span>';
    try {
      const r = await Api.products(q, s => { box.innerHTML = `<span class="small muted">The NVD allows only a few queries per minute – continuing in ${s} s …</span>`; });
      if (!$('#prodResults')) return;
      ui.prodList = r.items;
      const PART = { o: 'Firmware / operating system', a: 'Software', h: 'Hardware' };
      box.innerHTML = r.items.length ? `
        <div class="small muted" style="margin-bottom:6px">${r.items.length} ${plural(r.items.length, 'product')} found${r.truncated ? ' – a great many hits, please narrow the search term' : ''}. Click the matching product:</div>
        <div class="dirlist">${r.items.slice(0, 60).map((g, i) => `<button type="button" class="dir" data-action="prod-pick" data-i="${i}"><strong>${esc(g.title)}</strong><span class="muted small">${PART[g.part] || ''}${g.versions.length ? ' · ' + g.versions.length + ' known versions' : ''}</span></button>`).join('')}</div>`
        : '<span class="small">No product found. Tip: use a shorter keyword (e.g. only the type designation).</span>';
    } catch (e) { box.innerHTML = `<span class="small">${esc(e.message)}</span>`; }
  }

  function prodPick(i) {
    const g = (ui.prodList || [])[i]; if (!g) return;
    const form = $('#compForm'), el = form.elements;
    el.cpeKey.value = g.key;
    el.product.value = g.title;
    ui.prodVersions = g.versions;
    $('#verList').innerHTML = g.versions.slice(0, 300).map(v => `<option value="${esc(v.label)}">`).join('');
    if (!el.name.value.trim()) el.name.value = g.title;
    if (!el.vendor.value.trim()) el.vendor.value = g.vendor.replace(/\\/g, '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());
    if (!el.id.value) el.type.value = g.part === 'a' ? 'Anwendung' : /windows|linux|debian|ubuntu/i.test(g.title) ? 'Betriebssystem' : /s7|plc|cpu|controller|logo/i.test(g.title) ? 'SPS' : /panel|hmi/i.test(g.title) ? 'HMI' : /scalance|switch|router|ruggedcom/i.test(g.title) ? 'Netzwerk' : /sinamics|drive|servo/i.test(g.title) ? 'Antrieb' : 'Firmware';
    $('#prodResults').innerHTML = '';
    syncCpe(form);
    el.version.focus();
  }

  async function compSearch(c) {
    const precise = Api.isPrecise(c.cpe);
    openModal(`Search for vulnerabilities: ${c.name}`, `<p class="muted">Searching the NVD ${precise ? 'for the exact version' : c.cpe ? 'for all versions of the product' : 'by keyword “' + esc([c.vendor, c.name].filter(Boolean).join(' ')) + '”'} …</p><p id="searchWait" class="small muted"></p>`);
    try {
      const r = await Api.search(c, s => { const w = $('#searchWait'); if (w) w.textContent = `The NVD allows only a few queries per minute – continuing in ${s} s`; });
      if ($('#modal').hidden) return;
      const known = new Set(project().findings.map(f => f.cve + '|' + f.componentId));
      const ver = (c.version || '').replace(/^v/i, '').trim();
      const hint = r.precise ? 'According to the NVD these vulnerabilities affect exactly the version entered – all of them are preselected.'
        : `Caution: imprecise search${c.cpe ? ' (version missing)' : ' by keyword'} – it may include hits that do not apply. Only hits whose description mentions the version “${esc(ver)}” are preselected. “Edit → Assign product” gives more precise results.`;
      const body = r.items.length ? `
        <p class="small ${r.precise ? 'muted' : ''}">${r.total} ${plural(r.total, 'hit')}${r.total > r.items.length ? `, showing the newest ${r.items.length}` : ''}. ${hint}</p>
        <div class="row" style="margin-bottom:8px"><button class="btn small" data-action="sel-all">All</button><button class="btn small" data-action="sel-none">None</button><span class="spacer"></span><button class="btn primary" data-action="search-take" data-id="${c.id}">Add selected</button></div>
        <div class="table-wrap"><table><tbody>${r.items.map(it => {
          const dup = known.has(it.cve + '|' + c.id);
          const pre = !dup && (r.precise || (ver && it.description.includes(ver)));
          return `<tr><td><input type="checkbox" data-cve="${esc(it.cve)}" ${pre ? 'checked' : ''} ${dup ? 'disabled' : ''}></td>
            <td><strong>${esc(it.cve)}</strong> ${it.cvss ? `<span class="badge outline">${it.cvss.score}</span>` : ''} ${it.kev ? '<span class="badge kev">actively exploited</span>' : ''} ${dup ? '<span class="badge">already recorded</span>' : ''}
            <div class="small muted">${esc(it.description.slice(0, 260))}${it.description.length > 260 ? '…' : ''}</div></td></tr>`;
        }).join('')}</tbody></table></div>` : `<div class="empty">${r.precise ? 'The NVD knows no vulnerabilities for this version.' : 'No hits. Tip: use “Edit” to assign a product from the product list.'}</div>`;
      $('#modalBody').innerHTML = body;
      $('#modalBody')._items = r.items;
    } catch (e) { $('#modalBody').innerHTML = `<p>${esc(e.message)}</p>`; }
  }

  function manualForm() {
    const p = project();
    openModal('Record a vulnerability without a CVE number', `
      <form id="manualForm" class="grid two">
        <label class="field">Identifier*<input name="cve" required placeholder="e.g. vendor advisory or internal number"></label>
        <label class="field">Component<select name="componentId">${p.components.map(c => opt(c.id, '', c.name + ' ' + c.version)).join('')}<option value="">– none –</option></select></label>
        <label class="field">CVSS base score<input name="score" inputmode="decimal" placeholder="e.g. 9.8"></label>
        <label class="field">CVSS vector<input name="vector" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></label>
        <label class="field">CWE <span class="hint">comma-separated</span><input name="cwe" placeholder="CWE-787"></label>
        <label class="check" style="align-self:end"><input type="checkbox" name="patch"><span>Patch available</span></label>
        <label class="field" style="grid-column:1/-1">Description<textarea name="description"></textarea></label>
        <div class="row end" style="grid-column:1/-1"><button type="button" class="btn" data-action="modal-close">Cancel</button><button class="btn primary">Add</button></div>
      </form>`);
  }

  function menu() {
    const p = project();
    openModal('Data & backup', `
      <p class="small muted" style="margin-top:0">${storageNote()}</p>
      <div class="menu-list">
        <button class="btn" data-action="backup-all"><strong>Save a backup</strong>&nbsp;– all analyses in one file</button>
        <button class="btn" data-action="import-json"><strong>Load a backup or analysis</strong>&nbsp;– from a file</button>
        ${p ? `<button class="btn" data-action="export-json">Save only the current analysis (to pass it on)</button>
        <button class="btn" data-action="project-dup">Duplicate the current analysis</button>
        <button class="btn danger" data-action="project-del">Delete the current analysis</button>` : ''}
        <button class="btn" data-action="demo">Load the example machine</button>
        <button class="btn danger" data-action="wipe">Delete all data on this device</button>
      </div>
      <p class="small muted" style="margin-top:12px">Privacy: the analyses stay on this device and are stored unencrypted – for confidential customer data use a PC with disk encryption (e.g. BitLocker). Only CVE numbers and product names go to the data sources NVD (NIST), EPSS (FIRST) and KEV (CISA), no project data. <a href="legal.html" target="_blank" rel="noopener">Privacy and legal notes</a></p>`);
  }

  // ---------- Trivy ----------
  const TRIVY_CMDS = [
    ['Software project / program folder', 'trivy fs --format cyclonedx --scanners vuln --output result.cdx.json ./folder'],
    ['Linux device: copied or unpacked file system (edge PC, Linux HMI, firmware)', 'trivy rootfs --format cyclonedx --scanners vuln --output result.cdx.json /mnt/device'],
    ['Container image', 'trivy image --format cyclonedx --scanners vuln --output result.cdx.json registry.example.com/app:1.4']
  ];
  function trivyGuide(intro) {
    openModal('Scan software with Trivy', `
      ${intro}
      <details style="margin-top:12px"><summary style="cursor:pointer;font-weight:600">For experts: run the scan by hand on the command line</summary>
      ${TRIVY_CMDS.map(([t, c]) => `<div style="margin:12px 0"><div class="small" style="font-weight:600;margin-bottom:4px">${esc(t)}</div>
        <div class="row" style="flex-wrap:nowrap"><code class="mono" style="flex:1;background:var(--surface-2);padding:8px 10px;border-radius:8px;overflow-x:auto;white-space:nowrap">${esc(c)}</code><button class="btn small" data-action="copy" data-text="${esc(c)}">Copy</button></div></div>`).join('')}
      <p class="small muted"><code>--scanners vuln</code> is important, otherwise the vulnerabilities are missing from the file.</p></details>
      <div class="row end" style="margin-top:12px"><button class="btn primary" data-action="sbom-import">Import scan file</button></div>`);
  }

  async function scanOpen() {
    if (!Local.available) {
      return trivyGuide(`<p>Scanning with one click works on a Windows PC when the app was opened through the file <strong>“OT-Risikoanalyse starten”</strong>. On this device you can load a scan result created there via “Import a file”.</p>`);
    }
    if (!Local.trivy) {
      return trivyGuide(`<div class="callout warn"><strong>Trivy is not installed on this PC yet.</strong><br>Needed once: press the Windows key, type “PowerShell” and open it, paste the following command and press Enter. Then close the app's start window and start the app again.</div>
        <div class="row" style="flex-wrap:nowrap;margin-top:8px"><code class="mono" style="flex:1;background:var(--surface-2);padding:8px 10px;border-radius:8px">winget install AquaSecurity.Trivy</code><button class="btn small" data-action="copy" data-text="winget install AquaSecurity.Trivy">Copy</button></div>`);
    }
    ui.scan = { tab: 'folder', dir: null, mode: 'fs', modeTouched: false };
    openModal('Scan software', '<p class="muted">Loading folder list …</p>');
    await scanNavigate('');
  }

  async function scanNavigate(path) {
    try {
      ui.scan.dir = await Local.dirs(path);
      if (!ui.scan.modeTouched) ui.scan.mode = ui.scan.dir.rootfs ? 'rootfs' : 'fs';
    } catch (e) { toast(e.message); if (!ui.scan.dir) { closeModal(); return; } }
    renderScan();
  }

  function renderScan() {
    const s = ui.scan, d = s.dir;
    if ($('#modal').hidden) return;
    $('#modalBody').innerHTML = `
      <div class="seg" style="margin-bottom:14px"><button class="${s.tab === 'folder' ? 'on' : ''}" data-action="scan-tab" data-t="folder">Folder on this PC</button><button class="${s.tab === 'image' ? 'on' : ''}" data-action="scan-tab" data-t="image">Container image</button></div>
      ${s.tab === 'folder' ? `
        <p class="small muted" style="margin-top:0">Choose the folder with the software to be checked – e.g. the project folder of an HMI application or the copy of a Linux device's file system. Trivy (version ${esc(Local.trivy)}) detects software packages in it and their known vulnerabilities.</p>
        <div class="row" style="gap:6px;margin-bottom:8px">${d.shortcuts.map(x => `<button class="btn small" data-action="scan-dir" data-path="${esc(x.path)}">${esc(x.name)}</button>`).join('')}</div>
        <div class="pathbar"><button class="btn small" data-action="scan-dir" data-path="${esc(d.parent || '')}" ${d.parent ? '' : 'disabled'} title="One level up">↑ up</button><code>${esc(d.path)}</code></div>
        <div class="dirlist" style="max-height:38vh">${d.dirs.length ? d.dirs.slice(0, 400).map(x => `<button class="dir" data-action="scan-dir" data-path="${esc(x.path)}">📁 ${esc(x.name)}</button>`).join('') : '<div class="small muted" style="padding:10px">No subfolders.</div>'}</div>
        <div style="margin-top:12px"><div style="font-weight:550;font-size:.9rem;margin-bottom:6px">What is in this folder?</div>
          <label class="check radio-card"><input type="radio" name="scanMode" value="fs" ${s.mode === 'fs' ? 'checked' : ''}><span><strong>Software project</strong><br><span class="muted small">Source code with package lists (e.g. package-lock.json, requirements.txt, pom.xml)</span></span></label>
          <label class="check radio-card" style="margin-top:6px"><input type="radio" name="scanMode" value="rootfs" ${s.mode === 'rootfs' ? 'checked' : ''}><span><strong>Installed software or device file system</strong><br><span class="muted small">Program folder, unpacked firmware, copied Linux system${d.rootfs ? ' – <strong>detected here</strong>' : ''}</span></span></label></div>
        <div class="row end" style="margin-top:14px"><button class="btn" data-action="modal-close">Cancel</button><button class="btn primary big" data-action="scan-start">Scan this folder</button></div>`
        : `
        <p class="small muted" style="margin-top:0">Name of a container image, as you would give it to Docker. The PC needs access to the image (Docker Desktop or the registry).</p>
        <label class="field">Image name<input id="scanImage" placeholder="e.g. nginx:1.25 or registry.company.com/gateway:1.4"></label>
        <div class="row end" style="margin-top:14px"><button class="btn" data-action="modal-close">Cancel</button><button class="btn primary big" data-action="scan-start">Scan image</button></div>`}`;
  }

  /** Starts a scan through the local helper and waits for the result (CycloneDX text) while showing progress. */
  async function runScan(mode, target, bomText, label) {
    await Local.startScan(mode, target, bomText);
    const job = ui.job = { cancelled: false };
    $('#modalTitle').textContent = 'Scan running …';
    $('#modalBody').innerHTML = `
      <p><strong>${esc(label)}</strong></p>
      <div class="progress indet"><span></span></div>
      <p class="small" id="scanTime">started …</p>
      <p class="small muted" id="scanLog" style="min-height:2.6em;word-break:break-word"></p>
      <p class="small muted">The first scan of the day downloads the current vulnerability database (about 130 MB) and therefore takes longer. Large folders can take a few minutes.</p>
      <div class="row end"><button class="btn" data-action="modal-close">Cancel</button></div>`;
    try {
      for (;;) {
        await sleep(1500);
        if (job.cancelled) { await Local.cancelScan().catch(() => {}); throw new Error('Scan cancelled.'); }
        const st = await Local.scanStatus();
        const tEl = $('#scanTime'), lEl = $('#scanLog');
        if (tEl) tEl.textContent = `Running for ${Math.floor(st.seconds / 60)}:${String(st.seconds % 60).padStart(2, '0')} min`;
        if (lEl && st.log && st.log.length) lEl.textContent = st.log[st.log.length - 1].replace(/\t/g, ' ');
        if (st.state === 'done') return await Local.scanResult();
        if (st.state !== 'running') throw new Error('Trivy reports an error: ' + ((st.log || []).filter(l => /ERROR|FATAL/.test(l)).pop() || (st.log || []).pop() || 'unknown').replace(/\t/g, ' '));
      }
    } finally { if (ui.job === job) ui.job = null; }
  }

  async function scanStart() {
    const s = ui.scan;
    let mode, target, label;
    if (s.tab === 'image') {
      target = ($('#scanImage').value || '').trim(); mode = 'image'; label = 'Container image ' + target;
      if (!target) return toast('Please enter an image name');
    } else { mode = s.mode; target = s.dir.path; label = 'Folder ' + target; }
    try {
      const text = await runScan(mode, target, null, label);
      importSbom(text, 'trivy.cdx.json', mode === 'fs' ? 'Tip: if nothing was found, repeat the scan with the setting “Installed software or device file system”.' : '');
    } catch (e) {
      if (/cancelled/.test(e.message)) return toast(e.message);
      openModal('Scan not successful', `<div class="callout danger">${esc(e.message)}</div><div class="row end"><button class="btn" data-action="scan-open">Back</button></div>`);
    }
  }

  // ---------- Automatic vulnerability search ----------
  async function autoCheck() {
    const p = project();
    if (ui.job) return;
    const nvd = p.components.filter(c => checkKind(c) === 'nvd');
    const tv = p.components.filter(c => checkKind(c) === 'trivy');
    const none = p.components.filter(c => checkKind(c) === 'none');
    const useTrivy = tv.length && Local.trivy;
    const steps = nvd.length + (useTrivy ? 1 : 0);
    const rows = [];
    const pkgWord = n => plural(n, 'software package');
    let added = 0;
    if (steps) {
      const job = ui.job = { cancelled: false };
      openModal('Searching for vulnerabilities', `
        <div class="progress"><span id="jobBar" style="width:0%"></span></div>
        <p id="jobText" style="margin-bottom:4px">Starting …</p>
        <p class="small muted" id="jobWait" style="min-height:1.4em"></p>
        <p class="small muted">The NVD database allows only 5 queries per 30 seconds. The app queues the queries automatically – please just wait.</p>
        <div class="row end"><button class="btn" data-action="modal-close">Cancel</button></div>`);
      const setP = (i, text) => { const b = $('#jobBar'), t = $('#jobText'), w = $('#jobWait'); if (b) b.style.width = Math.round(i / steps * 100) + '%'; if (t) t.textContent = text; if (w) w.textContent = ''; };
      let i = 0;
      for (const c of nvd) {
        if (job.cancelled) break;
        setP(i, `${i + 1} of ${steps}: ${c.name} ${c.version}`);
        try {
          const r = await Api.search(c, s => { const w = $('#jobWait'); if (w) w.textContent = `Waiting for the NVD – continuing in ${s} s`; });
          let n = 0; r.items.forEach(it => { if (addFinding(p, it, c.id)) n++; });
          added += n; rows.push({ name: c.name + ' ' + c.version, total: r.total, n, capped: r.total > r.items.length });
        } catch (e) { rows.push({ name: c.name + ' ' + c.version, err: e.message }); }
        i++;
      }
      if (useTrivy && !job.cancelled) {
        setP(i, `${i + 1} of ${steps}: checking ${tv.length} ${pkgWord(tv.length)} with Trivy`);
        try {
          await Local.startScan('sbom', null, JSON.stringify(CDX.build(Object.assign({}, p, { components: tv }), false)));
          let st;
          do { await sleep(1500); if (job.cancelled) { await Local.cancelScan().catch(() => {}); break; } st = await Local.scanStatus(); const w = $('#jobWait'); if (w) w.textContent = `Trivy running for ${st.seconds} s`; } while (st.state === 'running');
          if (!job.cancelled) {
            if (st.state !== 'done') throw new Error((st.log || []).pop() || 'Trivy error');
            const r = parseSbom(await Local.scanResult(), 'trivy.cdx.json');
            const m = mergeImport(p, r, { onlyKnown: true });
            added += m.nv; rows.push({ name: `${tv.length} ${pkgWord(tv.length)} via Trivy`, total: r.vulns.length, n: m.nv });
          }
        } catch (e) { rows.push({ name: 'Software packages via Trivy', err: e.message }); }
      }
      const cancelled = job.cancelled;
      ui.job = null;
      save();
      if (cancelled) { render(); toast('Search cancelled – vulnerabilities already found have been added'); if (added) enrich(p, true); return; }
      setP(steps, 'Adding threat data (EPSS, actively exploited vulnerabilities) …');
      await enrich(p, true).catch(() => {});
    }
    render();
    const tvSkipped = tv.length && !Local.trivy;
    openModal(steps ? 'Search finished' : 'Automatic search not possible', `
      ${steps ? `<div class="callout ok"><strong>${added} new ${vulnWord(added)} added.</strong> ${p.findings.length} recorded in total now.</div>
      <div class="table-wrap"><table><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${r.err ? `<span class="badge hoch">Error</span> <span class="small">${esc(r.err)}</span>` : r.total ? `${r.total} known, ${r.n} newly added${r.capped ? ' (only the newest 500)' : ''}` : '<span class="muted">no known vulnerabilities</span>'}</td></tr>`).join('')}</tbody></table></div>` : ''}
      ${none.length ? `<div class="callout warn" style="margin-top:12px"><strong>${none.length} ${plural(none.length, 'component')} could not be checked automatically</strong> because no product with a version has been assigned yet. A click on “Assign” opens the product selection:
        <div class="dirlist" style="margin-top:8px;max-height:26vh">${none.slice(0, 40).map(c => `<button class="dir" data-action="comp-edit" data-id="${c.id}"><strong>${esc(c.name)} ${esc(c.version)}</strong><span class="muted small">Assign →</span></button>`).join('')}</div></div>` : ''}
      ${tvSkipped ? `<div class="callout warn" style="margin-top:12px">${tv.length} ${pkgWord(tv.length)} can only be checked with Trivy. That works on a Windows PC when the app was opened through the start file.</div>` : ''}
      ${!steps && !none.length && !tvSkipped ? '<p>No components have been recorded yet.</p>' : ''}
      <div class="row end" style="margin-top:14px">${steps ? '<button class="btn" data-action="tab" data-tab="cves">View vulnerabilities</button><button class="btn primary big" data-action="tab" data-tab="plan">Go to the action plan →</button>' : '<button class="btn" data-action="modal-close">Close</button>'}</div>`);
  }

  // ---------- Data operations ----------
  function addFinding(p, data, componentId) {
    if (p.findings.some(f => f.cve === data.cve && f.componentId === componentId)) return false;
    p.findings.push(Object.assign({ id: uid(), componentId, status: 'offen', mitigations: [], note: '', epss: null }, data));
    return true;
  }

  async function enrich(p, quiet) {
    const ids = [...new Set(p.findings.map(f => f.cve).filter(id => /^CVE-\d{4}-\d+$/i.test(id)))];
    if (!ids.length) return;
    const [ep, kev] = await Promise.all([Api.epss(ids), Api.kev().catch(() => null)]);
    p.findings.forEach(f => {
      if (ep[f.cve]) f.epss = ep[f.cve].epss;
      if (kev && kev.map[f.cve]) { f.kev = true; f.kevInfo = kev.map[f.cve]; }
    });
    save();
    if ($('#modal').hidden) render();
    if (!quiet) toast(`Threat data updated${kev ? ' (KEV catalogue ' + kev.version + ')' : ''}`);
  }

  async function fetchCves(btn) {
    const p = project();
    const ids = [...new Set(($('#cveIds').value.match(/CVE-\d{4}-\d{4,}/gi) || []).map(s => s.toUpperCase()))];
    if (!ids.length) return toast('No valid CVE number recognised (format: CVE-2024-12345)');
    const comp = $('#cveComp').value;
    btn.disabled = true;
    const st = $('#fetchStatus');
    let ok = 0; const errs = [];
    for (const [i, id] of ids.entries()) {
      st.textContent = `Loading ${id} (${i + 1}/${ids.length}) …`;
      try {
        const d = await Api.getCve(id, s => { st.textContent = `Waiting for the NVD – continuing in ${s} s …`; });
        if (addFinding(p, Object.assign(d, { source: 'NVD' }), comp)) ok++;
      } catch (e) { errs.push(id + ': ' + e.message); }
    }
    save();
    toast(`${ok} ${vulnWord(ok)} added${errs.length ? ' · ' + errs.length + ' ' + plural(errs.length, 'error') : ''}`);
    if (errs.length) setTimeout(() => alert(errs.join('\n')), 50);
    render();
    enrich(p, true);
  }

  function parseSbom(text, name) {
    const comps = [], vulns = [];
    const guessType = (t, n) => {
      const s = ((t || '') + ' ' + (n || '')).toLowerCase();
      if (/operating-system|windows|linux/.test(s)) return 'Betriebssystem';
      if (/firmware|device/.test(s)) return 'Firmware';
      if (/s7-|plc|sps|cpu/.test(s)) return 'SPS';
      if (/hmi|panel|wincc/.test(s)) return 'HMI';
      if (/library|framework/.test(s)) return 'Bibliothek';
      if (/application/.test(s)) return 'Anwendung';
      return 'Sonstiges';
    };
    // CSV: accept the internal (German) type keys as well as the English labels
    const typeKey = t => COMP_TYPES.includes(t) ? t : COMP_TYPES.find(k => TYPE_LABEL[k].toLowerCase() === String(t || '').toLowerCase());
    if (/\.csv$/i.test(name) || !/^\s*[{[]/.test(text)) {
      text.split(/\r?\n/).filter(l => l.trim()).forEach((l, i) => {
        const [n, v, ver, t, cpe] = l.split(/[;,\t]/).map(s => (s || '').trim().replace(/^"|"$/g, ''));
        if (i === 0 && /^name$/i.test(n)) return;
        if (n) comps.push({ name: n, vendor: v || '', version: ver || '', type: typeKey(t) || guessType(t, n), cpe: cpe || '' });
      });
      return { comps, vulns, format: 'CSV' };
    }
    const j = JSON.parse(text);
    if (j.bomFormat === 'CycloneDX' || j.components) {
      return Object.assign({ format: 'CycloneDX ' + (j.specVersion || '') }, CDX.parse(j, guessType));
    } else if (j.spdxVersion || j.packages) {
      (j.packages || []).forEach(pk => {
        const cpe = ((pk.externalRefs || []).find(r => /cpe23/i.test(r.referenceType)) || {}).referenceLocator || '';
        const purl = ((pk.externalRefs || []).find(r => /purl/i.test(r.referenceType)) || {}).referenceLocator || '';
        comps.push({ name: pk.name, vendor: (pk.supplier || '').replace(/^(Organization|Person):\s*/, ''), version: pk.versionInfo || '', type: guessType(pk.primaryPackagePurpose, pk.name), cpe, purl });
      });
      return { comps, vulns, format: 'SPDX ' + (j.spdxVersion || '') };
    } else throw new Error('Unknown file format – expected CycloneDX (JSON), SPDX (JSON) or CSV.');
  }

  /** Analyse the import first and show a summary, then add it */
  let pendingImport = null;
  function importSbom(text, name, tip) {
    const p = project();
    const r = parseSbom(text, name);
    if (!r.comps.length) {
      return openModal('Nothing found', `<p>${r.isTrivy ? 'Trivy did not detect any software packages in this target.' : 'The file contains no components.'}</p>${tip ? `<p class="small muted">${esc(tip)}</p>` : ''}
        <div class="row end">${r.isTrivy && Local.trivy ? '<button class="btn" data-action="scan-open">Scan another folder</button>' : ''}<button class="btn primary" data-action="modal-close">Close</button></div>`);
    }
    const affectedRefs = new Set(r.vulns.map(v => v.ref));
    const sev = { krit: 0, hoch: 0, mittel: 0, niedrig: 0 };
    r.vulns.forEach(v => { const s = v.cvss ? v.cvss.score : 0; sev[s >= 9 ? 'krit' : s >= 7 ? 'hoch' : s >= 4 ? 'mittel' : 'niedrig']++; });
    const nAff = r.comps.filter(c => affectedRefs.has(c.ref)).length;
    const nNb = r.vulns.filter(v => v.status === 'nb').length;
    pendingImport = r;
    openModal(r.isTrivy ? 'Add scan result' : 'Add file', `
      <p><span class="badge outline">${esc(r.format || 'CSV')}</span> ${r.isTrivy ? '<span class="badge" style="background:var(--accent);color:#fff">Trivy</span>' : ''} ${r.tool ? `<span class="muted small">created with ${esc(r.tool)}</span>` : ''}</p>
      ${r.target ? `<p class="small muted" style="word-break:break-all">Scan target: <code>${esc(r.target)}</code></p>` : ''}
      <div class="grid kpi" style="margin:12px 0">
        <div class="kpi-tile"><div class="v">${r.comps.length}</div><div class="l">components</div></div>
        <div class="kpi-tile"><div class="v">${nAff}</div><div class="l">of them with vulnerabilities</div></div>
        <div class="kpi-tile"><div class="v">${r.vulns.length}</div><div class="l">vulnerabilities</div></div>
      </div>
      ${r.vulns.length ? `<p class="small">Severity (CVSS): <span class="badge krit">${sev.krit} critical</span> <span class="badge hoch">${sev.hoch} high</span> <span class="badge mittel">${sev.mittel} medium</span> <span class="badge niedrig">${sev.niedrig} low</span>${nNb ? ` · ${nNb} not affected according to the file` : ''}</p>` : `<p class="small muted">The file contains components only, no vulnerabilities. After adding it, “Search for vulnerabilities now” looks for them.</p>`}
      <form id="importForm" class="grid" style="gap:12px;margin-top:12px">
        <label class="check"><input type="checkbox" name="onlyAffected" ${r.isTrivy && r.comps.length > 20 ? 'checked' : ''} ${nAff ? '' : 'disabled'}><span><strong>Add only components with vulnerabilities</strong><br><span class="muted small">Recommended for large scans so the component list stays manageable</span></span></label>
        <label class="field">Belongs to device <span class="hint">optional, e.g. the operator IPC the software runs on</span>
          <select name="parentId"><option value="">– not assigned –</option>${p.components.filter(c => !c.parentId).map(c => `<option value="${c.id}">${esc(c.name)} ${esc(c.version)}</option>`).join('')}</select></label>
        <div class="row end"><button type="button" class="btn" data-action="modal-close">Cancel</button><button class="btn primary big">Add</button></div>
      </form>`);
  }

  /** Adds parsed components/vulnerabilities to the project. onlyKnown: do not create new components (re-scan). */
  function mergeImport(p, r, opts) {
    const affectedRefs = new Set(r.vulns.map(v => v.ref));
    const comps = opts.onlyAffected ? r.comps.filter(c => affectedRefs.has(c.ref)) : r.comps;
    const refMap = {};
    let nc = 0, nv = 0;
    comps.forEach(c => {
      const existing = p.components.find(x => c.ref && x.id === c.ref)
        || p.components.find(x => (c.purl && x.purl === c.purl) || (x.name === c.name && x.version === c.version && (x.parentId || '') === (opts.parentId || '')));
      if (!existing && opts.onlyKnown) return;
      const id = existing ? existing.id : uid();
      if (!existing) { p.components.push({ id, name: c.name, vendor: c.vendor, version: c.version, type: c.type, cpe: c.cpe || '', purl: c.purl || '', parentId: opts.parentId || '', pkgType: c.pkgType || '' }); nc++; }
      if (c.ref) refMap[c.ref] = id;
    });
    r.vulns.forEach(v => {
      const ref = v.ref; const data = Object.assign({}, v); delete data.ref;
      if (ref && !refMap[ref]) return; // component was not added
      if (addFinding(p, data, refMap[ref] || '')) nv++;
    });
    return { nc, nv };
  }

  function applyImport(opts) {
    const p = project(), r = pendingImport;
    if (!r) return;
    const m = mergeImport(p, r, opts);
    pendingImport = null;
    save(); closeModal(); render();
    toast(`${m.nc} new ${plural(m.nc, 'component')}, ${m.nv} ${vulnWord(m.nv)} added`);
    if (m.nv) enrich(p, true);
  }

  function exportCdx(p, withVulns) {
    const bom = CDX.build(p, withVulns, f => evaluate(p, f));
    download(fileSafe(p.name) + (withVulns ? '_sbom-vex' : '_sbom') + '.cdx.json', JSON.stringify(bom, null, 2), 'application/vnd.cyclonedx+json');
    closeModal();
    toast(`CycloneDX ${bom.specVersion} saved (${bom.components.length} components${withVulns ? ', ' + bom.vulnerabilities.length + ' vulnerabilities' : ''})`);
  }

  function exportDialog() {
    openModal('Export in CycloneDX format', `
      <div class="menu-list">
        <button class="btn" data-action="cdx-sbom"><strong>Bill of materials (SBOM)</strong>&nbsp;– components only</button>
        <button class="btn" data-action="cdx-vex"><strong>Bill of materials + VEX</strong>&nbsp;– plus vulnerabilities, status, rating and measures</button>
      </div>
      <p class="small muted" style="margin-top:12px">CycloneDX 1.6 (JSON) is a widely used standard format for software bills of materials. Both files can be imported here again; the bill of materials can also be read by Trivy and other tools.</p>`);
  }

  function download(name, content, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const fileSafe = s => s.replace(/[^\w\-äöüÄÖÜß]+/g, '_');

  function exportCsv(p) {
    const head = ['CVE', 'Component', 'Version', 'CVSS', 'Vector', 'CWE', 'Actively exploited (KEV)', 'EPSS', 'L', 'I', 'Risk', 'Level', 'Residual', 'Residual level', 'Acceptance reachable', 'Status', 'Selected measures', 'Recommended measures', 'Note'];
    const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const title = id => (MITIGATIONS.find(m => m.id === id) || {}).title || id;
    const REACH = { now: 'yes, with immediate measures', later: 'only after patch/replacement', none: 'no – decision needed' };
    const rows = p.findings.map(f => {
      const e = evaluate(p, f);
      return [f.cve, e.comp?.name, e.comp?.version, f.cvss?.score, f.cvss?.vector, (f.cwe || []).join(' '), yesNo(f.kev), f.epss != null ? (f.epss * 100).toFixed(2) + '%' : '',
        e.base.L, e.base.I, e.base.score, e.base.level.label, e.res.score, e.res.eliminated ? 'fixed' : e.res.level.label, REACH[e.reach], STATUS[f.status || 'offen'],
        (f.mitigations || []).map(title).join(' | '), e.rec.map(title).join(' | '), f.note].map(q).join(',');
    });
    download(fileSafe(p.name) + '_risk-analysis.csv', '﻿' + [head.map(q).join(','), ...rows].join('\r\n'), 'text/csv;charset=utf-8');
  }

  function pickFile(accept, cb) {
    const inp = $('#fileInput');
    inp.value = ''; inp.accept = accept;
    inp.onchange = () => { const f = inp.files[0]; if (!f) return; const r = new FileReader(); r.onload = () => cb(r.result, f.name); r.readAsText(f); };
    inp.click();
  }

  function loadDemo() {
    const d = window.DEMO_PROJECT;
    if (!d) return toast('Demo data missing');
    const p = JSON.parse(JSON.stringify(d));
    p.id = uid(); p.created = new Date().toISOString();
    state.projects.push(p); state.currentId = p.id; save();
    ui.tab = 'cves'; closeModal(); render();
    toast('Example loaded');
    enrich(p, true);
  }

  function importJson(txt) {
    const o = JSON.parse(txt);
    const list = o.projects ? o.projects : (o.findings && o.components) ? [o] : null;
    if (!list) throw new Error('The file is neither a backup nor an analysis of this app.');
    let n = 0;
    list.forEach(np => {
      np.ctx = Object.assign(defaultCtx(), np.ctx);
      const i = state.projects.findIndex(x => x.id === np.id);
      if (o.projects && i >= 0) state.projects[i] = np; // backup: replace the same analysis
      else { if (i >= 0) np.id = uid(); state.projects.push(np); }
      state.currentId = np.id; n++;
    });
    save(); closeModal(); render(); toast(`${n} ${plural(n, 'analysis', 'analyses')} loaded`);
  }

  // ---------- Events ----------
  document.addEventListener('click', async e => {
    const t = e.target.closest('[data-action]');
    if (!t) return;
    const a = t.dataset.action;
    const p = project();
    const fid = t.closest('[data-fid]')?.dataset.fid;
    switch (a) {
      case 'tab': closeModal(); ui.tab = t.dataset.tab; ui.limit = PAGE; render(); window.scrollTo(0, 0); break;
      case 'project-new': projectForm(); break;
      case 'preset': Object.assign(p.ctx, PRESETS[t.dataset.k].ctx); save(); render(); break;
      case 'menu': menu(); break;
      case 'modal-close': closeModal(); break;
      case 'demo': loadDemo(); break;
      case 'comp-edit': compForm(p.components.find(c => c.id === t.dataset.id)); break;
      case 'comp-del': {
        const c = p.components.find(x => x.id === t.dataset.id);
        const n = p.findings.filter(f => f.componentId === c.id).length;
        if (confirm(`Delete “${c.name}”?${n ? ` ${n} assigned ${vulnWord(n)} will be removed as well.` : ''}`)) {
          p.components = p.components.filter(x => x.id !== c.id); p.components.forEach(x => { if (x.parentId === c.id) x.parentId = ''; }); p.findings = p.findings.filter(f => f.componentId !== c.id); save(); render();
        }
        break;
      }
      case 'prod-search': prodSearch(); break;
      case 'prod-pick': prodPick(+t.dataset.i); break;
      case 'prod-clear': { const f = $('#compForm').elements; f.cpeKey.value = ''; f.cpe.value = ''; f.product.value = ''; ui.prodVersions = null; $('#verList').innerHTML = ''; $('#prodChosen').innerHTML = assignedHtml(''); break; }
      case 'comp-search': compSearch(p.components.find(c => c.id === t.dataset.id)); break;
      case 'auto-check': autoCheck(); break;
      case 'sel-all': case 'sel-none': document.querySelectorAll('#modalBody input[data-cve]:not(:disabled)').forEach(i => { i.checked = a === 'sel-all'; }); break;
      case 'search-take': {
        const items = $('#modalBody')._items || [];
        const sel = [...document.querySelectorAll('#modalBody input[data-cve]:checked')].map(i => i.dataset.cve);
        let n = 0; items.filter(it => sel.includes(it.cve)).forEach(it => { if (addFinding(p, it, t.dataset.id)) n++; });
        save(); closeModal(); render(); toast(`${n} ${vulnWord(n)} added`); enrich(p, true);
        break;
      }
      case 'sbom-import': pickFile('.json,.csv,.cdx,.txt', (txt, name) => { try { importSbom(txt, name); } catch (err) { alert('Import not possible: ' + err.message); } }); break;
      case 'scan-open': scanOpen(); break;
      case 'scan-tab': ui.scan.tab = t.dataset.t; renderScan(); break;
      case 'scan-dir': if (t.dataset.path) scanNavigate(t.dataset.path); break;
      case 'scan-start': scanStart(); break;
      case 'cdx-export': exportDialog(); break;
      case 'cdx-sbom': exportCdx(p, false); break;
      case 'cdx-vex': exportCdx(p, true); break;
      case 'copy': navigator.clipboard?.writeText(t.dataset.text).then(() => toast('Command copied'), () => toast('Copying not possible')); break;
      case 'cve-fetch': fetchCves(t); break;
      case 'cve-manual': manualForm(); break;
      case 'enrich': t.disabled = true; await enrich(p).catch(err => toast(err.message)); t.disabled = false; break;
      case 'rec-apply': { const f = p.findings.find(x => x.id === fid); f.mitigations = [...evaluate(p, f).rec]; if (f.status === 'offen') f.status = 'umsetzung'; save(); render(); break; }
      case 'rec-all': {
        const todo = p.findings.filter(isOpenItem);
        const has = todo.filter(f => (f.mitigations || []).length).length;
        if (has && !confirm(`A selection has already been made for ${has} ${vulnWord(has)}. Replace it with the recommendation?`)) break;
        todo.forEach(f => { f.mitigations = [...evaluate(p, f).rec]; if (f.status === 'offen') f.status = 'umsetzung'; });
        save(); render(); toast(`Recommendations applied for ${todo.length} ${vulnWord(todo.length)}`); break;
      }
      case 'finding-del': if (confirm('Remove this vulnerability?')) { p.findings = p.findings.filter(f => f.id !== fid); save(); render(); } break;
      case 'more': ui.limit += PAGE; render(); break;
      case 'cell': ui.cell = [+t.dataset.l, +t.dataset.i]; ui.tab = 'cves'; ui.limit = PAGE; render(); window.scrollTo(0, 0); break;
      case 'cell-clear': e.preventDefault(); ui.cell = null; render(); break;
      case 'mmode': ui.matrixMode = t.dataset.m; render(); break;
      case 'psrc': ui.planSource = t.dataset.s; render(); break;
      case 'print': window.print(); break;
      case 'csv': exportCsv(p); break;
      case 'export-json': download(fileSafe(p.name) + '.otrisk.json', JSON.stringify(p, null, 2), 'application/json'); closeModal(); break;
      case 'backup-all': download('OT-Risk-Analysis_backup_' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(state, null, 2), 'application/json'); closeModal(); toast('Backup saved (“Downloads” folder)'); break;
      case 'import-json': pickFile('.json', txt => { try { importJson(txt); } catch (err) { alert('Loading not possible: ' + err.message); } }); break;
      case 'project-dup': { const np = JSON.parse(JSON.stringify(p)); np.id = uid(); np.name += ' (copy)'; state.projects.push(np); state.currentId = np.id; save(); closeModal(); render(); break; }
      case 'project-del':
        if (p && confirm(`Permanently delete the analysis “${p.name}”? This cannot be undone.`)) {
          state.projects = state.projects.filter(x => x.id !== p.id); state.currentId = state.projects[0]?.id || null; save(); closeModal(); render();
        }
        break;
      case 'wipe':
        if (confirm(`Really delete ALL ${state.projects.length} ${plural(state.projects.length, 'analysis', 'analyses')} on this device? This cannot be undone. Tip: use “Save a backup” first.`)) {
          state = { projects: [], currentId: null };
          try { localStorage.removeItem('otr.kev'); } catch (err) { /* ignore */ }
          save(); ui.tab = 'kontext'; closeModal(); render(); toast('All data deleted');
        }
        break;
    }
  });

  // Build the details of a vulnerability only when it is expanded (fast even with hundreds of entries)
  document.addEventListener('toggle', e => {
    const d = e.target;
    if (!(d.matches && d.matches('details[data-fid]'))) return;
    const id = d.dataset.fid;
    if (!d.open) { ui.open.delete(id); return; }
    ui.open.add(id);
    const body = d.querySelector('.body');
    if (!body.innerHTML.trim()) { const p = project(); const f = p.findings.find(x => x.id === id); if (f) body.innerHTML = findingBody(p, f, evaluate(p, f)); }
  }, true);

  document.addEventListener('submit', e => {
    e.preventDefault();
    const p = project();
    const fd = Object.fromEntries(new FormData(e.target));
    const formId = e.target.getAttribute('id'); // not e.target.id: a field named "id" would shadow it
    if (formId === 'projForm') {
      newProject(fd.name.trim(), fd.machine.trim(), fd.preset);
      ui.tab = 'sbom'; closeModal(); render();
      toast('Analysis created – now add components');
    } else if (formId === 'compForm') {
      delete fd.cpeKey;
      fd.cpe = (fd.cpe || '').trim(); fd.purl = (fd.purl || '').trim();
      if (fd.id) Object.assign(p.components.find(c => c.id === fd.id), fd);
      else p.components.push(Object.assign(fd, { id: uid() }));
      save(); closeModal(); render();
    } else if (formId === 'importForm') {
      applyImport({ onlyAffected: !!fd.onlyAffected, parentId: fd.parentId || '' });
    } else if (formId === 'manualForm') {
      const score = parseFloat(String(fd.score).replace(',', '.'));
      const ok = addFinding(p, {
        cve: fd.cve.trim(), description: fd.description, cwe: fd.cwe ? fd.cwe.split(/[,\s]+/).filter(Boolean).map(s => s.toUpperCase()) : [],
        cvss: (fd.vector || !isNaN(score)) ? { score: isNaN(score) ? null : score, vector: fd.vector.trim(), version: '' } : null,
        patchAvailable: !!fd.patch, references: [], kev: false, source: 'manual'
      }, fd.componentId);
      if (!ok) return toast('Already exists');
      save(); closeModal(); render(); enrich(p, true);
    }
  });

  document.addEventListener('change', e => {
    const t = e.target;
    const p = project();
    if (t.id === 'projectSelect') { state.currentId = t.value; ui.cell = null; ui.limit = PAGE; save(); render(); return; }
    if (t.name === 'scanMode' && ui.scan) { ui.scan.mode = t.value; ui.scan.modeTouched = true; return; }
    if (!p) return;
    if (t.dataset.ctx) { p.ctx[t.dataset.ctx] = t.type === 'checkbox' ? t.checked : +t.value; save(); render(); return; }
    const fid = t.closest('[data-fid]')?.dataset.fid;
    const f = fid && p.findings.find(x => x.id === fid);
    if (!f) return;
    if (t.dataset.mit) {
      const s = new Set(f.mitigations || []); t.checked ? s.add(t.dataset.mit) : s.delete(t.dataset.mit); f.mitigations = [...s];
    } else if (t.dataset.f) {
      f[t.dataset.f] = t.type === 'checkbox' ? t.checked : t.value;
    }
    save(); render();
  });

  document.addEventListener('input', e => {
    const t = e.target, p = project();
    if (t.dataset.bind && p) { p[t.dataset.bind] = t.value; save(); if (t.dataset.bind === 'name') { const o = $('#projectSelect').selectedOptions[0]; if (o) o.textContent = t.value; } }
    if (t.id === 'filter') {
      ui.filter = t.value; ui.limit = PAGE; const pos = t.selectionStart; render();
      const f = $('#filter'); f.focus(); f.setSelectionRange(pos, pos);
    }
    if (t.name === 'version' && t.form && t.form.getAttribute('id') === 'compForm') syncCpe(t.form);
  });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !$('#modal').hidden) closeModal();
    if (e.key === 'Enter' && e.target.id === 'prodQ') { e.preventDefault(); prodSearch(); }
    if (e.key === 'Enter' && e.target.id === 'scanImage') { e.preventDefault(); scanStart(); }
  });

  $('#tabs').addEventListener('click', e => { const b = e.target.closest('button[data-tab]'); if (b) { ui.tab = b.dataset.tab; ui.limit = PAGE; if (b.dataset.tab !== 'cves') ui.cell = null; render(); } });
  $('#modal').addEventListener('click', e => { if (e.target.id === 'modal' && !ui.job) closeModal(); });
  window.addEventListener('resize', () => document.documentElement.style.setProperty('--topbar-h', $('.topbar').offsetHeight + 'px'));
  window.addEventListener('beforeprint', () => { if (ui.tab !== 'plan') { ui.tab = 'plan'; render(); } });

  // ---------- Start ----------
  async function init() {
    if (!state.currentId && state.projects.length) state.currentId = state.projects[0].id;
    render();
    const HAD = 'otr.hadLocal';
    if (!(await Local.detect())) {
      try { if (localStorage.getItem(HAD)) { ui.noHelper = true; render(); } } catch (e) { /* ignore */ }
      return;
    }
    {
      try { localStorage.setItem(HAD, '1'); } catch (e) { /* ignore */ }
      try {
        const srv = await Local.loadData();
        if (srv && srv.projects && (srv.savedAt || 0) > (state.savedAt || 0)) {
          state = srv; // the file on the PC is newer (e.g. browser data was cleared)
          try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { /* full */ }
          if (!project()) state.currentId = state.projects[0]?.id || null;
        } else if (state.projects.length && (!srv || (state.savedAt || 0) > (srv.savedAt || 0))) {
          Local.saveData(JSON.stringify(state)).catch(() => {});
        }
      } catch (e) { /* file does not exist yet */ }
      render();
    }
  }
  init();

  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
