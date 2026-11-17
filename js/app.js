/* OT-Risikoanalyse – Oberfläche & Zustand.
 * Daten liegen im Browser (localStorage) und – wenn die App über die Start-Datei läuft – zusätzlich als Datei auf dem PC. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => Math.random().toString(36).slice(2, 10);
  const fmtDate = d => d ? new Date(d).toLocaleDateString('de-DE') : '–';
  const pct = e => e >= 0.999 ? '> 99,9 %' : (e * 100).toFixed(1).replace('.', ',') + ' %';
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const STORE = 'otr.state.v1';
  const COMP_TYPES = ['SPS', 'HMI', 'IPC', 'Betriebssystem', 'Firmware', 'Antrieb', 'Netzwerk', 'Bibliothek', 'Anwendung', 'Sonstiges'];
  const STATUS = { offen: 'Offen', umsetzung: 'In Umsetzung', mitigiert: 'Mitigiert', akzeptiert: 'Risiko akzeptiert', nb: 'Nicht betroffen' };
  const LEVELS = [{ key: 'krit', label: 'Kritisch' }, { key: 'hoch', label: 'Hoch' }, { key: 'mittel', label: 'Mittel' }, { key: 'niedrig', label: 'Niedrig' }];
  const PAGE = 100;

  const PRESETS = {
    isoliert: { label: 'Eigenständige Maschine ohne Netzwerk', hint: 'Kein Anschluss an Firmen- oder Produktionsnetz, keine Fernwartung', ctx: { exposure: 1, remoteAccess: false } },
    vernetzt: { label: 'Maschine im Produktionsnetz mit Fernwartung', hint: 'Der häufigste Fall: Netzwerk-/MES-Anbindung, Service per Fernzugriff', ctx: { exposure: 3, remoteAccess: true } },
    cloud: { label: 'Maschine mit Internet- oder Cloud-Anbindung', hint: 'Daten gehen in eine Cloud oder die Maschine ist von außen erreichbar', ctx: { exposure: 4, remoteAccess: true } }
  };
  const defaultCtx = () => ({ exposure: 3, remoteAccess: true, physical: 2, safety: 2, availability: 3, confidentiality: 2, slT: 2, patchable: false, acceptance: 4 });

  let state = load();
  let ui = { tab: 'kontext', matrixMode: 'vorher', cell: null, filter: '', open: new Set(), limit: PAGE, job: null, scan: null, prodVersions: null };

  function load() {
    try { const s = JSON.parse(localStorage.getItem(STORE)); if (s && s.projects) return s; } catch (e) { /* leer */ }
    return { projects: [], currentId: null };
  }
  let saveT;
  function save() {
    state.savedAt = Date.now();
    try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { toast('Speichern im Browser fehlgeschlagen: ' + e.message); }
    if (Local.available) {
      clearTimeout(saveT);
      saveT = setTimeout(() => Local.saveData(JSON.stringify(state)).catch(() => toast('Sicherung als Datei fehlgeschlagen – ist das Startfenster noch offen?')), 700);
    }
  }
  const project = () => state.projects.find(p => p.id === state.currentId);

  function newProject(name, machine, preset) {
    const ctx = Object.assign(defaultCtx(), (PRESETS[preset] || {}).ctx);
    const p = { id: uid(), name: name || 'Neue Maschine', machine: machine || '', customer: '', description: '', created: new Date().toISOString(), ctx, components: [], findings: [] };
    state.projects.push(p); state.currentId = p.id; save(); return p;
  }

  // ---------- Bewertung ----------
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
      recRes: Risk.residual(f, p.ctx, base, r.all),       // nach vollständiger Umsetzung (inkl. Patch/Austausch)
      recResNow: Risk.residual(f, p.ctx, base, r.now),    // nach den Sofortmaßnahmen
      over: res.score > p.ctx.acceptance
    };
  }

  /** Kleinste Maßnahmenkombination bis Restrisiko ≤ Akzeptanzschwelle.
   *  reach: 'now'   = mit Sofortmaßnahmen erreicht
   *         'later' = erst mit Patch/Austausch erreicht
   *         'none'  = mit dem Katalog nicht erreichbar → Entscheidung nötig */
  function recommend(p, f, base, options) {
    const target = p.ctx.acceptance;
    const now = [];
    if (f.kev) now.push('kev');
    let cur = Risk.residual(f, p.ctx, base, now).score;
    // Patch nur als Sofortmaßnahme, wenn er zeitnah einspielbar ist; Austausch ist nie Sofortmaßnahme
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
      if (!best) break; // keine weitere Maßnahme senkt das Risiko
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
  /** Wie lässt sich eine Komponente automatisch prüfen? */
  const checkKind = c => Api.isPrecise(c.cpe) ? 'nvd' : c.purl ? 'trivy' : 'none';
  const prettyCpe = cpe => { const p = Api.cpeParts(cpe); return [p[3], p[4]].filter(Boolean).join(' ').replace(/\\/g, '').replace(/_/g, ' '); };

  // ---------- Rendering ----------
  function render() {
    const sel = $('#projectSelect');
    sel.innerHTML = state.projects.map(p => `<option value="${p.id}" ${p.id === state.currentId ? 'selected' : ''}>${esc(p.name)}</option>`).join('') || '<option>– noch keine Analyse –</option>';
    document.querySelectorAll('#tabs button').forEach(b => b.setAttribute('aria-selected', b.dataset.tab === ui.tab));
    document.documentElement.style.setProperty('--topbar-h', $('.topbar').offsetHeight + 'px');
    const p = project();
    $('#tabs').hidden = !p;
    const v = $('#view');
    // App wurde früher über die Start-Datei benutzt, der Helfer läuft aber gerade nicht (Startfenster geschlossen)
    const banner = ui.noHelper ? '<div class="callout warn no-print"><strong>Das Startfenster ist geschlossen.</strong> Bitte „OT-Risikoanalyse starten“ erneut doppelklicken und diese Seite neu laden. Bis dahin sind „Software scannen“ und die Sicherung als Datei nicht verfügbar; deine Eingaben bleiben im Browser erhalten.</div>' : '';
    if (!p) { v.innerHTML = banner + viewWelcome(); return; }
    v.innerHTML = banner + { kontext: viewContext, sbom: viewSbom, cves: viewCves, matrix: viewMatrix, plan: viewPlan }[ui.tab](p);
  }

  function storageNote() {
    return Local.available
      ? `Deine Daten werden automatisch gespeichert – im Browser und als Datei auf diesem PC: <code>${esc(Local.dataFile)}</code>`
      : 'Deine Daten werden automatisch in diesem Browser auf diesem Gerät gespeichert. Lege über „⋯“ regelmäßig eine Sicherung an.';
  }

  function viewWelcome() {
    return `<div class="card hero">
      <h2>Willkommen zur OT-Risikoanalyse</h2>
      <p>In fünf Schritten von der Komponentenliste einer Maschine zum fertigen Maßnahmenplan: Komponenten erfassen, bekannte Schwachstellen (CVEs) automatisch suchen, Risiko im Maschinenkontext bewerten, Maßnahmen nach IEC 62443 erhalten.</p>
      <div class="choice-grid">
        <button class="choice main" data-action="project-new"><strong>Neue Analyse starten</strong><span>Maschine anlegen und loslegen</span></button>
        <button class="choice" data-action="demo"><strong>Beispiel ansehen</strong><span>Fertig ausgefüllte Demo-Maschine zum Ausprobieren</span></button>
        <a class="choice" href="anleitung.html" target="_blank" rel="noopener"><strong>Anleitung öffnen</strong><span>Schritt für Schritt erklärt</span></a>
      </div>
      <p class="small muted" style="margin-top:16px">${storageNote()}</p>
      <p class="small muted">Arbeitshilfe ohne Gewähr; ersetzt keine fachliche Prüfung. Dieses Produkt nutzt die NVD-API, ist aber nicht von der NVD empfohlen oder zertifiziert. <a href="rechtliches.html" target="_blank" rel="noopener">Datenschutz und rechtliche Hinweise</a></p>
    </div>`;
  }

  function opt(val, cur, label) { return `<option value="${val}" ${String(val) === String(cur) ? 'selected' : ''}>${esc(label)}</option>`; }

  function viewContext(p) {
    const c = p.ctx;
    return `
    <div class="card">
      <h2>Schnellauswahl: Wie ist die Maschine angebunden?</h2>
      <div class="choice-grid">${Object.entries(PRESETS).map(([k, pr]) => {
        const on = pr.ctx.exposure === c.exposure && pr.ctx.remoteAccess === c.remoteAccess;
        return `<button class="choice ${on ? 'on' : ''}" data-action="preset" data-k="${k}"><strong>${on ? '✓ ' : ''}${esc(pr.label)}</strong><span>${esc(pr.hint)}</span></button>`;
      }).join('')}</div>
      <p class="small muted" style="margin-top:10px">Die Auswahl setzt Netzexposition und Fernwartung. Alle Angaben lassen sich unten verfeinern – Änderungen wirken sofort auf die Bewertung aller Schwachstellen.</p>
    </div>
    <div class="card">
      <h2>Projekt & Maschine</h2>
      <div class="grid two">
        <label class="field">Projektname<input data-bind="name" value="${esc(p.name)}"></label>
        <label class="field">Maschine / Anlage <span class="hint">Typ, Seriennummer, Baujahr</span><input data-bind="machine" value="${esc(p.machine)}"></label>
        <label class="field">Kunde / Standort<input data-bind="customer" value="${esc(p.customer)}"></label>
        <label class="field">Bearbeiter<input data-bind="author" value="${esc(p.author || '')}"></label>
      </div>
      <label class="field" style="margin-top:14px">Beschreibung / Systemgrenze<textarea data-bind="description">${esc(p.description)}</textarea></label>
    </div>
    <div class="card">
      <h2>Einsatzkontext im Detail</h2>
      <div class="grid two">
        <label class="field">Netzexposition der Maschine<span class="hint">Wie weit ist die Maschine netzseitig erreichbar?</span>
          <select data-ctx="exposure">${[1, 2, 3, 4].map(i => opt(i, c.exposure, Risk.EXPOSURE[i])).join('')}</select></label>
        <label class="field">Physischer Zugang<span class="hint">Wer kommt an Schaltschrank, USB, Netzwerkports?</span>
          <select data-ctx="physical">${[1, 2, 3].map(i => opt(i, c.physical, Risk.PHYSICAL[i])).join('')}</select></label>
        <label class="field">Safety-Relevanz<span class="hint">Gefährdung von Personen bei Manipulation</span>
          <select data-ctx="safety">${opt(1, c.safety, 'gering')}${opt(2, c.safety, 'mittel – Verletzung möglich')}${opt(3, c.safety, 'hoch – schwere Verletzung möglich')}</select></label>
        <label class="field">Verfügbarkeitsanforderung<span class="hint">Folgen eines Maschinenstillstands</span>
          <select data-ctx="availability">${opt(1, c.availability, 'gering')}${opt(2, c.availability, 'mittel')}${opt(3, c.availability, 'hoch – Engpassmaschine / Linienstillstand')}</select></label>
        <label class="field">Schutzbedarf Vertraulichkeit<span class="hint">Rezepturen, Prozess-Know-how, Programme</span>
          <select data-ctx="confidentiality">${opt(1, c.confidentiality, 'gering')}${opt(2, c.confidentiality, 'mittel')}${opt(3, c.confidentiality, 'hoch')}</select></label>
        <label class="field">Ziel-Security-Level (SL-T) nach IEC 62443-3-3
          <select data-ctx="slT">${opt(1, c.slT, 'SL 1 – Schutz gegen zufällige Fehlhandlung')}${opt(2, c.slT, 'SL 2 – einfache Mittel, geringe Motivation')}${opt(3, c.slT, 'SL 3 – erweiterte Mittel, IACS-Kenntnisse')}${opt(4, c.slT, 'SL 4 – umfangreiche Ressourcen')}</select></label>
        <label class="field">Risikoakzeptanz<span class="hint">Bis zu welchem Risikowert (Wahrscheinlichkeit × Auswirkung) gilt ein Risiko als tragbar?</span>
          <select data-ctx="acceptance">${opt(4, c.acceptance, '≤ 4 (nur „Niedrig“ akzeptiert) – empfohlen')}${opt(6, c.acceptance, '≤ 6')}${opt(9, c.acceptance, '≤ 9 („Mittel“ akzeptiert)')}</select></label>
      </div>
      <div class="grid two" style="margin-top:14px">
        <label class="check"><input type="checkbox" data-ctx="remoteAccess" ${c.remoteAccess ? 'checked' : ''}><span><strong>Fernwartungszugang vorhanden</strong><br><span class="muted small">Router/VPN für den Service des Maschinenherstellers</span></span></label>
        <label class="check"><input type="checkbox" data-ctx="patchable" ${c.patchable ? 'checked' : ''}><span><strong>Patches zeitnah einspielbar</strong><br><span class="muted small">Ohne Haken (in der Produktion üblich) empfiehlt die App zuerst Sofortmaßnahmen und plant den Patch fürs nächste Wartungsfenster</span></span></label>
      </div>
    </div>
    <div class="row end"><button class="btn primary big" data-action="tab" data-tab="sbom">Weiter zu Schritt 2: Komponenten →</button></div>`;
  }

  function viewSbom(p) {
    const kinds = { nvd: 0, trivy: 0, none: 0 };
    const rows = p.components.map(c => {
      const n = p.findings.filter(f => f.componentId === c.id && f.status !== 'nb').length;
      const k = checkKind(c); kinds[k]++;
      const chk = k === 'nvd' ? '<span class="badge niedrig" title="Wird versionsgenau in der NVD geprüft">✓ automatisch prüfbar</span>'
        : k === 'trivy' ? `<span class="badge niedrig" title="Software-Paket: wird mit Trivy geprüft">✓ ${Local.trivy ? 'automatisch prüfbar' : 'per Trivy-Scan'}</span>`
          : `<button class="btn small" data-action="comp-edit" data-id="${c.id}" title="Produkt aus der NVD-Produktliste wählen, damit automatisch geprüft werden kann">Produkt zuordnen</button>`;
      return `<tr>
        <td><strong>${esc(c.name)}</strong><div class="muted small">${esc(c.vendor)}${c.pkgType ? ' · ' + esc(c.pkgType) : ''}${c.parentId ? ' · in ' + esc((p.components.find(x => x.id === c.parentId) || {}).name || '?') : ''}</div></td>
        <td>${esc(c.version)}</td>
        <td class="hide-sm">${esc(c.type)}</td>
        <td>${chk}</td>
        <td>${n ? `<span class="badge">${n}</span>` : '<span class="muted">0</span>'}</td>
        <td><div class="row" style="justify-content:flex-end;gap:6px;flex-wrap:nowrap">
          <button class="btn small" data-action="comp-search" data-id="${c.id}" title="Einzeln in der NVD suchen und Treffer auswählen">Suchen</button>
          <button class="btn small" data-action="comp-edit" data-id="${c.id}">Bearbeiten</button>
          <button class="btn small danger" data-action="comp-del" data-id="${c.id}" aria-label="Löschen">✕</button></div></td>
      </tr>`;
    }).join('');
    return `
    <div class="card">
      <h2>Komponenten hinzufügen</h2>
      <div class="choice-grid">
        <button class="choice" data-action="comp-edit"><strong>Gerät hinzufügen</strong><span>SPS, HMI, Antrieb, Switch, Betriebssystem … einfach aus der Produktliste wählen</span></button>
        <button class="choice" data-action="scan-open"><strong>Software scannen</strong><span>${Local.trivy ? 'Trivy durchsucht einen Ordner auf diesem PC nach Software-Paketen und Schwachstellen' : 'Software-Pakete mit Trivy erfassen (nur am PC mit der Start-Datei)'}</span></button>
        <button class="choice" data-action="sbom-import"><strong>Datei importieren</strong><span>Stückliste (SBOM) im CycloneDX-Format oder ein Trivy-Ergebnis laden</span></button>
      </div>
    </div>
    <div class="card">
      <div class="row"><h2 style="margin:0">Komponentenliste (${p.components.length})</h2><span class="spacer"></span>
        <button class="btn" data-action="cdx-export" ${p.components.length ? '' : 'disabled'}>Export (CycloneDX)</button></div>
      ${p.components.length ? `<div class="table-wrap" style="margin-top:10px"><table><thead><tr><th>Komponente</th><th>Version</th><th class="hide-sm">Typ</th><th>Prüfung</th><th>CVEs</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>
        ${kinds.none ? `<p class="small muted" style="margin-top:10px">${kinds.none} Komponente(n) lassen sich noch nicht automatisch prüfen. Über „Produkt zuordnen“ wählst du das passende Produkt und die Version aus der NVD-Produktliste – danach klappt es per Klick.</p>` : ''}`
        : '<div class="empty">Noch keine Komponenten. Wähle oben eine der drei Möglichkeiten.</div>'}
    </div>
    ${p.components.length ? `<div class="row end">
      <button class="btn" data-action="tab" data-tab="cves">Weiter ohne Suche →</button>
      <button class="btn primary big" data-action="auto-check">Schwachstellen jetzt suchen</button></div>` : ''}`;
  }

  function riskBadge(r, prefix) {
    if (r.eliminated) return `<span class="badge niedrig" title="Schwachstelle durch Patch bzw. Austausch beseitigt">${prefix || ''}✓ behoben</span>`;
    return `<span class="badge ${r.level.key}" title="Wahrscheinlichkeit ${r.L} × Auswirkung ${r.I}">${prefix || ''}${r.score} · ${r.level.label}</span>`;
  }
  function stars(n) { return '<span class="stars" title="Relevanz">' + '●'.repeat(n) + '○'.repeat(3 - n) + '</span>'; }

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
      <div class="row"><div><h2 style="margin:0">${p.findings.length} Schwachstellen</h2>
        <div class="small muted">Sortiert nach Risiko. Antippen zeigt Begründung und Maßnahmen.</div></div><span class="spacer"></span>
        <button class="btn" data-action="auto-check">Erneut suchen</button>
        <button class="btn ${noSel ? 'primary' : ''}" data-action="rec-all">Alle Empfehlungen übernehmen</button></div>
      ${noSel ? `<p class="small" style="margin:10px 0 0">Für ${noSel} offene Schwachstelle(n) sind noch keine Maßnahmen ausgewählt. Ein Klick auf „Alle Empfehlungen übernehmen“ wählt überall den Vorschlag der App – du kannst danach einzelne Einträge anpassen.</p>` : ''}
    </div>` : `<div class="card empty"><h2>Noch keine Schwachstellen</h2><p>Die App sucht für alle Komponenten automatisch nach bekannten Schwachstellen.</p>
      <button class="btn primary big" data-action="auto-check">Schwachstellen jetzt suchen</button></div>`}
    <details class="card no-print"><summary style="cursor:pointer;font-weight:650">Einzelne Schwachstelle von Hand hinzufügen</summary>
      <div class="grid two" style="margin-top:12px">
        <label class="field">CVE-Nummern <span class="hint">mehrere durch Komma oder Leerzeichen getrennt</span><input id="cveIds" placeholder="z. B. CVE-2022-38465, CVE-2021-44228"></label>
        <label class="field">Betroffene Komponente<select id="cveComp">${p.components.map(c => `<option value="${c.id}">${esc(c.name)} ${esc(c.version)}</option>`).join('')}<option value="">– ohne Zuordnung –</option></select></label>
      </div>
      <div class="row" style="margin-top:10px"><button class="btn primary" data-action="cve-fetch">Abrufen</button>
        <button class="btn" data-action="cve-manual">Ohne CVE-Nummer erfassen</button>
        <button class="btn" data-action="enrich" title="Ausnutzungswahrscheinlichkeit (EPSS) und Liste aktiv ausgenutzter Schwachstellen (CISA KEV) neu laden">Bedrohungsdaten aktualisieren</button>
        <span class="muted small" id="fetchStatus"></span></div>
    </details>
    ${p.findings.length ? `<div class="row no-print" style="margin-bottom:10px">
      <input type="search" id="filter" placeholder="Filtern nach CVE, Komponente, Text …" value="${esc(ui.filter)}" style="flex:1;min-width:200px">
      ${ui.cell ? `<span class="badge outline">Matrixfeld W${ui.cell[0]} × A${ui.cell[1]} <button class="btn small" data-action="cell-clear" style="min-height:22px;padding:0 6px;border:0">✕</button></span>` : ''}
    </div>` : ''}
    ${shown.map(x => findingCard(p, x.f, x.e)).join('')}
    ${list.length > shown.length ? `<div class="row" style="justify-content:center;margin:12px 0"><button class="btn" data-action="more">Weitere ${Math.min(PAGE, list.length - shown.length)} anzeigen (${list.length - shown.length} übrig)</button></div>` : ''}
    ${p.findings.length && !list.length ? '<div class="card empty">Kein Treffer für diesen Filter.</div>' : ''}
    ${p.findings.length ? '<div class="row end no-print" style="margin-top:14px"><button class="btn" data-action="tab" data-tab="matrix">Risikomatrix</button><button class="btn primary big" data-action="tab" data-tab="plan">Weiter zum Maßnahmenplan →</button></div>' : ''}`;
  }

  function findingCard(p, f, e) {
    const nb = f.status === 'nb';
    const lv = nb ? 'nb' : e.base.level.key;
    const sev = f.cvss && f.cvss.score != null ? `CVSS ${f.cvss.score}` : 'kein CVSS';
    const flagOver = !nb && e.over && f.status !== 'akzeptiert' && (f.mitigations || []).length;
    return `<details class="finding ${lv}" data-fid="${f.id}" ${ui.open.has(f.id) ? 'open' : ''}>
      <summary>
        <div>
          <div class="title">${esc(f.cve)} <span class="muted" style="font-weight:400">· ${esc(e.comp ? e.comp.name + ' ' + e.comp.version : 'ohne Komponente')}</span></div>
          <div class="meta">
            <span class="badge outline">${sev}</span>
            ${f.kev ? '<span class="badge kev" title="Steht auf der CISA-Liste aktiv ausgenutzter Schwachstellen (KEV)">aktiv ausgenutzt</span>' : ''}
            ${f.epss != null ? `<span class="badge outline" title="EPSS: Wahrscheinlichkeit einer Ausnutzung in den nächsten 30 Tagen">EPSS ${pct(f.epss)}</span>` : ''}
            ${f.patchAvailable ? '<span class="badge outline">Patch verfügbar</span>' : ''}
            ${f.source ? `<span class="badge outline">Quelle: ${esc(f.source)}</span>` : ''}
            <span class="badge outline">${STATUS[f.status || 'offen']}</span>
            ${flagOver ? '<span class="badge hoch" title="Das Restrisiko der gewählten Maßnahmen liegt über der Akzeptanzschwelle">über Akzeptanz</span>' : ''}
            ${!nb && e.reach !== 'now' && isOpenItem(f) ? `<span class="badge ${e.reach === 'none' ? 'krit' : 'mittel'}" title="Siehe Hinweis in den Details">${e.reach === 'none' ? 'Entscheidung nötig' : 'Akzeptanz erst nach Patch/Austausch'}</span>` : ''}
          </div>
        </div>
        <div class="riskflow">${nb ? '<span class="badge">nicht betroffen</span>' : `${riskBadge(e.base)} <span class="muted">→</span> ${riskBadge(e.res)}`}</div>
      </summary>
      <div class="body">${ui.open.has(f.id) ? findingBody(p, f, e) : ''}</div>
    </details>`;
  }

  function reachNote(p, f, e) {
    const t = p.ctx.acceptance;
    if (e.reach === 'now') return `<p class="small muted" style="margin:8px 0 0">Mit den empfohlenen Maßnahmen wird die Akzeptanzschwelle (≤ ${t}) erreicht: ${riskBadge(e.recResNow, 'Restrisiko ')}</p>`;
    if (e.reach === 'later') return `<div class="callout warn"><strong>Akzeptanzschwelle (≤ ${t}) erst nach ${e.recLater.includes('patch') ? 'dem Patch' : 'dem Austausch der Komponente'} erreicht.</strong>
      Bis dahin bleibt mit den Sofortmaßnahmen ${riskBadge(e.recResNow, 'Restrisiko ')}. Dieses Übergangsrisiko sollte bewusst entschieden und in der Notiz begründet werden.</div>`;
    return `<div class="callout danger"><strong>Akzeptanzschwelle (≤ ${t}) mit den verfügbaren Maßnahmen nicht erreichbar.</strong>
      Bestenfalls bleibt ${riskBadge(e.recRes, 'Restrisiko ')}. Hier ist eine Entscheidung der Verantwortlichen nötig: Risiko formal akzeptieren (Status „Risiko akzeptiert“ mit Begründung) oder die Komponente ersetzen.</div>`;
  }

  function findingBody(p, f, e) {
    const nb = f.status === 'nb';
    const chosen = f.mitigations || [];
    return `
        <p class="desc">${esc(f.description) || '<span class="muted">Keine Beschreibung</span>'}</p>
        ${f.fix ? `<p class="small"><strong>Fix laut ${esc(f.source || 'Scanner')}:</strong> ${esc(f.fix)}</p>` : ''}
        <div class="grid two">
          <div>
            <strong>Eintrittswahrscheinlichkeit: ${e.base.L}/5</strong>
            <ul class="why">${e.base.whyL.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
          </div>
          <div>
            <strong>Auswirkung: ${e.base.I}/5</strong>
            <ul class="why">${e.base.whyI.map(w => `<li>${esc(w)}</li>`).join('')}</ul>
          </div>
        </div>
        <p class="small muted" style="margin:10px 0">${f.cvss && f.cvss.vector ? `<code>${esc(f.cvss.vector)}</code> · ` : ''}${(f.cwe || []).map(esc).join(', ') || 'CWE unbekannt'} · veröffentlicht ${fmtDate(f.published)}
          ${/^CVE-/i.test(f.cve) ? `· <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}" target="_blank" rel="noopener">Details in der NVD</a>` : ''}</p>
        <div class="grid two no-print">
          <label class="field">Status<select data-f="status">${Object.entries(STATUS).map(([k, l]) => opt(k, f.status || 'offen', l)).join('')}</select></label>
          <label class="field">Komponente<select data-f="componentId">${p.components.map(c => opt(c.id, f.componentId, c.name + ' ' + c.version)).join('')}${opt('', f.componentId || '', '– ohne –')}</select></label>
        </div>
        <label class="check no-print" style="margin:10px 0"><input type="checkbox" data-f="patchAvailable" ${f.patchAvailable ? 'checked' : ''}><span>Hersteller-Patch / korrigierte Version verfügbar</span></label>
        ${f.status === 'akzeptiert' && !(f.note || '').trim() ? '<div class="callout warn">Für ein akzeptiertes Risiko bitte unten eine Begründung eintragen (wer hat wann warum akzeptiert).</div>' : ''}
        ${nb ? '' : `
        <div class="row" style="margin-top:12px"><h3 style="margin:0">Maßnahmen</h3><span class="spacer"></span>
          <button class="btn small primary no-print" data-action="rec-apply">Empfehlung übernehmen</button></div>
        ${reachNote(p, f, e)}
        <div class="mit-list">${e.options.map(o => {
          const isNow = e.recNow.includes(o.m.id), isLater = e.recLater.includes(o.m.id);
          const mand = o.m.sl <= p.ctx.slT && o.m.cat === 'Technisch';
          return `<div class="mit ${isNow || isLater ? 'rec' : ''}">
            <label class="h check"><input type="checkbox" data-mit="${o.m.id}" ${chosen.includes(o.m.id) ? 'checked' : ''}>
              <strong>${esc(o.m.title)}</strong>${stars(o.rel)}</label>
            <div class="small" style="margin:4px 0 0 26px">${esc(o.m.text)}</div>
            <div class="row small" style="margin:6px 0 0 26px;gap:6px">
              ${isNow ? '<span class="badge" style="background:var(--accent);color:#fff">empfohlen: sofort</span>' : ''}
              ${isLater ? '<span class="badge" style="background:var(--accent);color:#fff">empfohlen: einplanen</span>' : ''}
              <span class="badge outline">${esc(o.m.cat)}</span>
              ${o.m.sr.map(s => `<span class="badge outline">${esc(s)}</span>`).join('')}
              ${mand ? `<span class="badge outline" title="Systemanforderung ist für das Ziel-Security-Level relevant">SL-T ${p.ctx.slT}</span>` : ''}
              <span class="muted">Aufwand ${'€'.repeat(o.m.effort)}</span>
            </div>
            <ul style="margin-left:26px">${o.m.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
          </div>`;
        }).join('')}</div>`}
        <label class="field no-print" style="margin-top:12px">Notiz / Begründung<textarea data-f="note" placeholder="z. B. Begründung für eine Risikoakzeptanz oder warum die Maschine nicht betroffen ist">${esc(f.note || '')}</textarea></label>
        <div class="row end no-print" style="margin-top:8px"><button class="btn small danger" data-action="finding-del">Schwachstelle entfernen</button></div>`;
  }

  function matrixCounts(p, mode) {
    const m = {};
    activeFindings(p).forEach(f => { const e = evaluate(p, f); const r = mode === 'nachher' ? e.res : e.base; const k = r.L + '_' + r.I; m[k] = (m[k] || 0) + 1; });
    return m;
  }

  /* Achsen: Wahrscheinlichkeit nach rechts, Auswirkung nach oben – höchstes Risiko (25) oben rechts */
  function matrixHtml(p, mode, interactive) {
    const counts = matrixCounts(p, mode);
    let cells = '';
    for (let I = 5; I >= 1; I--) for (let L = 1; L <= 5; L++) {
      const n = counts[L + '_' + I] || 0;
      const lv = Risk.level(L * I).key;
      const sel = ui.cell && ui.cell[0] === L && ui.cell[1] === I;
      cells += `<button class="cell ${lv} ${n ? '' : 'zero'} ${sel ? 'sel' : ''}" ${interactive ? `data-action="cell" data-l="${L}" data-i="${I}"` : 'tabindex="-1"'} aria-label="Wahrscheinlichkeit ${L}, Auswirkung ${I}: ${n}"><span class="sc">${L * I}</span>${n || '·'}</button>`;
    }
    return `<div class="matrix-wrap">
      <div class="matrix-ylab">Auswirkung →</div>
      <div><div class="matrix">${cells}</div><div class="axis" style="margin-top:4px"><span>1</span><span>2</span><span>3</span><span>4</span><span>5</span></div></div>
      <div></div><div class="matrix-xlab">Eintrittswahrscheinlichkeit →</div>
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
    if (!activeFindings(p).length) return '<div class="card empty">Noch keine bewerteten Schwachstellen.</div>';
    return `
    <div class="card">
      <div class="row"><h2 style="margin:0">Risikomatrix</h2><span class="spacer"></span>
        <div class="seg" role="group" aria-label="Ansicht"><button class="${ui.matrixMode === 'vorher' ? 'on' : ''}" data-action="mmode" data-m="vorher">Ausgangsrisiko</button><button class="${ui.matrixMode === 'nachher' ? 'on' : ''}" data-action="mmode" data-m="nachher">Restrisiko</button></div></div>
      <p class="muted small">Oben rechts liegt das höchste Risiko. Restrisiko = nach den in Schritt 3 ausgewählten Maßnahmen. Ein Feld antippen zeigt die betroffenen Schwachstellen.</p>
      <div class="grid two" style="align-items:start">
        ${matrixHtml(p, ui.matrixMode, true)}
        <div>
          <h3>Verteilung – Ausgangsrisiko</h3>${distBar(distribution(p, e => e.base))}
          <h3 style="margin-top:18px">Verteilung – Restrisiko</h3>${distBar(distribution(p, e => e.res))}
          <p class="small muted" style="margin-top:18px">Risiko = Eintrittswahrscheinlichkeit (Angriffsweg, Komplexität, benötigte Rechte, Netzexposition, EPSS, CISA KEV) × Auswirkung (Verfügbarkeit und Integrität vor Vertraulichkeit, Safety-Relevanz). Akzeptanzschwelle: ≤ ${p.ctx.acceptance}.</p>
        </div>
      </div>
    </div>
    <div class="row end"><button class="btn primary big" data-action="tab" data-tab="plan">Weiter zum Maßnahmenplan →</button></div>`;
  }

  /** Aggregierter Maßnahmenplan über alle Schwachstellen */
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
      // Dauerhafte Behebung ohne zeitnahes Wartungsfenster bzw. Austausch: geplant statt sofort
      if (g.m.id === 'replace' || (g.m.id === 'patch' && p.ctx.patchable === false)) g.prio = Math.max(g.prio, 3);
      return g;
    }).sort((a, b) => a.prio - b.prio || (b.m.id === 'kev') - (a.m.id === 'kev') || b.reduction - a.reduction || b.findings.length - a.findings.length || a.m.effort - b.m.effort);
  }
  const PRIO = { 1: ['Sofort', 'krit', 'innerhalb von 72 h – 2 Wochen'], 2: ['Kurzfristig', 'hoch', 'innerhalb von 3 Monaten'], 3: ['Geplant', 'mittel', 'im nächsten Wartungs-/Release-Zyklus'] };
  const short = (arr, n) => arr.length > n ? arr.slice(0, n).join(', ') + ` … (+${arr.length - n})` : arr.join(', ');

  function viewPlan(p) {
    const act = activeFindings(p);
    if (!p.findings.length) return `<div class="card empty"><h2>Noch kein Maßnahmenplan</h2><p>Zuerst Komponenten erfassen und Schwachstellen suchen.</p><button class="btn primary big" data-action="tab" data-tab="sbom">Zu Schritt 2: Komponenten</button></div>`;
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
      <h1>OT-Risikoanalyse: ${esc(p.name)}</h1>
      <p>${esc(p.machine)} ${p.customer ? '· ' + esc(p.customer) : ''} · Stand ${new Date().toLocaleDateString('de-DE')} ${p.author ? '· Bearbeiter: ' + esc(p.author) : ''}</p>
      ${p.description ? `<p>${esc(p.description)}</p>` : ''}
      <p><strong>Kontext:</strong> Netzexposition ${esc(Risk.EXPOSURE[c.exposure])}; Fernwartung ${c.remoteAccess ? 'ja' : 'nein'}; physischer Zugang ${esc(Risk.PHYSICAL[c.physical])}; Safety ${c.safety}/3; Verfügbarkeit ${c.availability}/3; Vertraulichkeit ${c.confidentiality}/3; SL-T ${c.slT}; Patches zeitnah einspielbar: ${c.patchable ? 'ja' : 'nein'}; Risikoakzeptanz ≤ ${c.acceptance}.</p>
    </div>
    <div class="grid kpi" style="margin-bottom:16px">
      <div class="kpi-tile"><div class="v">${p.components.length}</div><div class="l">Komponenten</div></div>
      <div class="kpi-tile"><div class="v">${act.length}</div><div class="l">relevante Schwachstellen</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-krit)">${before.krit + before.hoch}</div><div class="l">kritisch/hoch im Ausgangszustand</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-krit)">${act.filter(f => f.kev).length}</div><div class="l">aktiv ausgenutzt</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-hoch)">${recNow.krit + recNow.hoch}</div><div class="l">kritisch/hoch nach Sofortmaßnahmen</div></div>
      <div class="kpi-tile"><div class="v" style="color:var(--r-niedrig)">${recFin.krit + recFin.hoch}</div><div class="l">kritisch/hoch nach Patch/Austausch</div></div>
    </div>
    ${later.length || none.length || accNoNote.length ? `<div class="card">
      <h2>Entscheidungen nötig</h2>
      ${none.length ? `<div class="callout danger"><strong>${none.length} Schwachstelle(n): Akzeptanzschwelle (≤ ${c.acceptance}) nicht erreichbar.</strong> Risiko formal akzeptieren oder Komponente ersetzen: ${esc(short(none.map(x => x.f.cve), 8))}</div>` : ''}
      ${later.length ? `<div class="callout warn"><strong>${later.length} Schwachstelle(n): Akzeptanzschwelle erst nach Patch bzw. Austausch erreicht.</strong> Bis dahin besteht trotz Sofortmaßnahmen ein erhöhtes Übergangsrisiko, das bewusst getragen werden muss: ${esc(short(later.map(x => x.f.cve), 8))}</div>` : ''}
      ${accNoNote.length ? `<div class="callout warn"><strong>${accNoNote.length} akzeptierte(s) Risiko ohne Begründung:</strong> ${esc(short(accNoNote.map(x => x.f.cve), 8))}</div>` : ''}
    </div>` : ''}
    <div class="card">
      <div class="row"><h2 style="margin:0">Maßnahmenplan</h2><span class="spacer"></span>
        <div class="seg no-print"><button class="${(ui.planSource || 'empfehlung') === 'empfehlung' ? 'on' : ''}" data-action="psrc" data-s="empfehlung">Empfehlung der App</button><button class="${ui.planSource === 'auswahl' ? 'on' : ''}" data-action="psrc" data-s="auswahl">Meine Auswahl</button></div></div>
      <p class="muted small">Je Schwachstelle die kleinste Maßnahmenkombination, die das Risiko unter die Akzeptanzschwelle (≤ ${c.acceptance}) bringt – zusammengefasst und nach Dringlichkeit sortiert. Mitigierte und akzeptierte Schwachstellen sind ausgenommen.</p>
      ${plan.length ? plan.map((g, i) => `
        <div class="mit" style="margin-bottom:10px">
          <div class="h"><span class="badge ${PRIO[g.prio][1]}">${PRIO[g.prio][0]}</span><strong>${i + 1}. ${esc(g.m.title)}</strong><span class="muted small">Aufwand ${'€'.repeat(g.m.effort)}</span></div>
          <div class="small" style="margin-top:6px">${esc(g.m.text)}</div>
          <div class="row small" style="margin-top:6px;gap:6px">
            ${g.m.sr.map(s => `<span class="badge outline">${esc(s)}</span>`).join('')}
            <span class="muted">Umsetzung ${PRIO[g.prio][2]} · betrifft ${g.findings.length} Schwachstelle${g.findings.length > 1 ? 'n' : ''}${g.reduction ? ' · Risikoreduktion Σ ' + g.reduction : ''}</span>
          </div>
          <div class="small muted" style="margin-top:4px">Komponenten: ${esc(short([...g.comps], 6) || '–')} · ${esc(short(g.findings, 10))}</div>
          <ul>${g.m.steps.map(s => `<li>${esc(s)}</li>`).join('')}</ul>
        </div>`).join('') : '<div class="empty">Keine offenen Maßnahmen – alle Risiken liegen innerhalb der Akzeptanz.</div>'}
    </div>
    <div class="card no-print">
      <h2>Ergebnis ausgeben</h2>
      <div class="choice-grid">
        <button class="choice main" data-action="print"><strong>Bericht drucken / als PDF speichern</strong><span>Im Druckdialog „Als PDF speichern“ wählen</span></button>
        <button class="choice" data-action="csv"><strong>Tabelle (CSV)</strong><span>Alle Schwachstellen für Excel</span></button>
        <button class="choice" data-action="cdx-vex"><strong>CycloneDX mit VEX</strong><span>Stückliste samt Status und Bewertung für Kunden oder andere Werkzeuge</span></button>
      </div>
    </div>
    <div class="grid two">
      <div class="card"><h3>Ausgangsrisiko</h3>${matrixHtml(p, 'vorher', false)}<div style="margin-top:10px">${distBar(before)}</div></div>
      <div class="card"><h3>Restrisiko (gewählte Maßnahmen)</h3>${matrixHtml(p, 'nachher', false)}<div style="margin-top:10px">${distBar(after)}</div></div>
    </div>
    <div class="card">
      <h3>Schwachstellenübersicht</h3>
      <div class="table-wrap"><table><thead><tr><th>CVE</th><th>Komponente</th><th>CVSS</th><th>W×A</th><th>Risiko</th><th>Rest</th><th>Status</th></tr></thead><tbody>
      ${p.findings.map(f => ({ f, e: evaluate(p, f) })).sort((a, b) => b.e.base.score - a.e.base.score).map(({ f, e }) => `<tr>
        <td><strong>${esc(f.cve)}</strong>${f.kev ? ' <span class="badge kev">KEV</span>' : ''}</td>
        <td>${esc(e.comp ? e.comp.name + ' ' + e.comp.version : '–')}</td>
        <td>${f.cvss && f.cvss.score != null ? f.cvss.score : '–'}</td><td>${e.base.L}×${e.base.I}</td>
        <td>${f.status === 'nb' ? '–' : riskBadge(e.base)}</td><td>${f.status === 'nb' ? '–' : riskBadge(e.res)}</td>
        <td>${STATUS[f.status || 'offen']}</td></tr>`).join('')}
      </tbody></table></div>
    </div>
    <p class="small muted">Methodik: Umgebungsbezogene Bewertung der CVSS-Basismetriken im Maschinenkontext; Bedrohungsdaten aus FIRST EPSS und CISA KEV; Maßnahmen zugeordnet zu IEC 62443-3-3 Systemanforderungen (SR) bzw. IEC 62443-2-3. Die automatische Empfehlung ersetzt keine fachliche Prüfung im Einzelfall.</p>`;
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
    openModal('Neue Analyse', `
      <form id="projForm" class="grid" style="gap:14px">
        <label class="field">Name der Analyse*<input name="name" required placeholder="z. B. Drahtziehmaschine Kunde Muster" autofocus></label>
        <label class="field">Maschine / Anlage <span class="hint">optional: Typ, Seriennummer, Baujahr</span><input name="machine"></label>
        <div><div style="font-weight:550;font-size:.9rem;margin-bottom:6px">Wie ist die Maschine angebunden?</div>
          <div class="grid" style="gap:8px">${Object.entries(PRESETS).map(([k, pr]) => `<label class="check radio-card"><input type="radio" name="preset" value="${k}" ${k === 'vernetzt' ? 'checked' : ''}><span><strong>${esc(pr.label)}</strong><br><span class="muted small">${esc(pr.hint)}</span></span></label>`).join('')}</div>
          <div class="small muted" style="margin-top:6px">Lässt sich später in Schritt 1 jederzeit ändern und verfeinern.</div></div>
        <div class="row end"><button type="button" class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary">Anlegen</button></div>
      </form>`);
  }

  function assignedHtml(cpe, title) {
    if (!cpe) return '<span class="muted small">Noch kein Produkt zugeordnet. Ohne Zuordnung ist nur eine ungenaue Stichwortsuche möglich.</span>';
    const ok = Api.isPrecise(cpe);
    return `<div class="callout ${ok ? 'ok' : 'warn'}" style="margin:0"><strong>${ok ? '✓' : '!'} Produkt zugeordnet: ${esc(title || prettyCpe(cpe))}</strong> ${ok ? '– wird versionsgenau geprüft.' : '– bitte noch die Version eintragen, damit versionsgenau geprüft werden kann.'}
      <button type="button" class="btn small" data-action="prod-clear" style="margin-left:6px">Zuordnung entfernen</button></div>`;
  }

  function compForm(c) {
    c = c || { name: '', vendor: '', version: '', type: 'SPS', cpe: '', purl: '' };
    ui.prodVersions = null;
    const key = c.cpe && c.cpe.startsWith('cpe:2.3:') ? Api.cpeParts(c.cpe).slice(2, 5).join(':') : '';
    openModal(c.id ? 'Komponente bearbeiten' : 'Gerät / Komponente hinzufügen', `
      <form id="compForm" class="grid two">
        <input type="hidden" name="id" value="${esc(c.id || '')}">
        <input type="hidden" name="cpeKey" value="${esc(key)}">
        <input type="hidden" name="product" value="${esc(c.product || '')}">
        <div style="grid-column:1/-1">
          <label class="field">1. Produkt in der NVD-Produktliste suchen <span class="hint">Stichwort genügt, z. B. „S7-1500“, „SCALANCE XC208“, „WinCC“, „Windows 10“</span></label>
          <div class="row" style="flex-wrap:nowrap;margin-top:4px"><input id="prodQ" type="search" value="${esc(c.id && !c.cpe ? c.name : '')}" placeholder="Produkt suchen …" style="flex:1"><button type="button" class="btn" data-action="prod-search">Suchen</button></div>
          <div id="prodResults" style="margin-top:8px"></div>
          <div id="prodChosen" style="margin-top:8px">${assignedHtml(c.cpe, c.product)}</div>
        </div>
        <label class="field">2. Version / Firmware-Stand<input name="version" list="verList" value="${esc(c.version)}" placeholder="z. B. 2.9.4" autocomplete="off"><datalist id="verList"></datalist></label>
        <label class="field">Typ<select name="type">${COMP_TYPES.map(t => opt(t, c.type, t)).join('')}</select></label>
        <label class="field">Bezeichnung*<input name="name" required value="${esc(c.name)}" placeholder="z. B. Hauptsteuerung S7-1516"></label>
        <label class="field">Hersteller<input name="vendor" value="${esc(c.vendor)}" placeholder="z. B. Siemens"></label>
        <details style="grid-column:1/-1"><summary class="small muted" style="cursor:pointer">Für Fachleute: Kennungen direkt bearbeiten (CPE / PURL)</summary>
          <div class="grid" style="margin-top:10px">
            <label class="field">CPE 2.3 <span class="hint">wird durch die Produktwahl automatisch gesetzt</span><input name="cpe" value="${esc(c.cpe)}"></label>
            <label class="field">Package-URL (PURL) <span class="hint">für Software-Pakete, z. B. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1</span><input name="purl" value="${esc(c.purl || '')}"></label>
          </div></details>
        <div class="row end" style="grid-column:1/-1"><button type="button" class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary">Speichern</button></div>
      </form>`);
  }

  // Hinweis: Felder immer über form.elements ansprechen – Felder namens "id"/"name" verdecken sonst die Formular-Eigenschaften
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
    if (q.length < 3) { box.innerHTML = '<span class="small muted">Bitte mindestens 3 Zeichen eingeben.</span>'; return; }
    box.innerHTML = '<span class="small muted">Suche in der NVD-Produktliste …</span>';
    try {
      const r = await Api.products(q, s => { box.innerHTML = `<span class="small muted">Die NVD lässt nur wenige Abfragen pro Minute zu – weiter in ${s} s …</span>`; });
      if (!$('#prodResults')) return;
      ui.prodList = r.items;
      const PART = { o: 'Firmware / Betriebssystem', a: 'Software', h: 'Hardware' };
      box.innerHTML = r.items.length ? `
        <div class="small muted" style="margin-bottom:6px">${r.items.length} Produkt(e) gefunden${r.truncated ? ' – sehr viele Treffer, bitte den Suchbegriff genauer fassen' : ''}. Passendes Produkt anklicken:</div>
        <div class="dirlist">${r.items.slice(0, 60).map((g, i) => `<button type="button" class="dir" data-action="prod-pick" data-i="${i}"><strong>${esc(g.title)}</strong><span class="muted small">${PART[g.part] || ''}${g.versions.length ? ' · ' + g.versions.length + ' Versionen bekannt' : ''}</span></button>`).join('')}</div>`
        : '<span class="small">Kein Produkt gefunden. Tipp: kürzeres Stichwort verwenden (z. B. nur die Typbezeichnung) oder auf Englisch suchen.</span>';
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
    if (!el.id.value) el.type.value =g.part === 'a' ? 'Anwendung' : /windows|linux|debian|ubuntu/i.test(g.title) ? 'Betriebssystem' : /s7|plc|cpu|controller|logo/i.test(g.title) ? 'SPS' : /panel|hmi/i.test(g.title) ? 'HMI' : /scalance|switch|router|ruggedcom/i.test(g.title) ? 'Netzwerk' : /sinamics|drive|servo/i.test(g.title) ? 'Antrieb' : 'Firmware';
    $('#prodResults').innerHTML = '';
    syncCpe(form);
    el.version.focus();
  }

  async function compSearch(c) {
    const precise = Api.isPrecise(c.cpe);
    openModal(`Schwachstellen suchen: ${c.name}`, `<p class="muted">Suche in der NVD ${precise ? 'versionsgenau' : c.cpe ? 'für alle Versionen des Produkts' : 'per Stichwort „' + esc([c.vendor, c.name].filter(Boolean).join(' ')) + '“'} …</p><p id="searchWait" class="small muted"></p>`);
    try {
      const r = await Api.search(c, s => { const w = $('#searchWait'); if (w) w.textContent = `Die NVD lässt nur wenige Abfragen pro Minute zu – weiter in ${s} s`; });
      if ($('#modal').hidden) return;
      const known = new Set(project().findings.map(f => f.cve + '|' + f.componentId));
      const ver = (c.version || '').replace(/^v/i, '').trim();
      const hint = r.precise ? 'Diese Schwachstellen betreffen laut NVD genau die eingetragene Version – alle sind vorausgewählt.'
        : `Achtung: ungenaue Suche${c.cpe ? ' (Version fehlt)' : ' per Stichwort'} – es können unpassende Treffer dabei sein. Vorausgewählt sind nur Treffer, in deren Beschreibung die Version „${esc(ver)}“ vorkommt. Genauer wird es über „Bearbeiten → Produkt zuordnen“.`;
      const body = r.items.length ? `
        <p class="small ${r.precise ? 'muted' : ''}">${r.total} Treffer${r.total > r.items.length ? `, die neuesten ${r.items.length} angezeigt` : ''}. ${hint}</p>
        <div class="row" style="margin-bottom:8px"><button class="btn small" data-action="sel-all">Alle</button><button class="btn small" data-action="sel-none">Keine</button><span class="spacer"></span><button class="btn primary" data-action="search-take" data-id="${c.id}">Ausgewählte übernehmen</button></div>
        <div class="table-wrap"><table><tbody>${r.items.map(it => {
          const dup = known.has(it.cve + '|' + c.id);
          const pre = !dup && (r.precise || (ver && it.description.includes(ver)));
          return `<tr><td><input type="checkbox" data-cve="${esc(it.cve)}" ${pre ? 'checked' : ''} ${dup ? 'disabled' : ''}></td>
            <td><strong>${esc(it.cve)}</strong> ${it.cvss ? `<span class="badge outline">${it.cvss.score}</span>` : ''} ${it.kev ? '<span class="badge kev">aktiv ausgenutzt</span>' : ''} ${dup ? '<span class="badge">bereits erfasst</span>' : ''}
            <div class="small muted">${esc(it.description.slice(0, 260))}${it.description.length > 260 ? '…' : ''}</div></td></tr>`;
        }).join('')}</tbody></table></div>` : `<div class="empty">${r.precise ? 'Für diese Version sind in der NVD keine Schwachstellen bekannt.' : 'Keine Treffer. Tipp: über „Bearbeiten“ ein Produkt aus der Produktliste zuordnen.'}</div>`;
      $('#modalBody').innerHTML = body;
      $('#modalBody')._items = r.items;
    } catch (e) { $('#modalBody').innerHTML = `<p>${esc(e.message)}</p>`; }
  }

  function manualForm() {
    const p = project();
    openModal('Schwachstelle ohne CVE-Nummer erfassen', `
      <form id="manualForm" class="grid two">
        <label class="field">Kennung*<input name="cve" required placeholder="z. B. Hersteller-Advisory oder interne Nummer"></label>
        <label class="field">Komponente<select name="componentId">${p.components.map(c => opt(c.id, '', c.name + ' ' + c.version)).join('')}<option value="">– ohne –</option></select></label>
        <label class="field">CVSS-Basisscore<input name="score" inputmode="decimal" placeholder="z. B. 9.8"></label>
        <label class="field">CVSS-Vektor<input name="vector" placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"></label>
        <label class="field">CWE <span class="hint">kommagetrennt</span><input name="cwe" placeholder="CWE-787"></label>
        <label class="check" style="align-self:end"><input type="checkbox" name="patch"><span>Patch verfügbar</span></label>
        <label class="field" style="grid-column:1/-1">Beschreibung<textarea name="description"></textarea></label>
        <div class="row end" style="grid-column:1/-1"><button type="button" class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary">Hinzufügen</button></div>
      </form>`);
  }

  function menu() {
    const p = project();
    openModal('Daten & Sicherung', `
      <p class="small muted" style="margin-top:0">${storageNote()}</p>
      <div class="menu-list">
        <button class="btn" data-action="backup-all"><strong>Sicherung speichern</strong>&nbsp;– alle Analysen in eine Datei</button>
        <button class="btn" data-action="import-json"><strong>Sicherung oder Analyse laden</strong>&nbsp;– aus einer Datei</button>
        ${p ? `<button class="btn" data-action="export-json">Nur die aktuelle Analyse speichern (zum Weitergeben)</button>
        <button class="btn" data-action="project-dup">Aktuelle Analyse duplizieren</button>
        <button class="btn danger" data-action="project-del">Aktuelle Analyse löschen</button>` : ''}
        <button class="btn" data-action="demo">Beispiel-Maschine laden</button>
        <button class="btn danger" data-action="wipe">Alle Daten auf diesem Gerät löschen</button>
      </div>
      <p class="small muted" style="margin-top:12px">Datenschutz: Die Analysen bleiben auf diesem Gerät und werden unverschlüsselt gespeichert – nutze für vertrauliche Kundendaten einen PC mit Festplattenverschlüsselung (z. B. BitLocker). An die Datenquellen NVD (NIST), EPSS (FIRST) und KEV (CISA) gehen nur CVE-Nummern und Produktnamen, keine Projektdaten. <a href="rechtliches.html" target="_blank" rel="noopener">Datenschutz und rechtliche Hinweise</a></p>`);
  }

  // ---------- Trivy ----------
  const TRIVY_CMDS = [
    ['Software-Projekt / Programmordner', 'trivy fs --format cyclonedx --scanners vuln --output ergebnis.cdx.json ./ordner'],
    ['Linux-Gerät: kopiertes oder entpacktes Dateisystem (Edge-PC, Linux-HMI, Firmware)', 'trivy rootfs --format cyclonedx --scanners vuln --output ergebnis.cdx.json /mnt/geraet'],
    ['Container-Image', 'trivy image --format cyclonedx --scanners vuln --output ergebnis.cdx.json registry.example.com/app:1.4']
  ];
  function trivyGuide(intro) {
    openModal('Software scannen mit Trivy', `
      ${intro}
      <details style="margin-top:12px"><summary style="cursor:pointer;font-weight:600">Für Fachleute: Scan von Hand in der Kommandozeile</summary>
      ${TRIVY_CMDS.map(([t, c]) => `<div style="margin:12px 0"><div class="small" style="font-weight:600;margin-bottom:4px">${esc(t)}</div>
        <div class="row" style="flex-wrap:nowrap"><code class="mono" style="flex:1;background:var(--surface-2);padding:8px 10px;border-radius:8px;overflow-x:auto;white-space:nowrap">${esc(c)}</code><button class="btn small" data-action="copy" data-text="${esc(c)}">Kopieren</button></div></div>`).join('')}
      <p class="small muted">Wichtig ist <code>--scanners vuln</code>, sonst fehlen die Schwachstellen in der Datei.</p></details>
      <div class="row end" style="margin-top:12px"><button class="btn primary" data-action="sbom-import">Scan-Datei importieren</button></div>`);
  }

  async function scanOpen() {
    if (!Local.available) {
      return trivyGuide(`<p>Scannen per Klick funktioniert am Windows-PC, wenn die App über die Datei <strong>„OT-Risikoanalyse starten“</strong> geöffnet wurde. Auf diesem Gerät kannst du ein dort erzeugtes Scan-Ergebnis über „Datei importieren“ laden.</p>`);
    }
    if (!Local.trivy) {
      return trivyGuide(`<div class="callout warn"><strong>Trivy ist auf diesem PC noch nicht installiert.</strong><br>Einmalig nötig: Windows-Taste drücken, „PowerShell“ eintippen und öffnen, den folgenden Befehl einfügen und Enter drücken. Danach das Startfenster der App schließen und die App neu starten.</div>
        <div class="row" style="flex-wrap:nowrap;margin-top:8px"><code class="mono" style="flex:1;background:var(--surface-2);padding:8px 10px;border-radius:8px">winget install AquaSecurity.Trivy</code><button class="btn small" data-action="copy" data-text="winget install AquaSecurity.Trivy">Kopieren</button></div>`);
    }
    ui.scan = { tab: 'folder', dir: null, mode: 'fs', modeTouched: false };
    openModal('Software scannen', '<p class="muted">Lade Ordnerliste …</p>');
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
      <div class="seg" style="margin-bottom:14px"><button class="${s.tab === 'folder' ? 'on' : ''}" data-action="scan-tab" data-t="folder">Ordner auf diesem PC</button><button class="${s.tab === 'image' ? 'on' : ''}" data-action="scan-tab" data-t="image">Container-Image</button></div>
      ${s.tab === 'folder' ? `
        <p class="small muted" style="margin-top:0">Wähle den Ordner mit der Software, die geprüft werden soll – z. B. den Projektordner einer HMI-Anwendung oder die Kopie des Dateisystems eines Linux-Geräts. Trivy (Version ${esc(Local.trivy)}) erkennt darin Software-Pakete und ihre bekannten Schwachstellen.</p>
        <div class="row" style="gap:6px;margin-bottom:8px">${d.shortcuts.map(x => `<button class="btn small" data-action="scan-dir" data-path="${esc(x.path)}">${esc(x.name)}</button>`).join('')}</div>
        <div class="pathbar"><button class="btn small" data-action="scan-dir" data-path="${esc(d.parent || '')}" ${d.parent ? '' : 'disabled'} title="Eine Ebene nach oben">↑ nach oben</button><code>${esc(d.path)}</code></div>
        <div class="dirlist" style="max-height:38vh">${d.dirs.length ? d.dirs.slice(0, 400).map(x => `<button class="dir" data-action="scan-dir" data-path="${esc(x.path)}">📁 ${esc(x.name)}</button>`).join('') : '<div class="small muted" style="padding:10px">Keine Unterordner.</div>'}</div>
        <div style="margin-top:12px"><div style="font-weight:550;font-size:.9rem;margin-bottom:6px">Was liegt in diesem Ordner?</div>
          <label class="check radio-card"><input type="radio" name="scanMode" value="fs" ${s.mode === 'fs' ? 'checked' : ''}><span><strong>Software-Projekt</strong><br><span class="muted small">Quellcode mit Paketlisten (z. B. package-lock.json, requirements.txt, pom.xml)</span></span></label>
          <label class="check radio-card" style="margin-top:6px"><input type="radio" name="scanMode" value="rootfs" ${s.mode === 'rootfs' ? 'checked' : ''}><span><strong>Installierte Software oder Geräte-Dateisystem</strong><br><span class="muted small">Programmordner, entpackte Firmware, kopiertes Linux-System${d.rootfs ? ' – <strong>hier erkannt</strong>' : ''}</span></span></label></div>
        <div class="row end" style="margin-top:14px"><button class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary big" data-action="scan-start">Diesen Ordner scannen</button></div>`
        : `
        <p class="small muted" style="margin-top:0">Name eines Container-Images, wie es auch bei Docker angegeben wird. Der PC braucht dafür Zugriff auf das Image (Docker Desktop oder die Registry).</p>
        <label class="field">Image-Name<input id="scanImage" placeholder="z. B. nginx:1.25 oder registry.firma.de/gateway:1.4"></label>
        <div class="row end" style="margin-top:14px"><button class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary big" data-action="scan-start">Image scannen</button></div>`}`;
  }

  /** Startet einen Scan über den lokalen Helfer und wartet mit Fortschrittsanzeige auf das Ergebnis (CycloneDX-Text). */
  async function runScan(mode, target, bomText, label) {
    await Local.startScan(mode, target, bomText);
    const job = ui.job = { cancelled: false };
    $('#modalTitle').textContent = 'Scan läuft …';
    $('#modalBody').innerHTML = `
      <p><strong>${esc(label)}</strong></p>
      <div class="progress indet"><span></span></div>
      <p class="small" id="scanTime">gestartet …</p>
      <p class="small muted" id="scanLog" style="min-height:2.6em;word-break:break-word"></p>
      <p class="small muted">Der erste Scan des Tages lädt die aktuelle Schwachstellen-Datenbank (ca. 130 MB) und dauert deshalb länger. Große Ordner können einige Minuten brauchen.</p>
      <div class="row end"><button class="btn" data-action="modal-close">Abbrechen</button></div>`;
    try {
      for (;;) {
        await sleep(1500);
        if (job.cancelled) { await Local.cancelScan().catch(() => {}); throw new Error('Scan abgebrochen.'); }
        const st = await Local.scanStatus();
        const tEl = $('#scanTime'), lEl = $('#scanLog');
        if (tEl) tEl.textContent = `Läuft seit ${Math.floor(st.seconds / 60)}:${String(st.seconds % 60).padStart(2, '0')} min`;
        if (lEl && st.log && st.log.length) lEl.textContent = st.log[st.log.length - 1].replace(/\t/g, ' ');
        if (st.state === 'done') return await Local.scanResult();
        if (st.state !== 'running') throw new Error('Trivy meldet einen Fehler: ' + ((st.log || []).filter(l => /ERROR|FATAL/.test(l)).pop() || (st.log || []).pop() || 'unbekannt').replace(/\t/g, ' '));
      }
    } finally { if (ui.job === job) ui.job = null; }
  }

  async function scanStart() {
    const s = ui.scan;
    let mode, target, label;
    if (s.tab === 'image') {
      target = ($('#scanImage').value || '').trim(); mode = 'image'; label = 'Container-Image ' + target;
      if (!target) return toast('Bitte einen Image-Namen eingeben');
    } else { mode = s.mode; target = s.dir.path; label = 'Ordner ' + target; }
    try {
      const text = await runScan(mode, target, null, label);
      importSbom(text, 'trivy.cdx.json', mode === 'fs' ? 'Tipp: Wenn nichts gefunden wurde, den Scan mit der Einstellung „Installierte Software oder Geräte-Dateisystem“ wiederholen.' : '');
    } catch (e) {
      if (/abgebrochen/.test(e.message)) return toast(e.message);
      openModal('Scan nicht erfolgreich', `<div class="callout danger">${esc(e.message)}</div><div class="row end"><button class="btn" data-action="scan-open">Zurück</button></div>`);
    }
  }

  // ---------- Automatische Schwachstellensuche ----------
  async function autoCheck() {
    const p = project();
    if (ui.job) return;
    const nvd = p.components.filter(c => checkKind(c) === 'nvd');
    const tv = p.components.filter(c => checkKind(c) === 'trivy');
    const none = p.components.filter(c => checkKind(c) === 'none');
    const useTrivy = tv.length && Local.trivy;
    const steps = nvd.length + (useTrivy ? 1 : 0);
    const rows = [];
    let added = 0;
    if (steps) {
      const job = ui.job = { cancelled: false };
      openModal('Schwachstellen werden gesucht', `
        <div class="progress"><span id="jobBar" style="width:0%"></span></div>
        <p id="jobText" style="margin-bottom:4px">Starte …</p>
        <p class="small muted" id="jobWait" style="min-height:1.4em"></p>
        <p class="small muted">Die NVD-Datenbank lässt nur 5 Abfragen pro 30 Sekunden zu. Die App reiht die Abfragen automatisch ein – bitte einfach warten.</p>
        <div class="row end"><button class="btn" data-action="modal-close">Abbrechen</button></div>`);
      const setP = (i, text) => { const b = $('#jobBar'), t = $('#jobText'), w = $('#jobWait'); if (b) b.style.width = Math.round(i / steps * 100) + '%'; if (t) t.textContent = text; if (w) w.textContent = ''; };
      let i = 0;
      for (const c of nvd) {
        if (job.cancelled) break;
        setP(i, `${i + 1} von ${steps}: ${c.name} ${c.version}`);
        try {
          const r = await Api.search(c, s => { const w = $('#jobWait'); if (w) w.textContent = `Warte auf die NVD – weiter in ${s} s`; });
          let n = 0; r.items.forEach(it => { if (addFinding(p, it, c.id)) n++; });
          added += n; rows.push({ name: c.name + ' ' + c.version, total: r.total, n, capped: r.total > r.items.length });
        } catch (e) { rows.push({ name: c.name + ' ' + c.version, err: e.message }); }
        i++;
      }
      if (useTrivy && !job.cancelled) {
        setP(i, `${i + 1} von ${steps}: ${tv.length} Software-Paket(e) mit Trivy prüfen`);
        try {
          await Local.startScan('sbom', null, JSON.stringify(CDX.build(Object.assign({}, p, { components: tv }), false)));
          let st;
          do { await sleep(1500); if (job.cancelled) { await Local.cancelScan().catch(() => {}); break; } st = await Local.scanStatus(); const w = $('#jobWait'); if (w) w.textContent = `Trivy läuft seit ${st.seconds} s`; } while (st.state === 'running');
          if (!job.cancelled) {
            if (st.state !== 'done') throw new Error((st.log || []).pop() || 'Trivy-Fehler');
            const r = parseSbom(await Local.scanResult(), 'trivy.cdx.json');
            const m = mergeImport(p, r, { onlyKnown: true });
            added += m.nv; rows.push({ name: `${tv.length} Software-Paket(e) über Trivy`, total: r.vulns.length, n: m.nv });
          }
        } catch (e) { rows.push({ name: 'Software-Pakete über Trivy', err: e.message }); }
      }
      const cancelled = job.cancelled;
      ui.job = null;
      save();
      if (cancelled) { render(); toast('Suche abgebrochen – bereits gefundene Schwachstellen wurden übernommen'); if (added) enrich(p, true); return; }
      setP(steps, 'Bedrohungsdaten (EPSS, aktiv ausgenutzte Schwachstellen) werden ergänzt …');
      await enrich(p, true).catch(() => {});
    }
    render();
    const tvSkipped = tv.length && !Local.trivy;
    openModal(steps ? 'Suche abgeschlossen' : 'Automatische Suche nicht möglich', `
      ${steps ? `<div class="callout ok"><strong>${added} neue Schwachstelle(n) übernommen.</strong> Insgesamt sind jetzt ${p.findings.length} erfasst.</div>
      <div class="table-wrap"><table><tbody>${rows.map(r => `<tr><td>${esc(r.name)}</td><td>${r.err ? `<span class="badge hoch">Fehler</span> <span class="small">${esc(r.err)}</span>` : r.total ? `${r.total} bekannt, ${r.n} neu übernommen${r.capped ? ' (nur die neuesten 500)' : ''}` : '<span class="muted">keine bekannten Schwachstellen</span>'}</td></tr>`).join('')}</tbody></table></div>` : ''}
      ${none.length ? `<div class="callout warn" style="margin-top:12px"><strong>${none.length} Komponente(n) konnten nicht automatisch geprüft werden</strong>, weil noch kein Produkt mit Version zugeordnet ist. Ein Klick auf „Zuordnen“ öffnet die Produktauswahl:
        <div class="dirlist" style="margin-top:8px;max-height:26vh">${none.slice(0, 40).map(c => `<button class="dir" data-action="comp-edit" data-id="${c.id}"><strong>${esc(c.name)} ${esc(c.version)}</strong><span class="muted small">Zuordnen →</span></button>`).join('')}</div></div>` : ''}
      ${tvSkipped ? `<div class="callout warn" style="margin-top:12px">${tv.length} Software-Paket(e) lassen sich nur mit Trivy prüfen. Das geht am Windows-PC, wenn die App über die Start-Datei geöffnet wurde.</div>` : ''}
      ${!steps && !none.length && !tvSkipped ? '<p>Es sind noch keine Komponenten erfasst.</p>' : ''}
      <div class="row end" style="margin-top:14px">${steps ? '<button class="btn" data-action="tab" data-tab="cves">Schwachstellen ansehen</button><button class="btn primary big" data-action="tab" data-tab="plan">Zum Maßnahmenplan →</button>' : '<button class="btn" data-action="modal-close">Schließen</button>'}</div>`);
  }

  // ---------- Datenoperationen ----------
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
    if (!quiet) toast(`Bedrohungsdaten aktualisiert${kev ? ' (KEV-Katalog ' + kev.version + ')' : ''}`);
  }

  async function fetchCves(btn) {
    const p = project();
    const ids = [...new Set(($('#cveIds').value.match(/CVE-\d{4}-\d{4,}/gi) || []).map(s => s.toUpperCase()))];
    if (!ids.length) return toast('Keine gültige CVE-Nummer erkannt (Form: CVE-2024-12345)');
    const comp = $('#cveComp').value;
    btn.disabled = true;
    const st = $('#fetchStatus');
    let ok = 0; const errs = [];
    for (const [i, id] of ids.entries()) {
      st.textContent = `Lade ${id} (${i + 1}/${ids.length}) …`;
      try {
        const d = await Api.getCve(id, s => { st.textContent = `Warte auf die NVD – weiter in ${s} s …`; });
        if (addFinding(p, Object.assign(d, { source: 'NVD' }), comp)) ok++;
      } catch (e) { errs.push(id + ': ' + e.message); }
    }
    save();
    toast(`${ok} Schwachstelle(n) übernommen${errs.length ? ' · ' + errs.length + ' Fehler' : ''}`);
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
    if (/\.csv$/i.test(name) || !/^\s*[{[]/.test(text)) {
      text.split(/\r?\n/).filter(l => l.trim()).forEach((l, i) => {
        const [n, v, ver, t, cpe] = l.split(/[;,\t]/).map(s => (s || '').trim().replace(/^"|"$/g, ''));
        if (i === 0 && /^name$/i.test(n)) return;
        if (n) comps.push({ name: n, vendor: v || '', version: ver || '', type: COMP_TYPES.includes(t) ? t : guessType(t, n), cpe: cpe || '' });
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
    } else throw new Error('Unbekanntes Dateiformat – erwartet wird CycloneDX (JSON), SPDX (JSON) oder CSV.');
  }

  /** Import zunächst analysieren und Zusammenfassung zeigen, dann übernehmen */
  let pendingImport = null;
  function importSbom(text, name, tip) {
    const p = project();
    const r = parseSbom(text, name);
    if (!r.comps.length) {
      return openModal('Nichts gefunden', `<p>${r.isTrivy ? 'Trivy hat in diesem Ziel keine Software-Pakete erkannt.' : 'Die Datei enthält keine Komponenten.'}</p>${tip ? `<p class="small muted">${esc(tip)}</p>` : ''}
        <div class="row end">${r.isTrivy && Local.trivy ? '<button class="btn" data-action="scan-open">Anderen Ordner scannen</button>' : ''}<button class="btn primary" data-action="modal-close">Schließen</button></div>`);
    }
    const affectedRefs = new Set(r.vulns.map(v => v.ref));
    const sev = { krit: 0, hoch: 0, mittel: 0, niedrig: 0 };
    r.vulns.forEach(v => { const s = v.cvss ? v.cvss.score : 0; sev[s >= 9 ? 'krit' : s >= 7 ? 'hoch' : s >= 4 ? 'mittel' : 'niedrig']++; });
    const nAff = r.comps.filter(c => affectedRefs.has(c.ref)).length;
    const nNb = r.vulns.filter(v => v.status === 'nb').length;
    pendingImport = r;
    openModal(r.isTrivy ? 'Scan-Ergebnis übernehmen' : 'Datei übernehmen', `
      <p><span class="badge outline">${esc(r.format || 'CSV')}</span> ${r.isTrivy ? '<span class="badge" style="background:var(--accent);color:#fff">Trivy</span>' : ''} ${r.tool ? `<span class="muted small">erstellt mit ${esc(r.tool)}</span>` : ''}</p>
      ${r.target ? `<p class="small muted" style="word-break:break-all">Scan-Ziel: <code>${esc(r.target)}</code></p>` : ''}
      <div class="grid kpi" style="margin:12px 0">
        <div class="kpi-tile"><div class="v">${r.comps.length}</div><div class="l">Komponenten</div></div>
        <div class="kpi-tile"><div class="v">${nAff}</div><div class="l">davon mit Schwachstellen</div></div>
        <div class="kpi-tile"><div class="v">${r.vulns.length}</div><div class="l">Schwachstellen</div></div>
      </div>
      ${r.vulns.length ? `<p class="small">Schweregrad (CVSS): <span class="badge krit">${sev.krit} kritisch</span> <span class="badge hoch">${sev.hoch} hoch</span> <span class="badge mittel">${sev.mittel} mittel</span> <span class="badge niedrig">${sev.niedrig} niedrig</span>${nNb ? ` · ${nNb} laut Datei nicht betroffen` : ''}</p>` : `<p class="small muted">Die Datei enthält nur Komponenten, keine Schwachstellen. Nach der Übernahme sucht „Schwachstellen jetzt suchen“ danach.</p>`}
      <form id="importForm" class="grid" style="gap:12px;margin-top:12px">
        <label class="check"><input type="checkbox" name="onlyAffected" ${r.isTrivy && r.comps.length > 20 ? 'checked' : ''} ${nAff ? '' : 'disabled'}><span><strong>Nur Komponenten mit Schwachstellen übernehmen</strong><br><span class="muted small">Empfohlen bei großen Scans, damit die Komponentenliste übersichtlich bleibt</span></span></label>
        <label class="field">Gehört zu Gerät <span class="hint">optional, z. B. der Bedien-IPC, auf dem die Software läuft</span>
          <select name="parentId"><option value="">– keine Zuordnung –</option>${p.components.filter(c => !c.parentId).map(c => `<option value="${c.id}">${esc(c.name)} ${esc(c.version)}</option>`).join('')}</select></label>
        <div class="row end"><button type="button" class="btn" data-action="modal-close">Abbrechen</button><button class="btn primary big">Übernehmen</button></div>
      </form>`);
  }

  /** Übernimmt geparste Komponenten/Schwachstellen ins Projekt. onlyKnown: keine neuen Komponenten anlegen (Re-Scan). */
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
      if (ref && !refMap[ref]) return; // Komponente nicht übernommen
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
    toast(`${m.nc} neue Komponente(n), ${m.nv} Schwachstelle(n) übernommen`);
    if (m.nv) enrich(p, true);
  }

  function exportCdx(p, withVulns) {
    const bom = CDX.build(p, withVulns, f => evaluate(p, f));
    download(fileSafe(p.name) + (withVulns ? '_sbom-vex' : '_sbom') + '.cdx.json', JSON.stringify(bom, null, 2), 'application/vnd.cyclonedx+json');
    closeModal();
    toast(`CycloneDX ${bom.specVersion} gespeichert (${bom.components.length} Komponenten${withVulns ? ', ' + bom.vulnerabilities.length + ' Schwachstellen' : ''})`);
  }

  function exportDialog() {
    openModal('Export im CycloneDX-Format', `
      <div class="menu-list">
        <button class="btn" data-action="cdx-sbom"><strong>Stückliste (SBOM)</strong>&nbsp;– nur die Komponenten</button>
        <button class="btn" data-action="cdx-vex"><strong>Stückliste + VEX</strong>&nbsp;– zusätzlich Schwachstellen, Status, Bewertung und Maßnahmen</button>
      </div>
      <p class="small muted" style="margin-top:12px">CycloneDX 1.6 (JSON) ist ein verbreitetes Standardformat für Software-Stücklisten. Beide Dateien lassen sich hier wieder importieren; die Stückliste kann auch von Trivy und anderen Werkzeugen gelesen werden.</p>`);
  }

  function download(name, content, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const fileSafe = s => s.replace(/[^\w\-äöüÄÖÜß]+/g, '_');

  function exportCsv(p) {
    const head = ['CVE', 'Komponente', 'Version', 'CVSS', 'Vektor', 'CWE', 'Aktiv ausgenutzt (KEV)', 'EPSS', 'W', 'A', 'Risiko', 'Stufe', 'Rest', 'Reststufe', 'Akzeptanz erreichbar', 'Status', 'Gewählte Maßnahmen', 'Empfohlene Maßnahmen', 'Notiz'];
    const q = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const title = id => (MITIGATIONS.find(m => m.id === id) || {}).title || id;
    const REACH = { now: 'ja, mit Sofortmaßnahmen', later: 'erst nach Patch/Austausch', none: 'nein – Entscheidung nötig' };
    const rows = p.findings.map(f => {
      const e = evaluate(p, f);
      return [f.cve, e.comp?.name, e.comp?.version, f.cvss?.score, f.cvss?.vector, (f.cwe || []).join(' '), f.kev ? 'ja' : 'nein', f.epss != null ? (f.epss * 100).toFixed(2) + '%' : '',
        e.base.L, e.base.I, e.base.score, e.base.level.label, e.res.score, e.res.eliminated ? 'behoben' : e.res.level.label, REACH[e.reach], STATUS[f.status || 'offen'],
        (f.mitigations || []).map(title).join(' | '), e.rec.map(title).join(' | '), f.note].map(q).join(';');
    });
    download(fileSafe(p.name) + '_Risikoanalyse.csv', '﻿' + [head.map(q).join(';'), ...rows].join('\r\n'), 'text/csv;charset=utf-8');
  }

  function pickFile(accept, cb) {
    const inp = $('#fileInput');
    inp.value = ''; inp.accept = accept;
    inp.onchange = () => { const f = inp.files[0]; if (!f) return; const r = new FileReader(); r.onload = () => cb(r.result, f.name); r.readAsText(f); };
    inp.click();
  }

  function loadDemo() {
    const d = window.DEMO_PROJECT;
    if (!d) return toast('Demo-Daten fehlen');
    const p = JSON.parse(JSON.stringify(d));
    p.id = uid(); p.created = new Date().toISOString();
    state.projects.push(p); state.currentId = p.id; save();
    ui.tab = 'cves'; closeModal(); render();
    toast('Beispiel geladen');
    enrich(p, true);
  }

  function importJson(txt) {
    const o = JSON.parse(txt);
    const list = o.projects ? o.projects : (o.findings && o.components) ? [o] : null;
    if (!list) throw new Error('Die Datei ist keine Sicherung und keine Analyse dieser App.');
    let n = 0;
    list.forEach(np => {
      np.ctx = Object.assign(defaultCtx(), np.ctx);
      const i = state.projects.findIndex(x => x.id === np.id);
      if (o.projects && i >= 0) state.projects[i] = np; // Sicherung: gleiche Analyse ersetzen
      else { if (i >= 0) np.id = uid(); state.projects.push(np); }
      state.currentId = np.id; n++;
    });
    save(); closeModal(); render(); toast(`${n} Analyse(n) geladen`);
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
        if (confirm(`„${c.name}“ löschen?${n ? ` ${n} zugeordnete Schwachstelle(n) werden ebenfalls entfernt.` : ''}`)) {
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
        save(); closeModal(); render(); toast(n + ' Schwachstelle(n) übernommen'); enrich(p, true);
        break;
      }
      case 'sbom-import': pickFile('.json,.csv,.cdx,.txt', (txt, name) => { try { importSbom(txt, name); } catch (err) { alert('Import nicht möglich: ' + err.message); } }); break;
      case 'scan-open': scanOpen(); break;
      case 'scan-tab': ui.scan.tab = t.dataset.t; renderScan(); break;
      case 'scan-dir': if (t.dataset.path) scanNavigate(t.dataset.path); break;
      case 'scan-start': scanStart(); break;
      case 'cdx-export': exportDialog(); break;
      case 'cdx-sbom': exportCdx(p, false); break;
      case 'cdx-vex': exportCdx(p, true); break;
      case 'copy': navigator.clipboard?.writeText(t.dataset.text).then(() => toast('Befehl kopiert'), () => toast('Kopieren nicht möglich')); break;
      case 'cve-fetch': fetchCves(t); break;
      case 'cve-manual': manualForm(); break;
      case 'enrich': t.disabled = true; await enrich(p).catch(err => toast(err.message)); t.disabled = false; break;
      case 'rec-apply': { const f = p.findings.find(x => x.id === fid); f.mitigations = [...evaluate(p, f).rec]; if (f.status === 'offen') f.status = 'umsetzung'; save(); render(); break; }
      case 'rec-all': {
        const todo = p.findings.filter(isOpenItem);
        const has = todo.filter(f => (f.mitigations || []).length).length;
        if (has && !confirm(`Bei ${has} Schwachstelle(n) ist bereits eine Auswahl getroffen. Diese durch die Empfehlung ersetzen?`)) break;
        todo.forEach(f => { f.mitigations = [...evaluate(p, f).rec]; if (f.status === 'offen') f.status = 'umsetzung'; });
        save(); render(); toast(`Empfehlungen für ${todo.length} Schwachstelle(n) übernommen`); break;
      }
      case 'finding-del': if (confirm('Schwachstelle entfernen?')) { p.findings = p.findings.filter(f => f.id !== fid); save(); render(); } break;
      case 'more': ui.limit += PAGE; render(); break;
      case 'cell': ui.cell = [+t.dataset.l, +t.dataset.i]; ui.tab = 'cves'; ui.limit = PAGE; render(); window.scrollTo(0, 0); break;
      case 'cell-clear': e.preventDefault(); ui.cell = null; render(); break;
      case 'mmode': ui.matrixMode = t.dataset.m; render(); break;
      case 'psrc': ui.planSource = t.dataset.s; render(); break;
      case 'print': window.print(); break;
      case 'csv': exportCsv(p); break;
      case 'export-json': download(fileSafe(p.name) + '.otrisk.json', JSON.stringify(p, null, 2), 'application/json'); closeModal(); break;
      case 'backup-all': download('OT-Risikoanalyse_Sicherung_' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify(state, null, 2), 'application/json'); closeModal(); toast('Sicherung gespeichert (Ordner „Downloads“)'); break;
      case 'import-json': pickFile('.json', txt => { try { importJson(txt); } catch (err) { alert('Laden nicht möglich: ' + err.message); } }); break;
      case 'project-dup': { const np = JSON.parse(JSON.stringify(p)); np.id = uid(); np.name += ' (Kopie)'; state.projects.push(np); state.currentId = np.id; save(); closeModal(); render(); break; }
      case 'project-del':
        if (p && confirm(`Analyse „${p.name}“ endgültig löschen? Das kann nicht rückgängig gemacht werden.`)) {
          state.projects = state.projects.filter(x => x.id !== p.id); state.currentId = state.projects[0]?.id || null; save(); closeModal(); render();
        }
        break;
      case 'wipe':
        if (confirm(`Wirklich ALLE ${state.projects.length} Analyse(n) auf diesem Gerät löschen? Das kann nicht rückgängig gemacht werden. Tipp: vorher „Sicherung speichern“.`)) {
          state = { projects: [], currentId: null };
          try { localStorage.removeItem('otr.kev'); } catch (err) { /* egal */ }
          save(); ui.tab = 'kontext'; closeModal(); render(); toast('Alle Daten gelöscht');
        }
        break;
    }
  });

  // Details einer Schwachstelle erst beim Aufklappen aufbauen (schnell auch bei Hunderten Einträgen)
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
    const formId = e.target.getAttribute('id'); // nicht e.target.id: ein Feld namens "id" würde es verdecken
    if (formId === 'projForm') {
      newProject(fd.name.trim(), fd.machine.trim(), fd.preset);
      ui.tab = 'sbom'; closeModal(); render();
      toast('Analyse angelegt – jetzt Komponenten hinzufügen');
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
        patchAvailable: !!fd.patch, references: [], kev: false, source: 'manuell'
      }, fd.componentId);
      if (!ok) return toast('Bereits vorhanden');
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
      try { if (localStorage.getItem(HAD)) { ui.noHelper = true; render(); } } catch (e) { /* egal */ }
      return;
    }
    {
      try { localStorage.setItem(HAD, '1'); } catch (e) { /* egal */ }
      try {
        const srv = await Local.loadData();
        if (srv && srv.projects && (srv.savedAt || 0) > (state.savedAt || 0)) {
          state = srv; // Datei auf dem PC ist neuer (z. B. Browserdaten wurden gelöscht)
          try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { /* voll */ }
          if (!project()) state.currentId = state.projects[0]?.id || null;
        } else if (state.projects.length && (!srv || (state.savedAt || 0) > (srv.savedAt || 0))) {
          Local.saveData(JSON.stringify(state)).catch(() => {});
        }
      } catch (e) { /* Datei noch nicht vorhanden */ }
      render();
    }
  }
  init();

  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) navigator.serviceWorker.register('sw.js').catch(() => {});
})();
