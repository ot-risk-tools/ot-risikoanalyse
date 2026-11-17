/* Risikobewertung: CVSS-Vektor + Maschinenkontext -> Eintrittswahrscheinlichkeit x Auswirkung (5x5) */
(function () {
  'use strict';

  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

  /** Normalisiert CVSS v2 / v3.x / v4.0 Vektoren auf {AV,AC,PR,UI,S,C,I,A} */
  function parseVector(vector) {
    const out = { AV: null, AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N', version: null };
    if (!vector) return out;
    const parts = {};
    vector.split('/').forEach(p => { const [k, v] = p.split(':'); if (k && v) parts[k] = v; });
    if (parts.CVSS && parts.CVSS.startsWith('4')) {
      out.version = '4.0';
      out.AV = parts.AV; out.AC = (parts.AC === 'H' || parts.AT === 'P') ? 'H' : 'L';
      out.PR = parts.PR || 'N'; out.UI = (parts.UI && parts.UI !== 'N') ? 'R' : 'N';
      out.C = parts.VC || 'N'; out.I = parts.VI || 'N'; out.A = parts.VA || 'N';
      out.S = [parts.SC, parts.SI, parts.SA].includes('H') ? 'C' : 'U';
    } else if (parts.CVSS) {
      out.version = parts.CVSS;
      Object.assign(out, { AV: parts.AV, AC: parts.AC, PR: parts.PR, UI: parts.UI, S: parts.S, C: parts.C, I: parts.I, A: parts.A });
    } else if (parts.Au) {
      out.version = '2.0';
      const m = { N: 'N', P: 'L', C: 'H' };
      out.AV = parts.AV; out.AC = parts.AC === 'H' ? 'H' : 'L';
      out.PR = { N: 'N', S: 'L', M: 'H' }[parts.Au] || 'N';
      out.C = m[parts.C] || 'N'; out.I = m[parts.I] || 'N'; out.A = m[parts.A] || 'N';
    }
    return out;
  }

  const AV_LABEL = { N: 'network', A: 'adjacent network', L: 'local', P: 'physical' };

  /** Likelihood 1..5 including reasons */
  function likelihood(v, ctx, f) {
    const why = [];
    let s = { N: 3, A: 2.5, L: 2, P: 1 }[v.AV] ?? 3;
    why.push(`Attack vector ${AV_LABEL[v.AV] || 'unknown'} → ${s}`);
    if (v.AC === 'H') { s -= 1; why.push('high attack complexity −1'); }
    if (v.PR === 'L') { s -= 0.5; why.push('privileges required (low) −0.5'); }
    if (v.PR === 'H') { s -= 1; why.push('admin privileges required −1'); }
    if (v.UI === 'R') { s -= 0.5; why.push('user interaction required −0.5'); }
    if (v.AV === 'N' || v.AV === 'A') {
      const d = { 1: -1.5, 2: -0.5, 3: 0, 4: 1.5 }[ctx.exposure] ?? 0;
      if (d) { s += d; why.push(`network exposure (${EXPOSURE[ctx.exposure]}) ${d > 0 ? '+' : '−'}${Math.abs(d)}`); }
      if (ctx.remoteAccess && ctx.exposure < 4) { s += 0.5; why.push('remote maintenance access +0.5'); }
    } else {
      const d = { 1: -0.5, 2: 0, 3: 0.5 }[ctx.physical] ?? 0;
      if (d) { s += d; why.push(`physical access (${PHYSICAL[ctx.physical]}) ${d > 0 ? '+' : '−'}0.5`); }
    }
    if (f.kev) { s += 1.5; why.push('actively exploited (CISA KEV) +1.5'); }
    else if (f.epss >= 0.5) { s += 1; why.push(`EPSS ${(f.epss * 100).toFixed(1)}% +1`); }
    else if (f.epss >= 0.1) { s += 0.5; why.push(`EPSS ${(f.epss * 100).toFixed(1)}% +0.5`); }
    return { value: clamp(Math.round(s), 1, 5), why };
  }

  /** Auswirkung 1..5 – OT-Priorisierung: Verfügbarkeit/Integrität vor Vertraulichkeit */
  function impact(v, ctx) {
    const w = { H: 1, L: 0.5, N: 0 };
    const why = [];
    const a = (w[v.A] || 0) * (2 + ctx.availability);
    const i = (w[v.I] || 0) * (2 + Math.max(ctx.safety, ctx.availability));
    const c = (w[v.C] || 0) * (2 + ctx.confidentiality);
    if (a) why.push(`Availability (${v.A}) × production criticality → ${a}`);
    if (i) why.push(`Integrity (${v.I}) × safety/production → ${i}`);
    if (c) why.push(`Confidentiality (${v.C}) × know-how protection → ${c}`);
    let s = Math.max(a, i, c, 1);
    if (v.S === 'C') { s += 0.5; why.push('scope change (impact on other components) +0.5'); }
    return { value: clamp(Math.round(s), 1, 5), why };
  }

  // Keys stay German on purpose: they are shared with the German edition (same stored data, same CSS classes)
  function level(score) {
    if (score >= 15) return { key: 'krit', label: 'Critical' };
    if (score >= 10) return { key: 'hoch', label: 'High' };
    if (score >= 5) return { key: 'mittel', label: 'Medium' };
    return { key: 'niedrig', label: 'Low' };
  }

  function assess(f, ctx) {
    const v = parseVector(f.cvss && f.cvss.vector);
    if (!v.AV) { // kein Vektor: konservative Annahme aus Basisscore
      const sc = (f.cvss && f.cvss.score) || 5;
      v.AV = 'N'; v.C = v.I = v.A = sc >= 7 ? 'H' : 'L';
    }
    const L = likelihood(v, ctx, f);
    const I = impact(v, ctx);
    const score = L.value * I.value;
    return { v, L: L.value, I: I.value, score, level: level(score), whyL: L.why, whyI: I.why };
  }

  /** Restrisiko nach ausgewählten Maßnahmen */
  function residual(f, ctx, base, mitigationIds) {
    const cat = window.MITIGATIONS;
    const sel = (mitigationIds || []).map(id => cat.find(m => m.id === id)).filter(Boolean);
    // Patch/Austausch beseitigt die Schwachstelle: kein Restrisiko aus dieser CVE
    if (sel.some(m => m.eliminates)) return { L: 1, I: 1, score: 1, level: level(1), eliminated: true };
    let L = base.L, I = base.I;
    const dL = Math.min(sel.reduce((s, m) => s + (m.dL || 0), 0), 3);
    L = clamp(Math.round(L - dL), 1, 5);
    const dI = Math.min(sel.reduce((s, m) => s + (m.dI || 0), 0), 2);
    I = clamp(Math.round(I - dI), 1, 5);
    const score = L * I;
    return { L, I, score, level: level(score) };
  }

  const EXPOSURE = { 1: 'isolated / air gap', 2: 'cell behind a firewall', 3: 'production network / linked to office IT', 4: 'reachable from internet / cloud' };
  const PHYSICAL = { 1: 'locked', 2: 'shop floor', 3: 'public / external staff' };

  window.Risk = { parseVector, assess, residual, level, EXPOSURE, PHYSICAL, AV_LABEL };
})();
