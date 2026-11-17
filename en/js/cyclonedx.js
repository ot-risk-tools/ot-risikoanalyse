/* CycloneDX: Import (inkl. Trivy-Scans, VEX) und Export (SBOM bzw. SBOM + VEX, Spec 1.6) */
(function () {
  'use strict';
  const APP = { name: 'OT Risk Analysis', version: '1.1.0' };

  const TYPE_IN = { library: 'Bibliothek', framework: 'Bibliothek', 'operating-system': 'Betriebssystem', platform: 'Betriebssystem', firmware: 'Firmware', application: 'Anwendung', container: 'Anwendung', 'device-driver': 'Firmware' };
  const TYPE_OUT = { SPS: 'device', HMI: 'device', IPC: 'device', Antrieb: 'device', Netzwerk: 'device', Betriebssystem: 'operating-system', Firmware: 'firmware', Bibliothek: 'library', Anwendung: 'application', Sonstiges: 'application' };
  const SEV_SCORE = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5 };

  const prop = (o, n) => ((o && o.properties) || []).find(p => p.name === n)?.value;

  /** Beste verfügbare CVSS-Bewertung: NVD vor GHSA vor Distributionen, v3.1 vor v4 vor v2 */
  function pickRating(ratings) {
    let best = null, bestRank = -1;
    (ratings || []).forEach(r => {
      if (r.score == null || r.method === 'other') return;
      const m = r.method || '';
      let rank = /CVSSv31|CVSSv3$/.test(m) ? 40 : /CVSSv4/.test(m) ? 35 : /CVSSv2/.test(m) ? 20 : 10;
      const src = (r.source && r.source.name || '').toLowerCase();
      rank += src === 'nvd' ? 5 : src === 'ghsa' ? 3 : 0;
      if (r.vector) rank += 2;
      if (rank > bestRank) { bestRank = rank; best = r; }
    });
    if (best) return { score: best.score, vector: best.vector || '', version: (best.method || '').replace('CVSSv31', '3.1').replace('CVSSv3', '3.0').replace('CVSSv4', '4.0').replace('CVSSv2', '2.0'), source: best.source && best.source.name };
    const sev = (ratings || []).find(r => r.severity && SEV_SCORE[r.severity] && r.method !== 'other');
    return sev ? { score: SEV_SCORE[sev.severity], vector: '', version: 'severity only', source: sev.source && sev.source.name } : null;
  }

  function statusFromAnalysis(a) {
    if (!a) return 'offen';
    const resp = a.response || [];
    if (['not_affected', 'false_positive'].includes(a.state)) return 'nb';
    if (['resolved', 'resolved_with_pertinent_requirement'].includes(a.state)) return 'mitigiert';
    if (resp.includes('will_not_fix')) return 'akzeptiert';
    if (a.state === 'exploitable' && resp.length) return 'umsetzung';
    return 'offen';
  }

  function parse(j, guessType) {
    const tools = j.metadata && j.metadata.tools;
    const toolList = Array.isArray(tools) ? tools : ((tools && tools.components) || []);
    const tool = toolList.map(t => [t.name, t.version].filter(Boolean).join(' ')).join(', ');
    const isTrivy = toolList.some(t => /trivy/i.test(t.name || ''));
    const target = (j.metadata && j.metadata.component && j.metadata.component.name) || '';
    const comps = [], vulns = [];

    const walk = arr => (arr || []).forEach(c => {
      // Trivy-Sammelknoten (z. B. requirements.txt, OS-Klasse) ohne Version überspringen
      const aggregate = prop(c, 'aquasecurity:trivy:Class') && !c.version;
      if (!aggregate) {
        const own = prop(c, 'otrisk:type');
        comps.push({
          ref: c['bom-ref'], name: c.name,
          vendor: (c.supplier && c.supplier.name) || c.publisher || (c.manufacturer && c.manufacturer.name) || c.group || '',
          version: c.version || '', cpe: c.cpe || '', purl: c.purl || '',
          type: own || (c.type !== 'application' && TYPE_IN[c.type]) || guessType(c.type, c.name),
          pkgType: prop(c, 'aquasecurity:trivy:PkgType') || ''
        });
      }
      walk(c.components);
    });
    walk(j.components);

    (j.vulnerabilities || []).forEach(v => {
      const a = v.analysis;
      const mits = prop(v, 'otrisk:mitigations');
      const base = {
        cve: v.id,
        description: v.description || v.detail || '',
        cvss: pickRating(v.ratings),
        cwe: (v.cwes || []).map(n => 'CWE-' + n),
        published: v.published || null,
        references: (v.advisories || []).slice(0, 15).map(x => ({ url: x.url, tags: [] })),
        patchAvailable: !!v.recommendation || !!(a && (a.response || []).includes('update')),
        fix: isTrivy ? (v.recommendation || '') : (prop(v, 'otrisk:fix') || ''),
        status: statusFromAnalysis(a),
        note: (a && a.detail) || '',
        mitigations: mits ? mits.split(',').filter(Boolean) : [],
        source: isTrivy ? 'Trivy' : (tool || 'CycloneDX'),
        kev: false
      };
      const affects = (v.affects && v.affects.length) ? v.affects : [{ ref: '' }];
      affects.forEach(x => vulns.push(Object.assign({ ref: x.ref }, JSON.parse(JSON.stringify(base)))));
    });
    return { comps, vulns, tool, isTrivy, target };
  }

  const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 3 | 8)).toString(16); }));
  const severity = s => s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : s > 0 ? 'low' : 'none';
  const LEVEL_SEV = { krit: 'critical', hoch: 'high', mittel: 'medium', niedrig: 'low' };
  const clean = o => JSON.parse(JSON.stringify(o)); // entfernt undefined

  function cvssMethod(c) {
    const v = (c.vector || '') + ' ' + (c.version || '');
    if (/CVSS:4|4\.0/.test(v)) return 'CVSSv4';
    if (/CVSS:3\.1|3\.1/.test(v)) return 'CVSSv31';
    if (/CVSS:3\.0|3\.0/.test(v)) return 'CVSSv3';
    if (/Au:|2\.0/.test(v)) return 'CVSSv2';
    return 'other';
  }

  function analysisFor(f, chosen) {
    const elim = chosen.some(id => id === 'patch' || id === 'replace');
    const detail = [f.note, chosen.length ? 'Measures: ' + chosen.map(id => (window.MITIGATIONS.find(m => m.id === id) || {}).title || id).join('; ') : ''].filter(Boolean).join(' | ') || undefined;
    switch (f.status) {
      case 'nb': return { state: 'not_affected', detail };
      case 'mitigiert': return { state: elim ? 'resolved' : 'resolved_with_pertinent_requirement', detail };
      case 'akzeptiert': return { state: 'exploitable', response: ['will_not_fix'], detail };
      case 'umsetzung': return { state: 'exploitable', response: [chosen.includes('patch') ? 'update' : 'workaround_available'], detail };
      default: return { state: 'in_triage', detail };
    }
  }

  /** evaluate(f) -> {base,res,rec} aus app.js */
  function build(p, withVulns, evaluate) {
    const now = new Date().toISOString();
    const comps = p.components.map(c => clean({
      'bom-ref': c.id, type: TYPE_OUT[c.type] || 'application',
      supplier: c.vendor ? { name: c.vendor } : undefined,
      name: c.name, version: c.version || undefined, cpe: c.cpe || undefined, purl: c.purl || undefined,
      properties: [{ name: 'otrisk:type', value: c.type }]
    }));
    const bom = {
      bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: 'urn:uuid:' + uuid(), version: 1,
      metadata: clean({
        timestamp: now,
        tools: { components: [{ type: 'application', name: APP.name, version: APP.version }] },
        // Wurzel als "application": Trivy akzeptiert "device" als Wurzeltyp nicht
        component: { 'bom-ref': 'machine', type: 'application', name: p.machine || p.name, description: p.description || undefined, properties: [{ name: 'otrisk:kind', value: 'machine' }] },
        properties: [{ name: 'otrisk:project', value: p.name }].concat(p.customer ? [{ name: 'otrisk:customer', value: p.customer }] : [])
      }),
      components: comps,
      dependencies: [{ ref: 'machine', dependsOn: p.components.map(c => c.id) }]
    };
    if (withVulns) {
      bom.vulnerabilities = p.findings.filter(f => f.componentId).map(f => {
        const e = evaluate(f);
        const chosen = f.mitigations || [];
        const ratings = [];
        if (f.cvss && f.cvss.score != null) ratings.push(clean({ source: { name: f.cvss.source || 'NVD' }, score: f.cvss.score, severity: severity(f.cvss.score), method: cvssMethod(f.cvss), vector: f.cvss.vector || undefined }));
        if (f.status !== 'nb') ratings.push({ source: { name: APP.name }, score: e.base.score, severity: LEVEL_SEV[e.base.level.key], method: 'other', justification: `Context rating likelihood ${e.base.L} × impact ${e.base.I} = ${e.base.score}; residual risk ${e.res.score} (${e.res.level.label})` });
        const isCve = /^CVE-/i.test(f.cve);
        return clean({
          'bom-ref': 'vuln-' + f.id, id: f.cve,
          source: isCve ? { name: 'NVD', url: 'https://nvd.nist.gov/vuln/detail/' + f.cve } : undefined,
          ratings, cwes: (f.cwe || []).map(c => parseInt(String(c).replace(/\D/g, ''), 10)).filter(n => !isNaN(n)),
          description: f.description || undefined,
          recommendation: e.rec.map(id => (window.MITIGATIONS.find(m => m.id === id) || {}).title).filter(Boolean).join('; ') || undefined,
          advisories: (f.references || []).slice(0, 10).map(r => ({ url: r.url })),
          published: f.published ? (/[zZ]|[+-]\d\d:?\d\d$/.test(f.published) ? f.published : f.published + 'Z') : undefined,
          analysis: analysisFor(f, chosen),
          affects: [{ ref: f.componentId }],
          properties: [
            { name: 'otrisk:likelihood', value: String(e.base.L) }, { name: 'otrisk:impact', value: String(e.base.I) },
            { name: 'otrisk:residual', value: String(e.res.score) }, { name: 'otrisk:mitigations', value: chosen.join(',') },
            { name: 'otrisk:kev', value: String(!!f.kev) }
          ].concat(f.epss != null ? [{ name: 'otrisk:epss', value: String(f.epss) }] : []).concat(f.fix ? [{ name: 'otrisk:fix', value: f.fix }] : [])
        });
      });
    }
    return bom;
  }

  window.CDX = { parse, build, pickRating };
})();
