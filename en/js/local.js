/* Verbindung zum lokalen Helfer (tools/server.ps1). Ohne Helfer – z. B. auf iPhone/iPad oder
 * bei gehosteter App – bleibt alles nutzbar, nur Scannen per Klick und die Datei-Sicherung entfallen. */
(function () {
  'use strict';
  const H = { 'X-OTR': '1' };
  async function call(path, opts) {
    const r = await fetch(path, Object.assign({ headers: H, cache: 'no-store' }, opts));
    if (!r.ok) {
      let msg = 'Error ' + r.status;
      try { msg = (await r.json()).error || msg; } catch (e) { /* kein JSON */ }
      throw new Error(msg);
    }
    return r;
  }
  window.Local = {
    available: false, trivy: null, dataFile: '',
    async detect() {
      try {
        const r = await fetch('../api/status', { cache: 'no-store' });
        if (!r.ok) return false;
        const j = await r.json();
        if (j.app !== 'ot-risikoanalyse') return false;
        this.available = true; this.trivy = j.trivy || null; this.dataFile = j.dataFile || '';
        return true;
      } catch (e) { return false; }
    },
    async loadData() { return (await call('../api/data')).json(); },
    async saveData(text) { await call('../api/data', { method: 'POST', body: text }); },
    async dirs(path) { return (await call('../api/dirs' + (path ? '?path=' + encodeURIComponent(path) : ''))).json(); },
    async startScan(mode, target, bomText) {
      const qs = 'mode=' + encodeURIComponent(mode) + (target ? '&target=' + encodeURIComponent(target) : '');
      await call('../api/scan?' + qs, { method: 'POST', body: bomText || null });
    },
    async scanStatus() { return (await call('../api/scan')).json(); },
    async scanResult() { return (await call('../api/scan/result')).text(); },
    async cancelScan() { await call('../api/scan/cancel', { method: 'POST' }); }
  };
})();
