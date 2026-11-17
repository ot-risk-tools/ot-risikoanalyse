/* Maßnahmenkatalog mit Bezug zu IEC 62443-3-3 (System Requirements) und IEC 62443-2-3 (Patch-Management).
 * applies(f, v, comp, ctx) liefert Relevanz 0..3 (0 = nicht anwendbar).
 * dL/dI = Reduktion Eintrittswahrscheinlichkeit/Auswirkung, eliminates = beseitigt Schwachstelle.
 */
(function () {
  'use strict';
  const hasCwe = (f, list) => (f.cwe || []).some(c => list.includes(c));
  const net = v => v.AV === 'N' || v.AV === 'A';
  const isType = (comp, types) => comp && types.includes(comp.type);

  const CWE = {
    auth: ['CWE-287', 'CWE-306', 'CWE-288', 'CWE-290', 'CWE-294', 'CWE-307', 'CWE-1390', 'CWE-1188'],
    creds: ['CWE-798', 'CWE-259', 'CWE-321', 'CWE-521', 'CWE-1391', 'CWE-1392', 'CWE-522', 'CWE-256'],
    web: ['CWE-79', 'CWE-352', 'CWE-22', 'CWE-89', 'CWE-434', 'CWE-601', 'CWE-918', 'CWE-1021', 'CWE-23'],
    mem: ['CWE-787', 'CWE-119', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-125', 'CWE-416', 'CWE-190', 'CWE-476', 'CWE-415'],
    inject: ['CWE-77', 'CWE-78', 'CWE-94', 'CWE-502', 'CWE-917', 'CWE-20'],
    dos: ['CWE-400', 'CWE-770', 'CWE-835', 'CWE-674', 'CWE-1333', 'CWE-404', 'CWE-754'],
    crypto: ['CWE-319', 'CWE-311', 'CWE-327', 'CWE-326', 'CWE-295', 'CWE-312', 'CWE-330', 'CWE-347', 'CWE-325'],
    integrity: ['CWE-494', 'CWE-345', 'CWE-347', 'CWE-354', 'CWE-353'],
    priv: ['CWE-269', 'CWE-250', 'CWE-284', 'CWE-285', 'CWE-862', 'CWE-863', 'CWE-732', 'CWE-276'],
    info: ['CWE-200', 'CWE-209', 'CWE-532', 'CWE-668']
  };

  window.CWE_GROUPS = CWE;

  window.MITIGATIONS = [
    {
      id: 'patch', cat: 'Patch', title: 'Sicherheitsupdate / Firmware-Update einspielen',
      sr: ['IEC 62443-2-3', 'SR 3.4'], sl: 1, effort: 2, eliminates: true,
      applies: (f, v, c, ctx) => f.patchAvailable ? (ctx.patchable === false ? 1 : 3) : 0,
      text: 'Herstellerupdate einspielen, das die Schwachstelle behebt.',
      steps: ['Kompatibilität mit Maschinensoftware/Freigabeliste des Herstellers prüfen', 'Update auf Test- bzw. Referenzanlage (digitaler Zwilling) validieren', 'Backup von Projekt, Firmware und Konfiguration erstellen', 'Wartungsfenster mit Produktion abstimmen, Rückfallplan festlegen', 'Update einspielen, Funktions- und Safety-Test, SBOM aktualisieren']
    },
    {
      id: 'kev', cat: 'Organisatorisch', title: 'Notfall-Change: Behandlung innerhalb 72 h',
      sr: ['IEC 62443-2-1 SPE'], sl: 1, effort: 1, dL: 0,
      applies: f => f.kev ? 3 : 0,
      text: 'Die Schwachstelle wird aktiv ausgenutzt (CISA KEV). Sofortmaßnahmen außerhalb des regulären Patch-Zyklus einleiten.',
      steps: ['Betroffene Maschinen/Kunden identifizieren (SBOM-Abgleich)', 'Kunden und Service per Security Advisory informieren', 'Kompensierende Maßnahmen sofort umsetzen, Patch priorisieren']
    },
    {
      id: 'seg', cat: 'Technisch', title: 'Netzsegmentierung nach Zonen & Conduits',
      sr: ['SR 5.1', 'SR 5.2'], sl: 1, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) ? (ctx.exposure >= 3 ? 3 : 2) : 0,
      text: 'Maschine als eigene Sicherheitszone abgrenzen; Kommunikation nur über definierte Conduits.',
      steps: ['Zonenmodell der Maschine/Linie dokumentieren', 'Maschinennetz per VLAN/eigener Firewall vom Produktions- und Office-Netz trennen', 'Kein direkter Zugriff aus dem Office-Netz – nur über DMZ']
    },
    {
      id: 'fw', cat: 'Technisch', title: 'Firewall-Regelwerk: Allowlist nur benötigter Protokolle/Ports',
      sr: ['SR 5.2', 'SR 7.6'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => net(v) ? 2 : 0,
      text: 'Am Zonenübergang nur explizit benötigte Verbindungen erlauben (Default Deny).',
      steps: ['Kommunikationsmatrix (Quelle, Ziel, Port, Protokoll) erstellen', 'Betroffenen Dienst/Port am Übergang sperren, sofern nicht zwingend benötigt', 'Regelwerk regelmäßig reviewen']
    },
    {
      id: 'remote', cat: 'Technisch', title: 'Fernwartung absichern (VPN, MFA, Freigabe durch Betreiber)',
      sr: ['SR 1.13', 'SR 2.6', 'SR 1.1'], sl: 2, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) && (ctx.remoteAccess || ctx.exposure >= 4) ? 3 : 0,
      text: 'Fernzugriff nur über zentralen Remote-Access-Gateway mit Mehrfaktor-Authentifizierung und Freischaltung durch den Betreiber.',
      steps: ['Keine direkten Portweiterleitungen / öffentlich erreichbaren Dienste', 'MFA und personenbezogene Accounts', 'Session-Freigabe vor Ort (Schlüsselschalter/Ticket), Sitzungs-Timeout und Protokollierung']
    },
    {
      id: 'auth', cat: 'Technisch', title: 'Authentifizierung aktivieren, Standardpasswörter ersetzen',
      sr: ['SR 1.1', 'SR 1.5', 'SR 1.7'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => hasCwe(f, CWE.auth) || hasCwe(f, CWE.creds) ? 3 : (v.PR === 'N' && net(v) ? 1 : 0),
      text: 'Zugriffsschutz an der Komponente aktivieren (z. B. Schutzstufe/Passwort an SPS, HMI-Benutzerverwaltung).',
      steps: ['Standard- und Herstellerpasswörter ändern, maschinenindividuelle Passwörter', 'Zugriffsschutzstufe der Steuerung auf höchste praktikable Stufe setzen', 'Passwort-Richtlinie (Länge, Sperre nach Fehlversuchen)']
    },
    {
      id: 'hardcoded', cat: 'Organisatorisch', title: 'Fest codierte Zugangsdaten: Herstellerfix einfordern, Dienst isolieren',
      sr: ['SR 1.5', 'SR 5.2'], sl: 1, effort: 2, dL: 1,
      applies: f => hasCwe(f, ['CWE-798', 'CWE-259', 'CWE-321']) ? 3 : 0,
      text: 'Fest eingebaute Zugangsdaten lassen sich nicht ändern – betroffene Schnittstelle konsequent unerreichbar machen und Hersteller zur Behebung auffordern.',
      steps: ['Betroffenen Dienst/Port identifizieren und am Übergang sperren', 'Lieferantenanfrage (PSIRT) mit Frist stellen', 'Ersatz der Komponente in Roadmap aufnehmen']
    },
    {
      id: 'harden', cat: 'Technisch', title: 'Härtung: nicht benötigte Dienste und Schnittstellen deaktivieren',
      sr: ['SR 7.7', 'SR 7.6'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => net(v) ? 2 : 1,
      text: 'Angriffsfläche reduzieren: ungenutzte Dienste (Webserver, SNMP, FTP, Telnet, Debug-Ports) abschalten.',
      steps: ['Port-Scan / Konfigurationsprüfung der Komponente', 'Nicht benötigte Dienste in der Gerätekonfiguration deaktivieren', 'Härtungsvorgabe in Maschinen-Standardkonfiguration übernehmen']
    },
    {
      id: 'web', cat: 'Technisch', title: 'Webinterface deaktivieren oder nur aus Engineering-Zone erreichbar',
      sr: ['SR 7.7', 'SR 5.2'], sl: 1, effort: 1, dL: 1,
      applies: f => hasCwe(f, CWE.web) ? 3 : 0,
      text: 'Schwachstelle betrifft die Weboberfläche – Webserver der Komponente abschalten oder Zugriff auf Engineering-Stationen beschränken.',
      steps: ['Webserver in Gerätekonfiguration deaktivieren, falls im Betrieb nicht benötigt', 'Sonst: Zugriff per Firewall auf definierte Engineering-IP begrenzen', 'Browser-Nutzung auf Engineering-Stationen absichern (kein paralleles Surfen)']
    },
    {
      id: 'removable', cat: 'Technisch', title: 'Physischen Zugang & Wechseldatenträger kontrollieren',
      sr: ['SR 2.3', 'SR 3.2'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => (v.AV === 'P' || v.AV === 'L') ? 3 : 0,
      text: 'Lokale/physische Angriffswege einschränken.',
      steps: ['Schaltschrank verschließen, Zugang nur für befugtes Personal', 'USB-Schnittstellen sperren oder nur geprüfte Datenträger (Schleuse/Kiosk-Scan)', 'Ungenutzte Netzwerkports physisch blockieren']
    },
    {
      id: 'least', cat: 'Technisch', title: 'Rollen- und Rechtekonzept (Least Privilege)',
      sr: ['SR 2.1', 'SR 1.3'], sl: 1, effort: 2, dL: 0.5,
      applies: (f, v) => hasCwe(f, CWE.priv) ? 3 : (v.PR === 'L' ? 2 : 0),
      text: 'Benutzer nur mit minimal notwendigen Rechten ausstatten; Bediener, Instandhaltung und Engineering trennen.',
      steps: ['Rollen definieren (Bediener, Einrichter, Service, Admin)', 'Keine Admin-Rechte für Bedien-Accounts', 'Regelmäßige Rezertifizierung der Berechtigungen']
    },
    {
      id: 'aware', cat: 'Organisatorisch', title: 'Sensibilisierung von Bedienern und Servicepersonal',
      sr: ['IEC 62443-2-1 ORG'], sl: 1, effort: 1, dL: 0.5,
      applies: (f, v) => v.UI === 'R' ? 2 : 0,
      text: 'Die Ausnutzung erfordert eine Benutzeraktion (z. B. Öffnen einer Datei/eines Links). Schulung reduziert die Wahrscheinlichkeit.',
      steps: ['Schulung zu manipulierten Projektdateien, Phishing und USB-Sticks', 'Nur Projektdateien aus vertrauenswürdiger Quelle öffnen', 'Meldeweg für Auffälligkeiten festlegen']
    },
    {
      id: 'malware', cat: 'Technisch', title: 'Application Whitelisting / Malware-Schutz auf IPC & HMI',
      sr: ['SR 3.2'], sl: 1, effort: 2, dL: 1,
      applies: (f, v, c) => isType(c, ['IPC', 'HMI', 'Betriebssystem']) && (hasCwe(f, CWE.mem) || hasCwe(f, CWE.inject) || v.I === 'H') ? 3 : (isType(c, ['IPC', 'HMI', 'Betriebssystem']) ? 1 : 0),
      text: 'Auf PC-basierten Komponenten nur freigegebene Programme zulassen (Allowlisting), OT-taugliches Malware-Schutzkonzept.',
      steps: ['Allowlisting-Lösung mit Herstellerfreigabe einsetzen', 'Autostart/Skripting für Bedien-Accounts einschränken', 'Signaturen/Regeln im Wartungsfenster aktualisieren']
    },
    {
      id: 'virtpatch', cat: 'Technisch', title: 'Virtuelles Patchen (IPS / Deep Packet Inspection am Zonenübergang)',
      sr: ['SR 5.2', 'SR 3.2'], sl: 2, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) && (!f.patchAvailable || ctx.patchable === false) ? 3 : (net(v) ? 1 : 0),
      text: 'Wenn kein Patch eingespielt werden kann: Angriffsmuster am Übergang erkennen und blockieren (industrielle Firewall mit DPI/IPS für S7, Modbus, OPC UA …).',
      steps: ['IPS-Signatur für CVE bzw. Protokollfilter (z. B. nur Lesezugriffe) aktivieren', 'Schreibende Zugriffe auf die Steuerung nur von Engineering-Station erlauben', 'Wirksamkeit dokumentieren (kompensierende Maßnahme nach IEC 62443-3-3)']
    },
    {
      id: 'monitor', cat: 'Technisch', title: 'OT-Netzwerk-Monitoring & Anomalieerkennung',
      sr: ['SR 6.2', 'SR 2.8'], sl: 2, effort: 3, dL: 0.5,
      applies: (f, v) => net(v) ? 1 : 0,
      text: 'Passive Überwachung des Maschinennetzes erkennt Ausnutzungsversuche und unbekannte Geräte.',
      steps: ['Passiven Sensor (SPAN-Port) am Maschinenswitch platzieren', 'Alarme für neue Verbindungen, Programmänderungen, Stop-Befehle', 'Anbindung an Betreiber-SOC/SIEM']
    },
    {
      id: 'logging', cat: 'Technisch', title: 'Security-Logging und zentrale Auswertung',
      sr: ['SR 2.8', 'SR 6.1'], sl: 1, effort: 2, dL: 0.5,
      applies: (f, v) => (hasCwe(f, CWE.auth) || hasCwe(f, CWE.priv)) ? 2 : (v.PR !== 'N' ? 1 : 0),
      text: 'Anmeldungen, Konfigurations- und Programmänderungen protokollieren, um Missbrauch zu erkennen.',
      steps: ['Syslog der Komponenten aktivieren', 'Zeitsynchronisation (NTP) sicherstellen', 'Regelmäßige Auswertung bzw. Alarmierung']
    },
    {
      id: 'dos', cat: 'Technisch', title: 'Schutz vor Überlast / Denial-of-Service',
      sr: ['SR 7.1', 'SR 7.2'], sl: 1, effort: 1, dL: 0.5,
      applies: (f, v) => net(v) && (hasCwe(f, CWE.dos) || (v.A === 'H' && v.C === 'N' && v.I === 'N')) ? 3 : 0,
      text: 'Netzlast und Verbindungsanzahl zur Komponente begrenzen, damit die Steuerung nicht in STOP geht.',
      steps: ['Rate-Limiting / Broadcast-Storm-Schutz am Switch', 'Verbindungslimits an der Firewall', 'Definierten sicheren Zustand bei Kommunikationsausfall prüfen']
    },
    {
      id: 'crypto', cat: 'Technisch', title: 'Verschlüsselte und authentisierte Kommunikation',
      sr: ['SR 3.1', 'SR 4.1', 'SR 4.3'], sl: 2, effort: 2, dL: 0.5,
      applies: (f, v) => hasCwe(f, CWE.crypto) ? 3 : 0,
      text: 'Sichere Protokollvarianten nutzen (z. B. TLS ≥ 1.2, OPC UA SignAndEncrypt, PG/PC-Kommunikation mit Zertifikaten).',
      steps: ['Unsichere Protokolle/Cipher deaktivieren', 'Gerätezertifikate einführen und verwalten', 'Schlüssel/Zertifikate maschinenindividuell erzeugen']
    },
    {
      id: 'integrity', cat: 'Technisch', title: 'Integritätsschutz von Firmware und Steuerungsprogramm',
      sr: ['SR 3.4', 'SR 3.3'], sl: 2, effort: 2, dL: 0.5, dI: 0.5,
      applies: (f, v, c) => hasCwe(f, CWE.integrity) ? 3 : (v.I === 'H' && isType(c, ['SPS', 'Firmware', 'Antrieb']) ? 2 : 0),
      text: 'Nur signierte Firmware zulassen; Programm-/Konfigurationsänderungen erkennen.',
      steps: ['Signaturprüfung bei Firmware-Updates aktivieren', 'Prüfsummen-/Versionsvergleich des SPS-Programms (Change Detection)', 'Know-how- und Kopierschutz der Bausteine aktivieren']
    },
    {
      id: 'backup', cat: 'Technisch', title: 'Backup & Wiederherstellungskonzept',
      sr: ['SR 7.3', 'SR 7.4'], sl: 1, effort: 1, dI: 1,
      applies: (f, v) => (v.A === 'H' || v.I === 'H') ? 2 : 0,
      text: 'Schnelle Wiederherstellung begrenzt Stillstand nach einem erfolgreichen Angriff.',
      steps: ['Regelmäßige Sicherung von SPS-Projekt, HMI, Antriebsparametern und IPC-Images', 'Offline-Kopie aufbewahren', 'Wiederherstellung regelmäßig testen (Restore-Zeit dokumentieren)']
    },
    {
      id: 'safety', cat: 'Technisch', title: 'Unabhängige Sicherheitsfunktion prüfen (Safety ≠ Security)',
      sr: ['IEC 62443-3-2 ZCR 5', 'ISO 13849 / IEC 62061'], sl: 1, effort: 2, dI: 1,
      applies: (f, v, c, ctx) => (v.I === 'H' || v.A === 'H') && ctx.safety >= 2 ? 3 : 0,
      text: 'Sicherstellen, dass Personenschutz auch bei manipulierter Standardsteuerung wirkt (Safety-SPS, hartverdrahtete Not-Halt-Kreise, mechanische Schutzeinrichtungen).',
      steps: ['Prüfen, ob Safety-Funktionen von der betroffenen Komponente abhängen', 'Safety-Programm durch separates Passwort/F-Signatur schützen', 'Ergebnis in Risikobeurteilung nach Maschinenrichtlinie / Maschinenverordnung dokumentieren']
    },
    {
      id: 'vendor', cat: 'Organisatorisch', title: 'Hersteller-Advisory auswerten und Workarounds umsetzen',
      sr: ['IEC 62443-2-3', 'IEC 62443-4-1 DM'], sl: 1, effort: 1, dL: 0.5,
      applies: () => 1,
      text: 'Security Advisory des Herstellers (z. B. Siemens ProductCERT, CERT@VDE, CISA ICS) prüfen – oft sind konkrete Workarounds beschrieben.',
      steps: ['Advisory zur CVE beim Komponentenhersteller suchen', 'Beschriebene Workarounds bewerten und umsetzen', 'Status im Schwachstellenmanagement dokumentieren (VEX: affected / not affected)']
    },
    {
      id: 'replace', cat: 'Organisatorisch', title: 'Komponente ersetzen / Migration planen (End-of-Life)',
      sr: ['IEC 62443-2-1', 'IEC 62443-4-1 SUM'], sl: 1, effort: 3, eliminates: true,
      applies: (f, v, c, ctx) => !f.patchAvailable && ctx.patchable === false ? 2 : (!f.patchAvailable ? 1 : 0),
      text: 'Wenn kein Patch verfügbar ist und keine Wartung mehr erfolgt: Komponente durch unterstützte Version ersetzen.',
      steps: ['Support-Status (EoL) beim Hersteller klären', 'Retrofit/Migration in Produkt-Roadmap aufnehmen', 'Bis dahin kompensierende Maßnahmen beibehalten']
    }
  ];
})();
