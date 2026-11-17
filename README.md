# OT-Risikoanalyse (CVE-basiert, IEC 62443)

Web-App für die Risikoanalyse von Maschinen und Anlagen: Komponenten erfassen, bekannte Schwachstellen (CVEs) abrufen, im Kontext der Maschine bewerten und priorisierte Maßnahmen erhalten.

- **Deutsch: https://ot-risk-tools.github.io/ot-risikoanalyse/**
- **English: https://ot-risk-tools.github.io/ot-risikoanalyse/en/**

*English summary:* web app for CVE-based OT risk analysis of machines and plants. Record components, look up known vulnerabilities in the NVD, rate them in the context of the machine and get prioritised measures mapped to IEC 62443. SBOM import and export in CycloneDX format, including Trivy results and VEX. All analyses stay in the browser of your own device. The English edition lives in the folder `en`; both editions share the same stored analyses.

Die App läuft im Browser unter Windows, macOS, iPadOS und iOS. Eine Schritt-für-Schritt-Anleitung steht in der App hinter dem Fragezeichen oder direkt unter [anleitung.html](https://ot-risk-tools.github.io/ot-risikoanalyse/anleitung.html).

## Ablauf

1. **Kontext** der Maschine festlegen: Netzexposition, Fernwartung, physischer Zugang, Safety-Relevanz, Verfügbarkeit, Vertraulichkeit, Risikoakzeptanz
2. **Komponenten** erfassen: von Hand mit Produktsuche im NVD-Verzeichnis oder per Import (CycloneDX, SPDX, CSV)
3. **Schwachstellen** suchen: versionsgenaue Abfrage der NVD, ergänzt um EPSS (FIRST) und CISA KEV
4. **Risikomatrix** 5×5 mit Ausgangs- und Restrisiko
5. **Maßnahmenplan** mit Bezug auf IEC 62443-3-3, als PDF, CSV oder CycloneDX/VEX

## Bewertungslogik

- **Eintrittswahrscheinlichkeit (1–5):** CVSS-Angriffsvektor, Komplexität, benötigte Rechte, Benutzerinteraktion, Netzexposition, Fernwartung, EPSS, CISA KEV
- **Auswirkung (1–5):** C/I/A aus CVSS, gewichtet mit Verfügbarkeitsanforderung, Safety-Relevanz und Know-how-Schutz
- **Risiko** = Wahrscheinlichkeit × Auswirkung; Niedrig ≤ 4, Mittel 5–9, Hoch 10–14, Kritisch ≥ 15
- **Empfehlung:** Auswahl der wirksamsten Maßnahmen pro Aufwand, bis das Restrisiko die Akzeptanzschwelle erreicht. Sind Patches nicht zeitnah einspielbar, schlägt die App zuerst kompensierende Maßnahmen vor und weist das Übergangsrisiko aus.

## SBOM und Trivy

Das SBOM-Format der App ist **CycloneDX (JSON)**.

- **Import:** CycloneDX 1.4–1.7, insbesondere Ergebnisse von [Trivy](https://trivy.dev), inklusive VEX-Status
- **Export:** CycloneDX 1.6 als SBOM oder als SBOM mit VEX (Status, Kontextbewertung, gewählte Maßnahmen)

Einen Scan erzeugt zum Beispiel:

```bash
trivy fs --format cyclonedx --scanners vuln --output scan.cdx.json ./projekt
```

Trivy erkennt Software-Pakete. Für SPS-, Antriebs- und Netzwerk-Firmware nutzt die App die NVD-Suche per CPE. Beispieldateien liegen im Ordner `beispiele`.

## Daten und Datenschutz

Analysen bleiben auf dem eigenen Gerät im Browser gespeichert (localStorage, unverschlüsselt). Es gibt keinen Server und kein Benutzerkonto. Zwischen Geräten lassen sich Analysen als Datei austauschen (Menü ⋯ → Sicherung speichern / laden).

Die App fragt nur öffentliche Quellen ab: `services.nvd.nist.gov`, `api.first.org` und `raw.githubusercontent.com/cisagov/kev-data`. Ohne NVD-API-Key gilt ein Limit von 5 Anfragen pro 30 Sekunden, die App wartet automatisch.

## Technik

Statische Web-App (PWA) ohne Build-Schritt und ohne Abhängigkeiten: HTML, CSS und JavaScript. Ein Service Worker macht die App offline nutzbar.

## Rechtliche Hinweise / Legal notes

Die vollständigen Hinweise stehen in der App: [Datenschutz und rechtliche Hinweise](https://ot-risk-tools.github.io/ot-risikoanalyse/rechtliches.html) · [Privacy and legal notes](https://ot-risk-tools.github.io/ot-risikoanalyse/en/legal.html)

- **Ohne Gewähr.** Die App ist eine Arbeitshilfe und ersetzt keine fachliche Prüfung. Ergebnisse hängen von der Qualität der Komponentenliste und der öffentlichen Schwachstellendaten ab. Die App ist nicht zertifiziert und begründet keine Konformität mit IEC 62443 oder anderen Vorschriften. Die Nutzung erfolgt auf eigenes Risiko.
- **NVD.** This product uses the NVD API but is not endorsed or certified by the NVD.
- **CVE.** CVE-Nummern und -Beschreibungen: Copyright © 1999–2026, The MITRE Corporation, genutzt nach den [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse). CVE ist eine eingetragene Marke der MITRE Corporation.
- **EPSS.** Daten von FIRST.org. See EPSS at https://www.first.org/epss.
- **CISA KEV.** Gemeinfrei (CC0 1.0).
- **Beispieldatei.** `beispiele/beispiel-trivy-scan.cdx.json` enthält Beschreibungen aus der GitHub Advisory Database, lizenziert unter [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), © GitHub, Inc. und Mitwirkende. Erzeugt mit Trivy, unverändert.
- **Marken.** Namen wie Siemens, SIMATIC, Microsoft, Windows, CODESYS, Apache Log4j, OpenSSL, Trivy oder CycloneDX gehören ihren jeweiligen Inhabern und werden nur beschreibend verwendet. Es besteht keine Verbindung zu diesen Unternehmen und Organisationen. Die Beispiel-Maschine ist erfunden.
- **IEC 62443.** Die App nennt nur Nummern von Normteilen und Anforderungen und gibt keinen Normtext wieder.
- **Programmcode.** Erstellt mit Unterstützung eines KI-Assistenten, ohne übernommenen Code, Bibliotheken, Schriften oder Bilder Dritter.
- **Kontakt.** Hinweise, auch zu möglichen Rechtsverletzungen, bitte über die Issues dieses Repositorys. Privates, nicht kommerzielles Projekt.
