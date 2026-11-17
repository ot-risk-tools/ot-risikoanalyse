# OT-Risikoanalyse (CVE-basiert, IEC 62443)

**Deutsch** · [English below](#english)

Web-App für die Risikoanalyse von Maschinen und Anlagen: Komponenten erfassen, bekannte Schwachstellen (CVEs) abrufen, im Kontext der Maschine bewerten und priorisierte Maßnahmen erhalten.

- **Deutsch: https://ot-risk-tools.github.io/ot-risikoanalyse/**
- **English: https://ot-risk-tools.github.io/ot-risikoanalyse/en/**

Die App läuft im Browser unter Windows, macOS, iPadOS und iOS. Eine Schritt-für-Schritt-Anleitung steht in der App hinter dem Fragezeichen oder direkt unter [anleitung.html](https://ot-risk-tools.github.io/ot-risikoanalyse/anleitung.html). Die englische Fassung liegt im Ordner `en`; beide Fassungen teilen sich die gespeicherten Analysen.

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

## Rechtliche Hinweise

Die vollständigen Hinweise stehen in der App: [Datenschutz und rechtliche Hinweise](https://ot-risk-tools.github.io/ot-risikoanalyse/rechtliches.html)

- **Ohne Gewähr.** Die App ist eine Arbeitshilfe und ersetzt keine fachliche Prüfung. Ergebnisse hängen von der Qualität der Komponentenliste und der öffentlichen Schwachstellendaten ab. Die App ist nicht zertifiziert und begründet keine Konformität mit IEC 62443 oder anderen Vorschriften. Die Nutzung erfolgt auf eigenes Risiko.
- **NVD.** Dieses Produkt nutzt die NVD-API, ist aber nicht von der NVD empfohlen oder zertifiziert.
- **CVE.** CVE-Nummern und -Beschreibungen: Copyright © 1999–2026, The MITRE Corporation, genutzt nach den [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse). CVE ist eine eingetragene Marke der MITRE Corporation.
- **EPSS.** Daten von FIRST.org, siehe https://www.first.org/epss.
- **CISA KEV.** Gemeinfrei (CC0 1.0).
- **Beispieldatei.** `beispiele/beispiel-trivy-scan.cdx.json` enthält Beschreibungen aus der GitHub Advisory Database, lizenziert unter [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), © GitHub, Inc. und Mitwirkende. Erzeugt mit Trivy, unverändert.
- **Marken.** Namen wie Siemens, SIMATIC, Microsoft, Windows, CODESYS, Apache Log4j, OpenSSL, Trivy oder CycloneDX gehören ihren jeweiligen Inhabern und werden nur beschreibend verwendet. Es besteht keine Verbindung zu diesen Unternehmen und Organisationen. Die Beispiel-Maschine ist erfunden.
- **IEC 62443.** Die App nennt nur Nummern von Normteilen und Anforderungen und gibt keinen Normtext wieder.
- **Programmcode.** Erstellt mit Unterstützung eines KI-Assistenten, ohne übernommenen Code, Bibliotheken, Schriften oder Bilder Dritter.
- **Kontakt.** Hinweise, auch zu möglichen Rechtsverletzungen, bitte über die Issues dieses Repositorys. Privates, nicht kommerzielles Projekt.

---

<a id="english"></a>

# OT Risk Analysis (CVE-based, IEC 62443)

Web app for the risk analysis of machines and plants: record components, look up known vulnerabilities (CVEs), rate them in the context of the machine and get prioritised measures.

- **English: https://ot-risk-tools.github.io/ot-risikoanalyse/en/**
- **Deutsch: https://ot-risk-tools.github.io/ot-risikoanalyse/**

The app runs in the browser on Windows, macOS, iPadOS and iOS. A step-by-step guide is available in the app behind the question mark or directly at [guide.html](https://ot-risk-tools.github.io/ot-risikoanalyse/en/guide.html). The English edition lives in the folder `en`; both editions share the same stored analyses.

## Workflow

1. **Context** of the machine: network exposure, remote maintenance, physical access, safety relevance, availability, confidentiality, risk acceptance
2. **Components:** by hand with a product search in the NVD dictionary, or by import (CycloneDX, SPDX, CSV)
3. **Vulnerabilities:** version-exact NVD query, enriched with EPSS (FIRST) and CISA KEV
4. **Risk matrix** 5×5 with initial and residual risk
5. **Action plan** mapped to IEC 62443-3-3, as PDF, CSV or CycloneDX/VEX

## Rating logic

- **Likelihood (1–5):** CVSS attack vector, complexity, privileges required, user interaction, network exposure, remote maintenance, EPSS, CISA KEV
- **Impact (1–5):** C/I/A from CVSS, weighted by availability requirement, safety relevance and know-how protection
- **Risk** = likelihood × impact; low ≤ 4, medium 5–9, high 10–14, critical ≥ 15
- **Recommendation:** the most effective measures per effort are chosen until the residual risk reaches the acceptance threshold. If patches cannot be installed promptly, the app proposes compensating measures first and shows the interim risk.

## SBOM and Trivy

The app's SBOM format is **CycloneDX (JSON)**.

- **Import:** CycloneDX 1.4–1.7, in particular results from [Trivy](https://trivy.dev), including VEX status
- **Export:** CycloneDX 1.6 as SBOM or as SBOM with VEX (status, context rating, selected measures)

A scan can be created like this, for example:

```bash
trivy fs --format cyclonedx --scanners vuln --output scan.cdx.json ./project
```

Trivy detects software packages. For PLC, drive and network firmware the app uses the NVD search by CPE. Example files are in the folder `beispiele`.

## Data and privacy

Analyses stay in the browser on your own device (localStorage, unencrypted). There is no server and no user account. Analyses can be moved between devices as a file (menu ⋯ → Save a backup / Load a backup).

The app only queries public sources: `services.nvd.nist.gov`, `api.first.org` and `raw.githubusercontent.com/cisagov/kev-data`. Without an NVD API key a limit of 5 requests per 30 seconds applies; the app waits automatically.

## Technology

Static web app (PWA) without a build step and without dependencies: HTML, CSS and JavaScript. A service worker makes the app usable offline.

## Legal notes

The complete notes are in the app: [Privacy and legal notes](https://ot-risk-tools.github.io/ot-risikoanalyse/en/legal.html)

- **No warranty.** The app is a working aid and does not replace an expert review. Results depend on the quality of the component list and of the public vulnerability data. The app is not certified and does not establish conformity with IEC 62443 or any other rules. Use is at your own risk.
- **NVD.** This product uses the NVD API but is not endorsed or certified by the NVD.
- **CVE.** CVE identifiers and descriptions: Copyright © 1999–2026, The MITRE Corporation, used under the [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse). CVE is a registered trademark of The MITRE Corporation.
- **EPSS.** Data from FIRST.org. See EPSS at https://www.first.org/epss.
- **CISA KEV.** Public domain (CC0 1.0).
- **Example file.** `beispiele/beispiel-trivy-scan.cdx.json` contains descriptions from the GitHub Advisory Database, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), © GitHub, Inc. and contributors. Generated with Trivy, unmodified.
- **Trademarks.** Names such as Siemens, SIMATIC, Microsoft, Windows, CODESYS, Apache Log4j, OpenSSL, Trivy or CycloneDX belong to their respective owners and are used descriptively only. There is no affiliation with these companies and organisations. The example machine is fictitious.
- **IEC 62443.** The app only names numbers of parts and requirements of the standard and reproduces no text of the standard.
- **Program code.** Created with the help of an AI assistant, without code, libraries, fonts or images taken from third parties.
- **Contact.** For notices, including about possible infringements, please use the issues of this repository. Private, non-commercial project.
