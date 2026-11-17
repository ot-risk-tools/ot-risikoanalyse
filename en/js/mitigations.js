/* Catalogue of measures mapped to IEC 62443-3-3 (system requirements) and IEC 62443-2-3 (patch management).
 * applies(f, v, comp, ctx) returns relevance 0..3 (0 = not applicable).
 * dL/dI = reduction of likelihood/impact, eliminates = removes the vulnerability.
 * Component type keys (SPS, HMI, Betriebssystem …) stay German: they are shared with the German edition.
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
      id: 'patch', cat: 'Patch', title: 'Install the security update / firmware update',
      sr: ['IEC 62443-2-3', 'SR 3.4'], sl: 1, effort: 2, eliminates: true,
      applies: (f, v, c, ctx) => f.patchAvailable ? (ctx.patchable === false ? 1 : 3) : 0,
      text: 'Install the vendor update that fixes the vulnerability.',
      steps: ['Check compatibility with the machine software / the vendor\'s list of approved versions', 'Validate the update on a test or reference system (digital twin)', 'Back up project, firmware and configuration', 'Agree a maintenance window with production and define a fallback plan', 'Install the update, run functional and safety tests, update the SBOM']
    },
    {
      id: 'kev', cat: 'Organisational', title: 'Emergency change: handle within 72 h',
      sr: ['IEC 62443-2-1 SPE'], sl: 1, effort: 1, dL: 0,
      applies: f => f.kev ? 3 : 0,
      text: 'The vulnerability is being actively exploited (CISA KEV). Start immediate measures outside the regular patch cycle.',
      steps: ['Identify affected machines/customers (SBOM comparison)', 'Inform customers and service by security advisory', 'Implement compensating measures at once, prioritise the patch']
    },
    {
      id: 'seg', cat: 'Technical', title: 'Network segmentation into zones & conduits',
      sr: ['SR 5.1', 'SR 5.2'], sl: 1, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) ? (ctx.exposure >= 3 ? 3 : 2) : 0,
      text: 'Make the machine its own security zone; communication only through defined conduits.',
      steps: ['Document the zone model of the machine/line', 'Separate the machine network from production and office networks by VLAN or its own firewall', 'No direct access from the office network – only through a DMZ']
    },
    {
      id: 'fw', cat: 'Technical', title: 'Firewall rule set: allowlist only the protocols/ports needed',
      sr: ['SR 5.2', 'SR 7.6'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => net(v) ? 2 : 0,
      text: 'Allow only explicitly required connections at the zone boundary (default deny).',
      steps: ['Create a communication matrix (source, destination, port, protocol)', 'Block the affected service/port at the boundary unless it is strictly needed', 'Review the rule set regularly']
    },
    {
      id: 'remote', cat: 'Technical', title: 'Secure remote maintenance (VPN, MFA, release by the operator)',
      sr: ['SR 1.13', 'SR 2.6', 'SR 1.1'], sl: 2, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) && (ctx.remoteAccess || ctx.exposure >= 4) ? 3 : 0,
      text: 'Remote access only through a central remote access gateway with multi-factor authentication and release by the operator.',
      steps: ['No direct port forwarding / publicly reachable services', 'MFA and personal accounts', 'Session release on site (key switch/ticket), session timeout and logging']
    },
    {
      id: 'auth', cat: 'Technical', title: 'Enable authentication, replace default passwords',
      sr: ['SR 1.1', 'SR 1.5', 'SR 1.7'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => hasCwe(f, CWE.auth) || hasCwe(f, CWE.creds) ? 3 : (v.PR === 'N' && net(v) ? 1 : 0),
      text: 'Enable access protection on the component (e.g. protection level/password on the PLC, HMI user management).',
      steps: ['Change default and vendor passwords, use a unique password per machine', 'Set the access protection level of the controller to the highest practicable level', 'Password policy (length, lockout after failed attempts)']
    },
    {
      id: 'hardcoded', cat: 'Organisational', title: 'Hard-coded credentials: demand a vendor fix, isolate the service',
      sr: ['SR 1.5', 'SR 5.2'], sl: 1, effort: 2, dL: 1,
      applies: f => hasCwe(f, ['CWE-798', 'CWE-259', 'CWE-321']) ? 3 : 0,
      text: 'Built-in credentials cannot be changed – make the affected interface strictly unreachable and ask the vendor for a fix.',
      steps: ['Identify the affected service/port and block it at the boundary', 'Send a supplier request (PSIRT) with a deadline', 'Put replacement of the component on the roadmap']
    },
    {
      id: 'harden', cat: 'Technical', title: 'Hardening: disable services and interfaces that are not needed',
      sr: ['SR 7.7', 'SR 7.6'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => net(v) ? 2 : 1,
      text: 'Reduce the attack surface: switch off unused services (web server, SNMP, FTP, Telnet, debug ports).',
      steps: ['Port scan / configuration check of the component', 'Disable unneeded services in the device configuration', 'Add the hardening rule to the standard machine configuration']
    },
    {
      id: 'web', cat: 'Technical', title: 'Disable the web interface or allow it only from the engineering zone',
      sr: ['SR 7.7', 'SR 5.2'], sl: 1, effort: 1, dL: 1,
      applies: f => hasCwe(f, CWE.web) ? 3 : 0,
      text: 'The vulnerability affects the web interface – switch off the component\'s web server or restrict access to engineering stations.',
      steps: ['Disable the web server in the device configuration if it is not needed in operation', 'Otherwise: limit access by firewall to a defined engineering IP', 'Secure browser use on engineering stations (no parallel web browsing)']
    },
    {
      id: 'removable', cat: 'Technical', title: 'Control physical access & removable media',
      sr: ['SR 2.3', 'SR 3.2'], sl: 1, effort: 1, dL: 1,
      applies: (f, v) => (v.AV === 'P' || v.AV === 'L') ? 3 : 0,
      text: 'Restrict local/physical attack paths.',
      steps: ['Lock the control cabinet, access for authorised staff only', 'Block USB ports or allow only checked media (sheep-dip / kiosk scan)', 'Physically block unused network ports']
    },
    {
      id: 'least', cat: 'Technical', title: 'Role and permission concept (least privilege)',
      sr: ['SR 2.1', 'SR 1.3'], sl: 1, effort: 2, dL: 0.5,
      applies: (f, v) => hasCwe(f, CWE.priv) ? 3 : (v.PR === 'L' ? 2 : 0),
      text: 'Give users only the minimum rights they need; separate operators, maintenance and engineering.',
      steps: ['Define roles (operator, setter, service, admin)', 'No admin rights for operator accounts', 'Recertify permissions regularly']
    },
    {
      id: 'aware', cat: 'Organisational', title: 'Awareness training for operators and service staff',
      sr: ['IEC 62443-2-1 ORG'], sl: 1, effort: 1, dL: 0.5,
      applies: (f, v) => v.UI === 'R' ? 2 : 0,
      text: 'Exploitation needs a user action (e.g. opening a file or link). Training lowers the likelihood.',
      steps: ['Training on manipulated project files, phishing and USB sticks', 'Open project files from trusted sources only', 'Define a reporting channel for anything suspicious']
    },
    {
      id: 'malware', cat: 'Technical', title: 'Application allowlisting / malware protection on IPC & HMI',
      sr: ['SR 3.2'], sl: 1, effort: 2, dL: 1,
      applies: (f, v, c) => isType(c, ['IPC', 'HMI', 'Betriebssystem']) && (hasCwe(f, CWE.mem) || hasCwe(f, CWE.inject) || v.I === 'H') ? 3 : (isType(c, ['IPC', 'HMI', 'Betriebssystem']) ? 1 : 0),
      text: 'Allow only approved programs on PC-based components (allowlisting), with a malware protection concept suitable for OT.',
      steps: ['Use an allowlisting solution approved by the vendor', 'Restrict autostart/scripting for operator accounts', 'Update signatures/rules in the maintenance window']
    },
    {
      id: 'virtpatch', cat: 'Technical', title: 'Virtual patching (IPS / deep packet inspection at the zone boundary)',
      sr: ['SR 5.2', 'SR 3.2'], sl: 2, effort: 2, dL: 1,
      applies: (f, v, c, ctx) => net(v) && (!f.patchAvailable || ctx.patchable === false) ? 3 : (net(v) ? 1 : 0),
      text: 'If no patch can be installed: detect and block attack patterns at the boundary (industrial firewall with DPI/IPS for S7, Modbus, OPC UA …).',
      steps: ['Enable the IPS signature for the CVE or a protocol filter (e.g. read access only)', 'Allow write access to the controller from the engineering station only', 'Document effectiveness (compensating measure under IEC 62443-3-3)']
    },
    {
      id: 'monitor', cat: 'Technical', title: 'OT network monitoring & anomaly detection',
      sr: ['SR 6.2', 'SR 2.8'], sl: 2, effort: 3, dL: 0.5,
      applies: (f, v) => net(v) ? 1 : 0,
      text: 'Passive monitoring of the machine network detects exploitation attempts and unknown devices.',
      steps: ['Place a passive sensor (SPAN port) at the machine switch', 'Alarms for new connections, program changes, stop commands', 'Connect to the operator\'s SOC/SIEM']
    },
    {
      id: 'logging', cat: 'Technical', title: 'Security logging and central evaluation',
      sr: ['SR 2.8', 'SR 6.1'], sl: 1, effort: 2, dL: 0.5,
      applies: (f, v) => (hasCwe(f, CWE.auth) || hasCwe(f, CWE.priv)) ? 2 : (v.PR !== 'N' ? 1 : 0),
      text: 'Log sign-ins and changes to configuration and programs to detect misuse.',
      steps: ['Enable syslog on the components', 'Ensure time synchronisation (NTP)', 'Regular evaluation or alerting']
    },
    {
      id: 'dos', cat: 'Technical', title: 'Protection against overload / denial of service',
      sr: ['SR 7.1', 'SR 7.2'], sl: 1, effort: 1, dL: 0.5,
      applies: (f, v) => net(v) && (hasCwe(f, CWE.dos) || (v.A === 'H' && v.C === 'N' && v.I === 'N')) ? 3 : 0,
      text: 'Limit network load and the number of connections to the component so the controller does not go to STOP.',
      steps: ['Rate limiting / broadcast storm protection on the switch', 'Connection limits on the firewall', 'Check the defined safe state on loss of communication']
    },
    {
      id: 'crypto', cat: 'Technical', title: 'Encrypted and authenticated communication',
      sr: ['SR 3.1', 'SR 4.1', 'SR 4.3'], sl: 2, effort: 2, dL: 0.5,
      applies: (f, v) => hasCwe(f, CWE.crypto) ? 3 : 0,
      text: 'Use secure protocol variants (e.g. TLS ≥ 1.2, OPC UA SignAndEncrypt, PG/PC communication with certificates).',
      steps: ['Disable insecure protocols/ciphers', 'Introduce and manage device certificates', 'Generate keys/certificates individually per machine']
    },
    {
      id: 'integrity', cat: 'Technical', title: 'Integrity protection of firmware and control program',
      sr: ['SR 3.4', 'SR 3.3'], sl: 2, effort: 2, dL: 0.5, dI: 0.5,
      applies: (f, v, c) => hasCwe(f, CWE.integrity) ? 3 : (v.I === 'H' && isType(c, ['SPS', 'Firmware', 'Antrieb']) ? 2 : 0),
      text: 'Allow signed firmware only; detect changes to program and configuration.',
      steps: ['Enable signature verification for firmware updates', 'Checksum/version comparison of the PLC program (change detection)', 'Enable know-how and copy protection of the blocks']
    },
    {
      id: 'backup', cat: 'Technical', title: 'Backup & recovery concept',
      sr: ['SR 7.3', 'SR 7.4'], sl: 1, effort: 1, dI: 1,
      applies: (f, v) => (v.A === 'H' || v.I === 'H') ? 2 : 0,
      text: 'Fast recovery limits downtime after a successful attack.',
      steps: ['Regular backup of PLC project, HMI, drive parameters and IPC images', 'Keep an offline copy', 'Test recovery regularly (document the restore time)']
    },
    {
      id: 'safety', cat: 'Technical', title: 'Verify the independent safety function (safety ≠ security)',
      sr: ['IEC 62443-3-2 ZCR 5', 'ISO 13849 / IEC 62061'], sl: 1, effort: 2, dI: 1,
      applies: (f, v, c, ctx) => (v.I === 'H' || v.A === 'H') && ctx.safety >= 2 ? 3 : 0,
      text: 'Make sure people are protected even if the standard controller is manipulated (safety PLC, hard-wired emergency stop circuits, mechanical guards).',
      steps: ['Check whether safety functions depend on the affected component', 'Protect the safety program with a separate password / F-signature', 'Document the result in the risk assessment under the Machinery Directive / Machinery Regulation']
    },
    {
      id: 'vendor', cat: 'Organisational', title: 'Evaluate the vendor advisory and implement workarounds',
      sr: ['IEC 62443-2-3', 'IEC 62443-4-1 DM'], sl: 1, effort: 1, dL: 0.5,
      applies: () => 1,
      text: 'Check the vendor\'s security advisory (e.g. Siemens ProductCERT, CERT@VDE, CISA ICS) – it often describes concrete workarounds.',
      steps: ['Look up the advisory for the CVE at the component vendor', 'Assess and implement the described workarounds', 'Document the status in vulnerability management (VEX: affected / not affected)']
    },
    {
      id: 'replace', cat: 'Organisational', title: 'Replace the component / plan a migration (end of life)',
      sr: ['IEC 62443-2-1', 'IEC 62443-4-1 SUM'], sl: 1, effort: 3, eliminates: true,
      applies: (f, v, c, ctx) => !f.patchAvailable && ctx.patchable === false ? 2 : (!f.patchAvailable ? 1 : 0),
      text: 'If no patch is available and the product is no longer maintained: replace the component with a supported version.',
      steps: ['Clarify the support status (EoL) with the vendor', 'Put retrofit/migration on the product roadmap', 'Keep compensating measures in place until then']
    }
  ];
})();
