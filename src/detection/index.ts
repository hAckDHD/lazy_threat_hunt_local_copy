import type { IOC, IOCType } from '../types/index.js';
import { filterSafeQueryIOCs } from '../security/validate.js';

// ── Detection Rule Types ────────────────────────────────────────────────────

export type DetectionPlatform = 'sigma' | 'kql' | 'splunk' | 'elastic';

export interface DetectionRule {
  platform: DetectionPlatform;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule: string;
  mitreAttack: string[];
  falsePositives: string[];
  tuningNotes: string[];
  iocType: IOCType;
  iocValues: string[];
}

// ── MITRE ATT&CK Mapping ────────────────────────────────────────────────────

const MITRE_MAP: Record<IOCType, string[]> = {
  ip:      ['T1071', 'T1090', 'T1571'],
  ipv6:    ['T1071', 'T1090', 'T1571'],
  domain:  ['T1071.001', 'T1568', 'T1583.001'],
  url:     ['T1071.001', 'T1566.002', 'T1204.001'],
  sha256:  ['T1204', 'T1059', 'T1027'],
  sha1:    ['T1204', 'T1059', 'T1027'],
  md5:     ['T1204', 'T1059', 'T1027'],
  email:   ['T1566.001', 'T1566.002', 'T1598'],
  cve:     ['T1190', 'T1210'],
  hostname:['T1071', 'T1568'],
  registry_key: ['T1112', 'T1547.001'],
  filename:    ['T1059', 'T1204', 'T1036'],
};

// Primary ATT&CK tactic name per technique ID this tool ever tags with —
// used to populate a real "tactics" field (tactic names) separately from
// "relevantTechniques" (technique IDs), since Sentinel's schema wants both,
// not technique IDs shoved into the tactics field.
const TACTIC_NAME_MAP: Record<string, string> = {
  T1071: 'Command and Control', 'T1071.001': 'Command and Control',
  T1090: 'Command and Control', T1571: 'Command and Control', T1568: 'Command and Control',
  'T1583.001': 'Resource Development',
  'T1566.001': 'Initial Access', 'T1566.002': 'Initial Access', T1190: 'Initial Access',
  T1204: 'Execution', 'T1204.001': 'Execution', T1059: 'Execution',
  T1027: 'Defense Evasion', T1112: 'Defense Evasion', T1036: 'Defense Evasion',
  T1598: 'Reconnaissance',
  T1210: 'Lateral Movement',
  'T1547.001': 'Persistence',
};

// Real ATT&CK tactic IDs (TAxxxx), keyed by tactic display name. The previous
// code derived a "tactic id" via techniques[0]?.split('.')[0] — that strips a
// sub-technique suffix off a TECHNIQUE id (T1071.001 -> T1071), which is
// never a valid TA-prefixed tactic id at all. techniqueTacticId() below is
// the real lookup: technique -> tactic name (TACTIC_NAME_MAP) -> tactic id.
const TACTIC_ID_MAP: Record<string, string> = {
  Reconnaissance: 'TA0043',
  'Resource Development': 'TA0042',
  'Initial Access': 'TA0001',
  Execution: 'TA0002',
  Persistence: 'TA0003',
  'Privilege Escalation': 'TA0004',
  'Defense Evasion': 'TA0005',
  'Credential Access': 'TA0006',
  Discovery: 'TA0007',
  'Lateral Movement': 'TA0008',
  Collection: 'TA0009',
  'Command and Control': 'TA0011',
  Exfiltration: 'TA0010',
  Impact: 'TA0040',
};

function techniqueTacticId(technique: string | undefined): string {
  const tacticName = (technique && TACTIC_NAME_MAP[technique]) || 'Initial Access';
  return TACTIC_ID_MAP[tacticName] ?? 'TA0001';
}

// Real per-IOC ATT&CK techniques (populated by enrichment, e.g. from VirusTotal)
// take priority over the static per-type guess above — an actual observed
// technique is strictly better evidence than a guess keyed only on IOC type.
function techniquesForGroup(typeIOCs: IOC[], type: IOCType): string[] {
  const observed = [...new Set(typeIOCs.flatMap(i => i.enrichment?.attackTechniques ?? []))];
  return observed.length ? observed : (MITRE_MAP[type] || []);
}

// ── Sigma Rule Generator ────────────────────────────────────────────────────

function generateSigma(iocs: IOC[]): DetectionRule[] {
  const byType = groupByType(iocs);
  const rules: DetectionRule[] = [];

  for (const [type, typeIOCs] of Object.entries(byType) as [IOCType, IOC[]][]) {
    const values = typeIOCs.map(i => i.value.replace(/'/g, "''"));
    const techniques = techniquesForGroup(typeIOCs, type);
    let logsource = '';
    let detection = '';
    let name = '';
    let desc = '';
    let severity: DetectionRule['severity'] = 'high';
    let fps: string[] = [];
    let tuning: string[] = [];

    switch (type) {
      case 'ip':
      case 'ipv6':
        logsource = `logsource:
    category: network_connection
    product: windows`;
        detection = `detection:
    selection:
        DestinationIp|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Network_IP_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects network connections to ${values.length} known-malicious IP address(es)`;
        severity = 'critical';
        fps = ['Legitimate business services hosted on shared infrastructure', 'VPN exit nodes matching known-bad IPs'];
        tuning = ['Review hits against asset inventory — prioritize servers and domain controllers', 'Cross-reference with proxy logs for HTTP/HTTPS context', 'Check if IP is a known CDN or cloud provider before blocking'];
        break;

      case 'domain':
        logsource = `logsource:
    category: dns_query`;
        detection = `detection:
    selection:
        query|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_DNS_Domain_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects DNS queries for ${values.length} known-malicious domain(s)`;
        severity = 'high';
        fps = ['Internal applications using similar domain patterns', 'Security research or sandbox environments'];
        tuning = ['Filter out known-good resolvers (internal DNS forwarders)', 'Add exclusion for security tools that resolve threat intel domains', 'Consider threshold: >5 unique clients querying within 1 hour'];
        break;

      case 'url':
        logsource = `logsource:
    category: proxy`;
        detection = `detection:
    selection:
        c-uri|contains:
${values.map(v => `            - '${v.length > 80 ? v.substring(0, 80) : v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_URL_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects web requests to ${values.length} known-malicious URL(s)`;
        severity = 'critical';
        fps = ['Security research or threat intel platforms', 'URL scanning services'];
        tuning = ['Exclude security vendor IPs from detection scope', 'Add URI path normalization to reduce false positives'];
        break;

      case 'sha256':
        logsource = `logsource:
    category: process_creation
    product: windows`;
        detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'SHA256=${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Hash_SHA256_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects process creation with ${values.length} known-malicious SHA256 hash(es)`;
        severity = 'critical';
        fps = ['False positive hash collisions (extremely rare)', 'Legitimate software with matching hash (supply chain)'];
        tuning = ['Add parent process context to reduce noise', 'Exclude known-good signed binaries', 'Correlate with network connections for higher confidence'];
        break;

      case 'md5':
        logsource = `logsource:
    category: process_creation
    product: windows`;
        detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'MD5=${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Hash_MD5_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects process creation with ${values.length} known-malicious MD5 hash(es)`;
        severity = 'critical';
        fps = ['Legacy hash format — may have collisions'];
        tuning = ['Prefer SHA256 when available', 'Add file path context for additional filtering'];
        break;

      case 'sha1':
        logsource = `logsource:
    category: process_creation
    product: windows`;
        detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'SHA1=${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Hash_SHA1_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects process creation with ${values.length} known-malicious SHA1 hash(es)`;
        severity = 'critical';
        fps = ['Legacy hash format — may have collisions'];
        tuning = ['Prefer SHA256 when available'];
        break;

      case 'email':
        logsource = `logsource:
    category: email`;
        detection = `detection:
    selection:
        sender|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Email_Sender_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects emails from ${values.length} known-malicious sender address(es)`;
        severity = 'high';
        fps = ['Legitimate mailing lists or newsletters using similar domains', 'Internal users who interacted with phishing campaigns'];
        tuning = ['Add attachment hash correlation for higher confidence', 'Exclude emails that were already quarantined by gateway'];
        break;

      case 'registry_key':
        logsource = `logsource:
    category: registry_event
    product: windows`;
        detection = `detection:
    selection:
        TargetObject|startswith:
${values.map(v => `            - '${v.length > 100 ? v.substring(0, 100) : v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Registry_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects registry modifications to ${values.length} known-malicious key(s)`;
        severity = 'high';
        fps = ['Legitimate software using similar registry paths', 'Windows updates modifying registry'];
        tuning = ['Add process context — filter out trusted installers', 'Monitor for creation AND modification events'];
        break;

      case 'cve':
        // "vulnerability"/"network" are not real Sigma logsource taxonomy
        // values — CVE exploitation is normally observed via whatever
        // IDS/IPS/firewall product actually raised the signature; adjust
        // category/product below to match your real log source.
        logsource = `logsource:
    category: firewall`;
        detection = `detection:
    selection:
        cve|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_CVE_Exploitation_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects exploitation attempts targeting ${values.length} known CVE(s)`;
        severity = 'critical';
        fps = ['Vulnerability scanning by authorized tools', 'Penetration testing activities'];
        tuning = ['Exclude authorized scanner IPs', 'Correlate with IDS/IPS alerts for confirmation'];
        break;

      case 'filename':
        logsource = `logsource:
    category: process_creation
    product: windows`;
        detection = `detection:
    selection:
        Image|endswith:
${values.map(v => `            - '${v.length > 60 ? v.substring(0, 60) : v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Filename_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects process creation from ${values.length} known-malicious filename(s)`;
        severity = 'high';
        fps = ['Legitimate tools with similar names', 'Internal scripts or automation'];
        tuning = ['Add full path matching for precision', 'Combine with hash verification for high-confidence detection'];
        break;

      case 'hostname':
        logsource = `logsource:
    category: network_connection`;
        detection = `detection:
    selection:
        DestinationHostname|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
        name = `IOC_Hunt_Hostname_${new Date().toISOString().split('T')[0].replace(/-/g, '')}`;
        desc = `Detects connections to ${values.length} known-malicious hostname(s)`;
        severity = 'high';
        fps = ['Internal hostnames that match patterns', 'Cloud services with dynamic hostnames'];
        tuning = ['Resolve hostnames to IPs and cross-reference with IP IOCs', 'Add DNS query logging for additional context'];
        break;

      default:
        continue;
    }

    const ts = new Date().toISOString().split('T')[0];
    const rule = `title: ${name}
id: ${generateUUID()}
status: experimental
description: ${desc}
references:
    - 'IOC Hunt - Generated ${ts}'
author: Threat Hunt
date: ${ts}
tags:
${techniques.map(t => `    - attack.${t.toLowerCase()}`).join('\n')}
${logsource}
${detection}
falsepositives:
${fps.map(fp => `    - ${fp}`).join('\n')}
level: ${severity}`;

    rules.push({
      platform: 'sigma',
      name,
      description: desc,
      severity,
      rule,
      mitreAttack: techniques,
      falsePositives: fps,
      tuningNotes: tuning,
      iocType: type,
      iocValues: values,
    });
  }

  return rules;
}

// ── KQL Analytics Rule Generator ─────────────────────────────────────────────

function generateKQLRule(iocs: IOC[]): DetectionRule[] {
  const byType = groupByType(iocs);
  const rules: DetectionRule[] = [];

  for (const [type, typeIOCs] of Object.entries(byType) as [IOCType, IOC[]][]) {
    const values = typeIOCs.map(i => i.value);
    const techniques = techniquesForGroup(typeIOCs, type);
    let query = '';
    let name = '';
    let desc = '';
    let severity: DetectionRule['severity'] = 'high';
    let fps: string[] = [];
    let tuning: string[] = [];
    let entityMappings = '';

    const ts = new Date().toISOString().split('T')[0].replace(/-/g, '');
    const valueList = values.map(v => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(', ');

    switch (type) {
      case 'ip':
      case 'ipv6':
        name = `IOC_Hunt_IP_${ts}`;
        desc = `Detects network connections to ${values.length} known-malicious IP(s)`;
        severity = 'high';
        query = `let ioc_ips = dynamic([${valueList}]);
union DeviceNetworkEvents, CommonSecurityLog
| where RemoteIP in (ioc_ips) or DestinationIP in (ioc_ips)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName),
    ConnectionCount = count()
    by RemoteIP, LocalIP, InitiatingProcessFileName
| extend DeviceCount = array_length(Devices)
| sort by ConnectionCount desc`;
        entityMappings = `entityMappings:
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: RemoteIP
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName`;
        fps = ['Legitimate services on shared hosting', 'VPN/proxy IPs'];
        tuning = ['Exclude known-good IPs (CDNs, cloud providers)', 'Add threshold: DeviceCount > 3 for higher confidence'];
        break;

      case 'domain':
        name = `IOC_Hunt_Domain_${ts}`;
        desc = `Detects DNS queries for ${values.length} known-malicious domain(s)`;
        severity = 'medium';
        query = `let ioc_domains = dynamic([${valueList}]);
union DnsEvents, DeviceNetworkEvents
| where Name in~ (ioc_domains) or RemoteUrl has_any (ioc_domains)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Computers = make_set(Computer),
    QueryCount = count()
    by Name, RemoteIP
| extend ComputerCount = array_length(Computers)`;
        entityMappings = `entityMappings:
  - entityType: DNS
    fieldMappings:
      - identifier: DomainName
        columnName: Name`;
        fps = ['Security research tools', 'Internal applications with similar domain patterns'];
        tuning = ['Filter out internal DNS forwarders', 'Add threshold for minimum unique clients'];
        break;

      case 'sha256':
        name = `IOC_Hunt_SHA256_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA256 hash(es)`;
        severity = 'high';
        query = `let ioc_hashes = dynamic([${valueList}]);
union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents
| where SHA256 in (ioc_hashes)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName),
    Actions = make_set(ActionType)
    by SHA256, FileName, FolderPath
| extend DeviceCount = array_length(Devices)`;
        entityMappings = `entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: SHA256
        columnName: SHA256
  - entityType: Host
    fieldMappings:
      - identifier: HostName
        columnName: DeviceName`;
        fps = ['False positive hash collisions (extremely rare)'];
        tuning = ['Add parent process context', 'Correlate with network connections'];
        break;

      case 'md5':
        name = `IOC_Hunt_MD5_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious MD5 hash(es)`;
        severity = 'medium';
        query = `let ioc_hashes = dynamic([${valueList}]);
DeviceFileEvents
| where MD5 in (ioc_hashes)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName)
    by MD5, FileName, FolderPath`;
        entityMappings = `entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: MD5
        columnName: MD5`;
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        break;

      case 'sha1':
        name = `IOC_Hunt_SHA1_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA1 hash(es)`;
        severity = 'medium';
        query = `let ioc_hashes = dynamic([${valueList}]);
DeviceFileEvents
| where SHA1 in (ioc_hashes)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName)
    by SHA1, FileName, FolderPath`;
        entityMappings = `entityMappings:
  - entityType: File
    fieldMappings:
      - identifier: SHA1
        columnName: SHA1`;
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        break;

      case 'registry_key':
        name = `IOC_Hunt_Registry_${ts}`;
        desc = `Detects registry modifications to ${values.length} known-malicious key(s)`;
        severity = 'medium';
        query = `let ioc_keys = dynamic([${valueList}]);
DeviceRegistryEvents
| where RegistryKey has_any (ioc_keys)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Devices = make_set(DeviceName),
    Actions = make_set(ActionType)
    by RegistryKey, RegistryValueName, InitiatingProcessFileName`;
        entityMappings = `entityMappings:
  - entityType: RegistryKey
    fieldMappings:
      - identifier: Key
        columnName: RegistryKey`;
        fps = ['Legitimate software using similar paths', 'Windows updates'];
        tuning = ['Filter out trusted installer processes', 'Monitor creation AND modification events'];
        break;

      case 'cve':
        name = `IOC_Hunt_CVE_${ts}`;
        desc = `Detects exploitation attempts targeting ${values.length} known CVE(s)`;
        severity = 'high';
        query = `let ioc_cves = dynamic([${valueList}]);
SecurityAlert
| where Entities has_any (ioc_cves) or ExtendedProperties has_any (ioc_cves)
| summarize
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    AlertCount = count()
    by AlertName, AlertSeverity, CompromisedEntity`;
        entityMappings = `entityMappings:
  - entityType: SecurityAlert
    fieldMappings:
      - identifier: AlertName
        columnName: AlertName`;
        fps = ['Authorized vulnerability scanning', 'Penetration testing'];
        tuning = ['Exclude authorized scanner IPs', 'Correlate with IDS/IPS alerts'];
        break;

      default:
        continue;
    }

    // A scheduled Sentinel analytics rule needs an actual TimeGenerated output
    // column for lookback to work — every branch above ends in a `summarize`
    // that only produces FirstSeen/LastSeen, so add it here uniformly.
    const queryWithTimeGenerated = `${query}\n| extend TimeGenerated = LastSeen`;
    // Sentinel's `tactics` enum wants PascalCase-no-space shortnames
    // (e.g. "CommandAndControl"), not the human-readable ATT&CK tactic name.
    const toSentinelTactic = (name: string) => name.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('');
    const tacticNames = [...new Set(techniques.map(t => toSentinelTactic(TACTIC_NAME_MAP[t] ?? 'Initial Access')))];

    const rule = `id: ${generateUUID()}
name: ${name}
description: >
  ${desc}
  Generated by Threat Hunt on ${new Date().toISOString().split('T')[0]}.
severity: ${severity}
kind: Scheduled
version: 1
requiredDataConnectors: []
queryFrequency: PT1H
queryPeriod: PT24H
triggerOperator: gt
triggerThreshold: 0
query: |
  ${queryWithTimeGenerated.replace(/\n/g, '\n  ')}
tactics:
${tacticNames.map(t => `  - ${t}`).join('\n')}
relevantTechniques:
${techniques.map(t => `  - ${t}`).join('\n')}
${entityMappings}
suppressionDuration: PT24H
incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    matchingMethod: Selected
    groupByEntities: [Host]
    lookbackDuration: PT1H
    reopenClosedIncident: false`;

    rules.push({
      platform: 'kql',
      name,
      description: desc,
      severity,
      rule,
      mitreAttack: techniques,
      falsePositives: fps,
      tuningNotes: tuning,
      iocType: type,
      iocValues: values,
    });
  }

  return rules;
}

// ── Splunk Correlation Search Generator ──────────────────────────────────────

function generateSplunkRule(iocs: IOC[]): DetectionRule[] {
  const byType = groupByType(iocs);
  const rules: DetectionRule[] = [];

  for (const [type, typeIOCs] of Object.entries(byType) as [IOCType, IOC[]][]) {
    const values = typeIOCs.map(i => i.value);
    const techniques = techniquesForGroup(typeIOCs, type);
    let search = '';
    let name = '';
    let desc = '';
    let severity: DetectionRule['severity'] = 'high';
    let fps: string[] = [];
    let tuning: string[] = [];

    const ts = new Date().toISOString().split('T')[0].replace(/-/g, '');
    // SPL double-quoted strings: backslash must be escaped before the quote,
    // otherwise a value ending in a backslash (registry paths) closes the
    // string early — same fix as src/hunting/splunk.ts.
    const list = values.map(v => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(' ');
    let riskObjectField = 'host';

    switch (type) {
      case 'ip':
      case 'ipv6':
        name = `IOC_Hunt_IP_${ts}`;
        desc = `Detects network connections to ${values.length} known-malicious IP(s)`;
        severity = 'critical';
        riskObjectField = 'dest';
        // src_ip/dest_ip are CIM Network_Traffic fields; src/dst are not (dst isn't
        // a CIM field — dest is), so the raw src/dst pair is dropped.
        search = `index=* (src_ip IN (${list}) OR dest_ip IN (${list}))
| stats count as hits, values(src_ip) as src_ips, values(dest_ip) as dest_ips, dc(dest_ip) as unique_dest by _time, src, dest, index, sourcetype
| where hits > 0
| sort -hits
| eval severity="high"
| table _time, src, dest, hits, unique_dest, index, sourcetype`;
        fps = ['Legitimate services on shared hosting', 'VPN/proxy IPs'];
        tuning = ['Exclude known-good IPs', 'Add threshold for minimum hit count', 'Filter by sourcetype for focused detection'];
        break;

      case 'domain':
        name = `IOC_Hunt_Domain_${ts}`;
        desc = `Detects DNS queries for ${values.length} known-malicious domain(s)`;
        severity = 'high';
        riskObjectField = 'dest';
        // CIM Network_Resolution (DNS) model field is "query", not "dns.query".
        search = `index=* (query IN (${list}) OR url IN (${list}))
| eval ioc_match=coalesce(query, url)
| stats count as hits, dc(src) as unique_sources by _time, src, ioc_match, index, sourcetype
| where hits > 0
| sort -hits`;
        fps = ['Security research tools', 'Internal applications'];
        tuning = ['Filter out internal DNS forwarders', 'Add threshold for minimum unique sources'];
        break;

      case 'sha256':
        name = `IOC_Hunt_SHA256_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA256 hash(es)`;
        severity = 'critical';
        search = `index=* (sha256 IN (${list}) OR file_hash IN (${list}))
| stats count as hits, values(file_name) as files, values(file_path) as paths, dc(host) as unique_hosts by _time, sha256, host, user
| where hits > 0
| sort -hits`;
        fps = ['False positive hash collisions (extremely rare)'];
        tuning = ['Add parent process context', 'Correlate with network connections'];
        break;

      case 'md5':
        name = `IOC_Hunt_MD5_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious MD5 hash(es)`;
        severity = 'medium';
        search = `index=* (md5 IN (${list}) OR file_hash IN (${list}))
| stats count as hits, values(file_name) as files, dc(host) as unique_hosts by _time, md5, host
| where hits > 0
| sort -hits`;
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        break;

      case 'sha1':
        name = `IOC_Hunt_SHA1_${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA1 hash(es)`;
        severity = 'medium';
        search = `index=* (sha1 IN (${list}) OR file_hash IN (${list}))
| stats count as hits, values(file_name) as files, dc(host) as unique_hosts by _time, sha1, host
| where hits > 0
| sort -hits`;
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        break;

      case 'registry_key':
        name = `IOC_Hunt_Registry_${ts}`;
        desc = `Detects registry modifications to ${values.length} known-malicious key(s)`;
        severity = 'high';
        search = `index=* sourcetype=xmlwineventlog EventCode IN (12,13,14) (${values.map(v => `TargetObject="${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}*"`).join(' OR ')})
| stats count as hits, dc(host) as unique_hosts by _time, host, TargetObject, Details, EventCode
| where hits > 0
| sort -hits`;
        fps = ['Legitimate software', 'Windows updates'];
        tuning = ['Filter out trusted installer processes'];
        break;

      case 'cve':
        name = `IOC_Hunt_CVE_${ts}`;
        desc = `Detects exploitation attempts targeting ${values.length} known CVE(s)`;
        severity = 'critical';
        search = `index=* (vulnerability IN (${list}) OR cve IN (${list}) OR signature IN (${list}))
| stats count as hits, dc(host) as unique_hosts by _time, host, signature, severity
| where hits > 0
| sort -hits`;
        fps = ['Authorized vulnerability scanning', 'Penetration testing'];
        tuning = ['Exclude authorized scanner IPs'];
        break;

      default:
        continue;
    }

    const rule = `[${name}]
description = ${desc}
search = ${search}
action.notable = 1
action.notable.param.rule_description = ${desc}
action.notable.param.rule_title = ${name}
action.notable.param.security_domain = threat
action.notable.param.severity = ${severity}
action.notable.param.nes_fields = src,dest,user,host
action.risk = 1
action.risk.param._risk_object_1 = ${riskObjectField}
action.risk.param._risk_object_type_1 = system
action.risk.param._risk_score_1 = ${severity === 'critical' ? '100' : severity === 'high' ? '75' : '50'}
action.correlationsearch.enabled = 1
action.correlationsearch.annotations = {"mitre_attack": [${techniques.map(t => `"${t}"`).join(', ')}]}
dispatch.earliest_time = -24h
dispatch.latest_time = now
cron_schedule = 0 * * * *
is_scheduled = 1
enableSched = 1
alert.suppress = 1
alert.suppress.period = 24h
alert.track = 1
alert.severity = ${severity === 'critical' ? '4' : severity === 'high' ? '3' : '2'}
alert.expires = 24h
alert.digest_mode = 0

# False Positives:
${fps.map(fp => `#   - ${fp}`).join('\n')}
#
# Tuning Notes:
${tuning.map(t => `#   - ${t}`).join('\n')}`;

    rules.push({
      platform: 'splunk',
      name,
      description: desc,
      severity,
      rule,
      mitreAttack: techniques,
      falsePositives: fps,
      tuningNotes: tuning,
      iocType: type,
      iocValues: values,
    });
  }

  return rules;
}

// ── Elastic Detection Rule Generator ─────────────────────────────────────────

// Elastic Security has a purpose-built rule type for exactly this use case:
// "threat_match" (Indicator Match) matches event fields against a maintained
// threat-intel index via threat_mapping entries, instead of baking IOC values
// into the rule's own query text (which requires redeploying the rule every
// time the IOC list changes). THREAT_INDEX below is a placeholder — populate
// it by exporting this tool's IOC store as ECS threat.indicator.* documents.
// CVE/vulnerability detections are NOT an indicator-match use case (there is
// no "threat.indicator.vulnerability" feed concept) so that case keeps a
// plain custom query rule instead of being forced into threat_match.
const THREAT_INDEX = 'logs-ioc-hunt-threat-intel';

interface ThreatMappingEntry { field: string; indicatorField: string }

function elasticThreatMatchRule(
  name: string, desc: string, severity: DetectionRule['severity'],
  eventQuery: string, eventIndex: string[], mappings: ThreatMappingEntry[],
  techniques: string[], fps: string[],
): string {
  return `{
  "name": "${name}",
  "description": "${desc}",
  "risk_score": ${severity === 'critical' ? 90 : severity === 'high' ? 70 : 40},
  "severity": "${severity === 'critical' ? 'critical' : severity === 'high' ? 'high' : 'medium'}",
  "type": "threat_match",
  "language": "kuery",
  "query": "${eventQuery}",
  "index": [${eventIndex.map(i => `"${i}"`).join(', ')}],
  "threat_index": ["${THREAT_INDEX}"],
  "threat_query": "*:*",
  "threat_mapping": [
${mappings.map(m => `    { "entries": [ { "field": "${m.field}", "type": "mapping", "value": "threat.indicator.${m.indicatorField}" } ] }`).join(',\n')}
  ],
  "threat_indicator_path": "threat.indicator",
  "threat_filters": [],
  "tags": [
    "ioc-hunt",
    "threat-intel"${techniques.length ? ',\n    ' + techniques.map(t => `"mitre:${t}"`).join(',\n    ') : ''}
  ],
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "${techniqueTacticId(techniques[0])}",
        "name": "${TACTIC_NAME_MAP[techniques[0]] ?? 'Initial Access'}",
        "reference": "https://attack.mitre.org/tactics/${techniqueTacticId(techniques[0])}/"
      },
      "technique": [
${techniques.map(t => `        {
          "id": "${t}",
          "name": "${t}",
          "reference": "https://attack.mitre.org/techniques/${t}/"
        }`).join(',\n')}
      ]
    }
  ],
  "interval": "1h",
  "from": "now-25m",
  "to": "now",
  "max_signals": 100,
  "enabled": true,
  "throttle": "24h",
  "actions": [],
  "false_positives": [
${fps.map(fp => `    "${fp}"`).join(',\n')}
  ],
  "references": [
    "IOC Hunt - Generated ${new Date().toISOString().split('T')[0]}"
  ],
  "exceptions_list": [],
  "meta": {
    "from": "threat-hunt-tool"
  }
}`;
}

function generateElasticRule(iocs: IOC[]): DetectionRule[] {
  const byType = groupByType(iocs);
  const rules: DetectionRule[] = [];

  for (const [type, typeIOCs] of Object.entries(byType) as [IOCType, IOC[]][]) {
    const values = typeIOCs.map(i => i.value);
    const techniques = techniquesForGroup(typeIOCs, type);
    let name = '';
    let desc = '';
    let severity: DetectionRule['severity'] = 'high';
    let fps: string[] = [];
    let tuning: string[] = [];
    let rule = '';

    const ts = new Date().toISOString().split('T')[0].replace(/-/g, '');

    switch (type) {
      case 'ip':
      case 'ipv6':
        name = `ioc-hunt-ip-${ts}`;
        desc = `Detects network connections to ${values.length} known-malicious IP(s)`;
        severity = 'critical';
        fps = ['Legitimate services on shared hosting', 'VPN/proxy IPs'];
        tuning = ['Exclude known-good IPs', 'Add threshold for minimum unique hosts'];
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:network', ['logs-*', 'filebeat-*', 'packetbeat-*'], [
          { field: 'destination.ip', indicatorField: 'ip' },
          { field: 'source.ip', indicatorField: 'ip' },
        ], techniques, fps);
        break;

      case 'domain':
        name = `ioc-hunt-domain-${ts}`;
        desc = `Detects DNS queries for ${values.length} known-malicious domain(s)`;
        severity = 'high';
        fps = ['Security research tools', 'Internal applications'];
        tuning = ['Filter out internal DNS forwarders'];
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:dns', ['logs-*', 'packetbeat-*'], [
          { field: 'dns.question.name', indicatorField: 'domain' },
        ], techniques, fps);
        break;

      case 'sha256':
        name = `ioc-hunt-sha256-${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA256 hash(es)`;
        severity = 'critical';
        fps = ['False positive hash collisions (extremely rare)'];
        tuning = ['Add parent process context', 'Correlate with network connections'];
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:file or event.category:process', ['logs-*', 'winlogbeat-*'], [
          { field: 'file.hash.sha256', indicatorField: 'file.hash.sha256' },
          { field: 'process.hash.sha256', indicatorField: 'file.hash.sha256' },
        ], techniques, fps);
        break;

      case 'md5':
        name = `ioc-hunt-md5-${ts}`;
        desc = `Detects files matching ${values.length} known-malicious MD5 hash(es)`;
        severity = 'medium';
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:file or event.category:process', ['logs-*', 'winlogbeat-*'], [
          { field: 'file.hash.md5', indicatorField: 'file.hash.md5' },
          { field: 'process.hash.md5', indicatorField: 'file.hash.md5' },
        ], techniques, fps);
        break;

      case 'sha1':
        name = `ioc-hunt-sha1-${ts}`;
        desc = `Detects files matching ${values.length} known-malicious SHA1 hash(es)`;
        severity = 'medium';
        fps = ['Legacy hash format — possible collisions'];
        tuning = ['Prefer SHA256 when available'];
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:file or event.category:process', ['logs-*', 'winlogbeat-*'], [
          { field: 'file.hash.sha1', indicatorField: 'file.hash.sha1' },
          { field: 'process.hash.sha1', indicatorField: 'file.hash.sha1' },
        ], techniques, fps);
        break;

      case 'registry_key':
        name = `ioc-hunt-registry-${ts}`;
        desc = `Detects registry modifications to ${values.length} known-malicious key(s)`;
        severity = 'high';
        fps = ['Legitimate software', 'Windows updates'];
        tuning = ['Filter out trusted installer processes'];
        // registry.path is the real ECS field — registry.key.path (previous
        // implementation) does not exist and would match zero events.
        rule = elasticThreatMatchRule(name, desc, severity, 'event.category:registry', ['logs-*', 'winlogbeat-*'], [
          { field: 'registry.path', indicatorField: 'registry.path' },
        ], techniques, fps);
        break;

      case 'cve':
        // Not an indicator-match use case — kept as a plain custom query rule.
        name = `ioc-hunt-cve-${ts}`;
        desc = `Detects exploitation attempts targeting ${values.length} known CVE(s)`;
        severity = 'critical';
        fps = ['Authorized vulnerability scanning', 'Penetration testing'];
        tuning = ['Exclude authorized scanner IPs'];
        {
          const query = `event.category:vulnerability AND vulnerability.id:(${values.map(v => `"${v}"`).join(' ')})`;
          rule = `{
  "name": "${name}",
  "description": "${desc}",
  "risk_score": 90,
  "severity": "critical",
  "type": "query",
  "language": "kuery",
  "query": "${query.replace(/"/g, '\\"')}",
  "tags": ["ioc-hunt", "threat-intel"${techniques.length ? ',\n    ' + techniques.map(t => `"mitre:${t}"`).join(',\n    ') : ''}],
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": { "id": "${techniqueTacticId(techniques[0])}", "name": "${TACTIC_NAME_MAP[techniques[0]] ?? 'Initial Access'}", "reference": "https://attack.mitre.org/tactics/${techniqueTacticId(techniques[0])}/" },
    "technique": [${techniques.map(t => `{ "id": "${t}", "name": "${t}", "reference": "https://attack.mitre.org/techniques/${t}/" }`).join(', ')}]
  }],
  "interval": "1h",
  "from": "now-24h",
  "to": "now",
  "max_signals": 100,
  "enabled": true,
  "throttle": "24h",
  "actions": [],
  "false_positives": [${fps.map(fp => `"${fp}"`).join(', ')}],
  "references": ["IOC Hunt - Generated ${new Date().toISOString().split('T')[0]}"],
  "exceptions_list": [],
  "meta": { "from": "threat-hunt-tool" }
}`;
        }
        break;

      default:
        continue;
    }

    rules.push({
      platform: 'elastic',
      name,
      description: desc,
      severity,
      rule,
      mitreAttack: techniques,
      falsePositives: fps,
      tuningNotes: tuning,
      iocType: type,
      iocValues: values,
    });
  }

  return rules;
}

// ── Main Export ──────────────────────────────────────────────────────────────

export function generateDetectionRules(
  iocs: IOC[],
  platform: DetectionPlatform | 'all' = 'all'
): DetectionRule[] {
  iocs = filterSafeQueryIOCs(iocs);
  if (iocs.length === 0) return [];

  const platforms: DetectionPlatform[] = platform === 'all'
    ? ['sigma', 'kql', 'splunk', 'elastic']
    : [platform];

  const rules: DetectionRule[] = [];

  for (const p of platforms) {
    switch (p) {
      case 'sigma':  rules.push(...generateSigma(iocs)); break;
      case 'kql':    rules.push(...generateKQLRule(iocs)); break;
      case 'splunk': rules.push(...generateSplunkRule(iocs)); break;
      case 'elastic':rules.push(...generateElasticRule(iocs)); break;
    }
  }

  return rules;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function groupByType(iocs: IOC[]): Partial<Record<IOCType, IOC[]>> {
  const map: Partial<Record<IOCType, IOC[]>> = {};
  for (const ioc of iocs) {
    if (!map[ioc.type]) map[ioc.type] = [];
    map[ioc.type]!.push(ioc);
  }
  return map;
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}
