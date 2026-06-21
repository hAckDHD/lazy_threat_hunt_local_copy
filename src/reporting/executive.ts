import type { IOC, ExecutiveReport } from '../types/index.js';

const ATTACK_TECHNIQUE_NAMES: Record<string, string> = {
  T1566: 'Phishing',
  T1190: 'Exploit Public-Facing Application',
  T1059: 'Command and Scripting Interpreter',
  T1071: 'Application Layer Protocol (C2)',
  T1055: 'Process Injection',
  T1078: 'Valid Accounts',
  T1486: 'Data Encrypted for Impact (Ransomware)',
  T1041: 'Exfiltration Over C2 Channel',
  T1005: 'Data from Local System',
  T1083: 'File and Directory Discovery',
};

export function generateExecutiveReport(
  iocs: IOC[],
  periodStart: string,
  periodEnd: string
): ExecutiveReport {
  const malicious = iocs.filter(i => i.classification === 'malicious');
  const suspicious = iocs.filter(i => i.classification === 'suspicious');
  const criticalCount = malicious.length;

  // Severity scoring
  const severity = deriveSeverity(criticalCount, iocs.length);

  // Geo spread from enrichment
  const countries = [...new Set(
    iocs
      .filter(i => i.enrichment?.country)
      .map(i => i.enrichment!.country!)
  )];

  // ATT&CK techniques found across enrichments
  const allTechniques = iocs.flatMap(i => i.enrichment?.attackTechniques ?? []);
  const uniqueTechniques = [...new Set(allTechniques)];

  // Malware families
  const families = [...new Set(
    iocs.flatMap(i => i.enrichment?.malwareFamily ?? []).filter(Boolean)
  )];

  // External communications: any URL or IP IOC with external classification
  const hasExternalComms = iocs.some(
    i => (i.type === 'url' || i.type === 'ip') && i.classification === 'malicious'
  );

  // Timeline: use extraction timestamps grouped by day
  const timeline = buildTimeline(iocs);

  // Business-readable recommendations
  const recommendations = buildRecommendations(iocs, severity, families, uniqueTechniques);

  // Estimated impact string (business-readable)
  const estimatedImpact = buildImpactStatement(criticalCount, severity, families);

  return {
    generatedAt: new Date().toISOString(),
    periodStart,
    periodEnd,
    totalIOCs: iocs.length,
    criticalCount,
    severity,
    businessImpact: {
      affectedSystems: deriveAffectedSystems(iocs),
      usersAtRisk: estimateUsersAtRisk(iocs),
      externalCommunications: hasExternalComms,
      estimatedImpact,
      geographicSpread: countries,
    },
    timeline,
    attackTechniques: uniqueTechniques.map(
      t => `${t} — ${ATTACK_TECHNIQUE_NAMES[t] ?? 'Unknown Technique'}`
    ),
    recommendations,
  };
}

function deriveSeverity(critical: number, total: number): ExecutiveReport['severity'] {
  if (critical >= 10 || (total > 0 && critical / total > 0.3)) return 'critical';
  if (critical >= 5) return 'high';
  if (critical >= 1) return 'medium';
  return 'low';
}

function deriveAffectedSystems(iocs: IOC[]): string[] {
  const systems: Set<string> = new Set();
  for (const ioc of iocs) {
    if (ioc.type === 'domain' || ioc.type === 'hostname') systems.add('DNS / Proxy Infrastructure');
    if (ioc.type === 'ip') systems.add('Network Perimeter / Firewall');
    if (['sha256', 'sha1', 'md5'].includes(ioc.type)) systems.add('Endpoint / EDR Systems');
    if (ioc.type === 'email') systems.add('Email / Mail Gateway');
    if (ioc.type === 'registry_key') systems.add('Windows Endpoints (Registry)');
    if (ioc.type === 'cve') systems.add('Vulnerable Applications / Patch Management');
    if (ioc.type === 'url') systems.add('Web Proxy / Browser Controls');
  }
  return [...systems];
}

function estimateUsersAtRisk(iocs: IOC[]): number {
  // Conservative heuristic: email IOCs = 1 user each; others = broader risk
  const emailCount = iocs.filter(i => i.type === 'email').length;
  const hasEndpoint = iocs.some(i => ['sha256', 'sha1', 'md5', 'registry_key'].includes(i.type));
  const hasNetwork = iocs.some(i => ['ip', 'domain', 'url'].includes(i.type));

  let risk = emailCount;
  if (hasEndpoint) risk += 50;
  if (hasNetwork) risk += 100;
  return risk;
}

function buildTimeline(iocs: IOC[]): ExecutiveReport['timeline'] {
  const byDay = new Map<string, IOC[]>();
  for (const ioc of iocs) {
    const day = ioc.extractedAt.split('T')[0];
    if (!byDay.has(day)) byDay.set(day, []);
    byDay.get(day)!.push(ioc);
  }

  const events: ExecutiveReport['timeline'] = [];
  for (const [day, dayIOCs] of [...byDay.entries()].sort()) {
    const malCount = dayIOCs.filter(i => i.classification === 'malicious').length;
    events.push({
      timestamp: day,
      event: `${dayIOCs.length} indicator(s) extracted — ${malCount} confirmed malicious`,
      severity: malCount > 0 ? 'high' : 'medium',
    });
  }
  return events;
}

function buildRecommendations(
  iocs: IOC[],
  severity: ExecutiveReport['severity'],
  families: string[],
  techniques: string[]
): string[] {
  const recs: string[] = [];

  if (iocs.some(i => i.type === 'ip' && i.classification === 'malicious')) {
    recs.push('Block all confirmed malicious IP addresses at the perimeter firewall immediately.');
  }
  if (iocs.some(i => i.type === 'domain' && i.classification === 'malicious')) {
    recs.push('Add malicious domains to DNS sinkhole / web proxy blocklist within 24 hours.');
  }
  if (iocs.some(i => ['sha256', 'sha1', 'md5'].includes(i.type) && i.classification === 'malicious')) {
    recs.push('Trigger endpoint AV/EDR scan using malicious file hashes across all endpoints.');
  }
  if (iocs.some(i => i.type === 'email')) {
    recs.push('Quarantine emails from identified malicious senders; notify affected recipients.');
  }
  if (iocs.some(i => i.type === 'cve')) {
    recs.push('Prioritize patching CVEs referenced in this intelligence within the next patch cycle.');
  }
  if (families.length > 0) {
    recs.push(
      `Investigate for signs of ${families.join(', ')} malware across impacted systems.`
    );
  }
  if (techniques.some(t => t === 'T1486')) {
    recs.push('CRITICAL: Ransomware indicators detected. Verify offline backups are intact and isolated.');
  }
  if (severity === 'critical' || severity === 'high') {
    recs.push('Escalate to CISO and legal team for potential breach notification obligations.');
    recs.push('Activate incident response plan and establish a war room if not already active.');
  }

  recs.push('Share IOC list with ISACs and trusted peers under TLP:AMBER.');
  return recs;
}

function buildImpactStatement(
  criticalCount: number,
  severity: ExecutiveReport['severity'],
  families: string[]
): string {
  const familyStr = families.length > 0
    ? ` associated with ${families.join(', ')}`
    : '';

  const sevMap = {
    critical: 'CRITICAL — Immediate containment required.',
    high: 'HIGH — Significant risk to operations.',
    medium: 'MEDIUM — Elevated monitoring warranted.',
    low: 'LOW — Informational; monitor and track.',
  };

  return `${criticalCount} confirmed malicious indicator(s) detected${familyStr}. Severity: ${sevMap[severity]}`;
}
