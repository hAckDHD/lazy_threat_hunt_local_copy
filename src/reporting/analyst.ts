import type { IOC, AnalystReport, IOCType, IOCClassification } from '../types/index.js';
import { generateHuntQueries } from '../hunting/index.js';

export function generateAnalystReport(iocs: IOC[]): AnalystReport {
  const byType: Partial<Record<IOCType, IOC[]>> = {};
  const byClass: Partial<Record<IOCClassification, IOC[]>> = {};

  for (const ioc of iocs) {
    if (!byType[ioc.type]) byType[ioc.type] = [];
    byType[ioc.type]!.push(ioc);

    if (!byClass[ioc.classification]) byClass[ioc.classification] = [];
    byClass[ioc.classification]!.push(ioc);
  }

  const enriched = iocs.filter(i => i.enrichedAt).length;
  const huntQueries = generateHuntQueries(iocs, 'all');

  return {
    generatedAt: new Date().toISOString(),
    iocs,
    huntQueries,
    enrichmentSummary: {
      enriched,
      pending: iocs.length - enriched,
      failed: 0,
    },
    iocsByType: byType,
    iocsByClassification: byClass,
    threatActorHypotheses: deriveThreatHypotheses(iocs),
    detectionOpportunities: deriveDetectionOpportunities(iocs),
  };
}

function deriveThreatHypotheses(iocs: IOC[]): string[] {
  const hypotheses: string[] = [];
  const families = [...new Set(iocs.flatMap(i => i.enrichment?.malwareFamily ?? []))];
  const techniques = [...new Set(iocs.flatMap(i => i.enrichment?.attackTechniques ?? []))];
  const countries = [...new Set(iocs.map(i => i.enrichment?.country).filter(Boolean))];

  if (families.length > 0) {
    hypotheses.push(
      `Activity is consistent with ${families.join(', ')} malware — review TTP overlap with known campaigns.`
    );
  }
  if (techniques.includes('T1566') && techniques.includes('T1071')) {
    hypotheses.push(
      'Phishing + C2 communication pattern observed — likely initial access broker or APT initial-stage activity.'
    );
  }
  if (iocs.filter(i => i.type === 'domain').length > 10) {
    hypotheses.push(
      'High domain IOC volume may indicate DGA-based malware or infrastructure rotation — consider clustering by registration date.'
    );
  }
  if (countries.length > 3) {
    hypotheses.push(
      `Infrastructure spans ${countries.length} countries (${countries.slice(0, 5).join(', ')}) — possible bulletproof hosting or VPN exit nodes in use.`
    );
  }
  if (iocs.some(i => i.type === 'registry_key')) {
    hypotheses.push(
      'Registry persistence IOCs present — threat actor likely established persistence for long-term access.'
    );
  }
  if (!hypotheses.length) {
    hypotheses.push(
      'Insufficient enrichment data for confident attribution — enrich IOCs and cross-reference with threat intel feeds.'
    );
  }
  return hypotheses;
}

function deriveDetectionOpportunities(iocs: IOC[]): string[] {
  const ops: string[] = [];
  const types = new Set(iocs.map(i => i.type));

  if (types.has('ip') || types.has('domain')) {
    ops.push('Deploy network IOCs to EDL/threat feeds on perimeter firewalls and NGFW policies.');
    ops.push('Configure DNS RPZ (Response Policy Zones) for domain-based blocking.');
  }
  if (types.has('sha256') || types.has('md5') || types.has('sha1')) {
    ops.push('Add file hashes to EDR/AV custom IOC lists for real-time detection and response.');
    ops.push('Query SIEM for historical matches — check 30/60/90-day retrospective lookback.');
  }
  if (types.has('email')) {
    ops.push('Create email gateway sender block rules and configure DMARC/DKIM enforcement.');
  }
  if (types.has('registry_key')) {
    ops.push('Enable Windows Registry audit policies (Event IDs 12/13/14) if not active.');
    ops.push('Alert on creation of identified registry keys via Sysmon or EDR.');
  }
  if (types.has('cve')) {
    ops.push('Cross-reference CVEs with asset inventory to identify exposed/unpatched systems.');
    ops.push('Enable IDS/IPS signatures for identified CVE exploitation attempts.');
  }
  if (types.has('url')) {
    ops.push('Add malicious URLs to web proxy block categories and SSL inspection rules.');
  }
  return ops;
}

export function formatAnalystReportText(report: AnalystReport): string {
  const lines: string[] = [
    `IOC ANALYST REPORT`,
    `Generated: ${report.generatedAt}`,
    `${'='.repeat(60)}`,
    '',
    `SUMMARY`,
    `-------`,
    `Total IOCs: ${report.iocs.length}`,
    `Enriched: ${report.enrichmentSummary.enriched} / ${report.iocs.length}`,
    '',
    `IOC BREAKDOWN BY TYPE`,
    `---------------------`,
  ];

  for (const [type, typeIOCs] of Object.entries(report.iocsByType)) {
    lines.push(`  ${type.padEnd(14)}: ${typeIOCs.length}`);
  }

  lines.push('', `IOC BREAKDOWN BY CLASSIFICATION`, `-------------------------------`);
  for (const [cls, clsIOCs] of Object.entries(report.iocsByClassification)) {
    lines.push(`  ${cls.padEnd(14)}: ${clsIOCs.length}`);
  }

  lines.push('', `THREAT HYPOTHESES`, `-----------------`);
  for (const h of report.threatActorHypotheses) {
    lines.push(`  • ${h}`);
  }

  lines.push('', `DETECTION OPPORTUNITIES`, `-----------------------`);
  for (const d of report.detectionOpportunities) {
    lines.push(`  • ${d}`);
  }

  lines.push('', `HUNT QUERIES GENERATED`, `----------------------`);
  for (const q of report.huntQueries) {
    lines.push(`  [${q.platform.toUpperCase()}] ${q.description}`);
  }

  return lines.join('\n');
}
