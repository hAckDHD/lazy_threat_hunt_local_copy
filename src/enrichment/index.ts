import type { IOC, IOCEnrichment, EnrichmentConfig } from '../types/index.js';
import { enrichWithVT } from './virustotal.js';
import { enrichWithAbuseIPDB } from './abuseipdb.js';
import { enrichWithShodan } from './shodan.js';
import { updateEnrichment, updateClassification } from '../storage/db.js';

export function loadConfig(): EnrichmentConfig {
  return {
    virusTotal: process.env.VT_API_KEY,
    abuseIpDb: process.env.ABUSEIPDB_API_KEY,
    shodan: process.env.SHODAN_API_KEY,
  };
}

export async function enrichIOC(
  ioc: IOC,
  config?: EnrichmentConfig
): Promise<IOC> {
  const cfg = config ?? loadConfig();
  const enrichments: IOCEnrichment[] = [];

  const tasks: Promise<IOCEnrichment | null>[] = [];

  if (cfg.virusTotal) {
    tasks.push(enrichWithVT(ioc, cfg.virusTotal));
  }
  if (cfg.abuseIpDb && (ioc.type === 'ip' || ioc.type === 'ipv6')) {
    tasks.push(enrichWithAbuseIPDB(ioc, cfg.abuseIpDb));
  }
  if (cfg.shodan && (ioc.type === 'ip' || ioc.type === 'ipv6')) {
    tasks.push(enrichWithShodan(ioc, cfg.shodan));
  }

  const results = await Promise.allSettled(tasks);
  for (const r of results) {
    if (r.status === 'fulfilled' && r.value) enrichments.push(r.value);
  }

  if (enrichments.length === 0) return ioc;

  // Merge enrichments: take highest reputation score, combine arrays
  const merged = mergeEnrichments(enrichments);
  const updated: IOC = { ...ioc, enrichment: merged, enrichedAt: new Date().toISOString() };

  // Auto-classify based on reputation score
  const classification = scoreToClassification(merged.reputationScore);
  updated.classification = classification;

  // Persist to DB
  await updateEnrichment(ioc.id, merged);
  await updateClassification(ioc.id, classification);

  return updated;
}

export async function enrichBatch(
  iocs: IOC[],
  config?: EnrichmentConfig,
  concurrency = 3
): Promise<IOC[]> {
  const cfg = config ?? loadConfig();
  const results: IOC[] = [];

  // Process in chunks to avoid rate limiting
  for (let i = 0; i < iocs.length; i += concurrency) {
    const chunk = iocs.slice(i, i + concurrency);
    const enriched = await Promise.all(chunk.map(ioc => enrichIOC(ioc, cfg)));
    results.push(...enriched);

    // Polite delay between batches
    if (i + concurrency < iocs.length) {
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  return results;
}

function mergeEnrichments(list: IOCEnrichment[]): IOCEnrichment {
  const merged: IOCEnrichment = { provider: list.map(e => e.provider).join('+') };

  // Take max reputation score across providers
  const scores = list.map(e => e.reputationScore).filter((s): s is number => s !== undefined);
  if (scores.length) merged.reputationScore = Math.max(...scores);

  // Take first non-null geo values
  for (const e of list) {
    if (!merged.country && e.country) merged.country = e.country;
    if (!merged.city && e.city) merged.city = e.city;
    if (!merged.asn && e.asn) merged.asn = e.asn;
    if (!merged.asnOrg && e.asnOrg) merged.asnOrg = e.asnOrg;
    if (!merged.latitude && e.latitude) merged.latitude = e.latitude;
    if (!merged.longitude && e.longitude) merged.longitude = e.longitude;
    if (!merged.firstSeen && e.firstSeen) merged.firstSeen = e.firstSeen;
    if (!merged.lastSeen && e.lastSeen) merged.lastSeen = e.lastSeen;
  }

  // Combine arrays
  const families = list.flatMap(e => e.malwareFamily ?? []);
  if (families.length) merged.malwareFamily = [...new Set(families)];

  const techniques = list.flatMap(e => e.attackTechniques ?? []);
  if (techniques.length) merged.attackTechniques = [...new Set(techniques)];

  return merged;
}

function scoreToClassification(score?: number): IOC['classification'] {
  if (score === undefined) return 'unknown';
  if (score >= 70) return 'malicious';
  if (score >= 30) return 'suspicious';
  return 'unknown';
}
