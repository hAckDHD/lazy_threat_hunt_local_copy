import type { IOC, IOCEnrichment } from '../types/index.js';

const BASE = 'https://www.virustotal.com/api/v3';

export async function enrichWithVT(
  ioc: IOC,
  apiKey: string
): Promise<IOCEnrichment | null> {
  const endpoint = vtEndpoint(ioc);
  if (!endpoint) return null;

  try {
    const res = await fetch(`${BASE}/${endpoint}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`VT API ${res.status}`);

    const json = (await res.json()) as VTResponse;
    return parseVTResponse(json, ioc);
  } catch (err) {
    console.error(`[VT] enrichment failed for ${ioc.value}:`, err);
    return null;
  }
}

function vtEndpoint(ioc: IOC): string | null {
  switch (ioc.type) {
    case 'ip':     return `ip_addresses/${encodeURIComponent(ioc.value)}`;
    case 'domain': return `domains/${encodeURIComponent(ioc.value)}`;
    case 'url':    return `urls/${btoa(ioc.value).replace(/=/g, '')}`;
    case 'sha256': return `files/${ioc.value}`;
    case 'sha1':   return `files/${ioc.value}`;
    case 'md5':    return `files/${ioc.value}`;
    default:       return null;
  }
}

interface VTResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: { malicious?: number; total?: number };
      reputation?: number;
      country?: string;
      asn?: number;
      as_owner?: string;
      tags?: string[];
      last_submission_date?: number;
      first_submission_date?: number;
      popular_threat_classification?: { suggested_threat_label?: string };
    };
  };
}

function parseVTResponse(json: VTResponse, ioc: IOC): IOCEnrichment {
  const attrs = json.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const malicious = stats.malicious ?? 0;
  const total = ((stats as Record<string, number>).harmless ?? 0) +
                ((stats as Record<string, number>).suspicious ?? 0) +
                malicious +
                ((stats as Record<string, number>).undetected ?? 0);

  const score = total > 0 ? Math.round((malicious / total) * 100) : 0;

  return {
    provider: 'virustotal',
    reputationScore: score,
    country: attrs.country,
    asn: attrs.asn ? String(attrs.asn) : undefined,
    asnOrg: attrs.as_owner,
    firstSeen: attrs.first_submission_date
      ? new Date(attrs.first_submission_date * 1000).toISOString()
      : undefined,
    lastSeen: attrs.last_submission_date
      ? new Date(attrs.last_submission_date * 1000).toISOString()
      : undefined,
    malwareFamily: attrs.popular_threat_classification?.suggested_threat_label
      ? [attrs.popular_threat_classification.suggested_threat_label]
      : [],
    positives: malicious,
    total,
    raw: { tags: attrs.tags },
  };
}
