import type { IOC, IOCEnrichment } from '../types/index.js';

export interface AbuseIPDBPublicResult {
  ip: string;
  reportCount: number;
  abuseConfidence: number;
  country?: string;
  isp?: string;
  usageType?: string;
  lastReported?: string;
  vtLink: string;
  abuseLink: string;
}

// Scrape AbuseIPDB check page — no API key required
export async function scrapeAbuseIPDBPublic(
  ip: string
): Promise<AbuseIPDBPublicResult | null> {
  try {
    const res = await fetch(`https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache',
      },
      signal: AbortSignal.timeout(6000),
    });

    if (!res.ok) return null;
    const html = await res.text();

    // Parse confidence percentage — multiple fallback patterns for HTML changes
    let abuseConfidence = 0;
    const confPatterns = [
      /confidence[^%]*?(\d{1,3})%/i,
      /Confidence of Abuse[^>]*>[\s\S]*?(\d{1,3})/i,
      /"abuseConfidenceScore"\s*:\s*(\d+)/,
      /(\d{1,3})<small>%<\/small>/,
      /<span[^>]*abusePercent[^>]*>(\d+)/i,
    ];
    for (const pat of confPatterns) {
      const m = html.match(pat);
      if (m) { abuseConfidence = parseInt(m[1], 10); break; }
    }

    // Parse report count
    let reportCount = 0;
    const reportPatterns = [
      /reported\s+(?:<[^>]+>)?(\d[\d,]*)/i,
      /(\d[\d,]+)\s+times/i,
      /total[^>]*>[\s\S]*?(\d[\d,]+)/i,
    ];
    for (const pat of reportPatterns) {
      const m = html.match(pat);
      if (m) { reportCount = parseInt(m[1].replace(/,/g, ''), 10); break; }
    }

    // Parse ISP
    const ispMatch = html.match(/(?:ISP|isp)[^<]*<[^>]+>\s*([^<]{3,80})\s*</) ??
                     html.match(/"isp"\s*:\s*"([^"]+)"/);
    const isp = ispMatch?.[1]?.trim().replace(/&amp;/g, '&');

    // Parse country
    const countryMatch = html.match(/country[^<]*<[^>]+>\s*([A-Z]{2})\b/) ??
                         html.match(/"countryCode"\s*:\s*"([A-Z]{2})"/);
    const country = countryMatch?.[1];

    // Parse usage type
    const usageMatch = html.match(/usage[^<]*<[^>]+>\s*([^<]{3,60})\s*</i);
    const usageType = usageMatch?.[1]?.trim();

    // Parse last reported
    const lastMatch = html.match(/(?:last\s+report|reported)\s+(?:on\s+)?([A-Za-z]+\.?\s+\d{1,2},?\s+\d{4})/i);
    const lastReported = lastMatch?.[1]?.trim();

    return {
      ip,
      reportCount,
      abuseConfidence,
      country,
      isp,
      usageType,
      lastReported,
      vtLink: `https://www.virustotal.com/gui/ip-address/${ip}`,
      abuseLink: `https://www.abuseipdb.com/check/${ip}`,
    };
  } catch (err) {
    console.error(`[AbuseIPDB-public] scrape failed for ${ip}:`, err);
    return null;
  }
}

const BASE = 'https://api.abuseipdb.com/api/v2';

export async function enrichWithAbuseIPDB(
  ioc: IOC,
  apiKey: string
): Promise<IOCEnrichment | null> {
  if (ioc.type !== 'ip' && ioc.type !== 'ipv6') return null;

  try {
    const url = new URL(`${BASE}/check`);
    url.searchParams.set('ipAddress', ioc.value);
    url.searchParams.set('maxAgeInDays', '90');
    url.searchParams.set('verbose', '');

    const res = await fetch(url, {
      headers: {
        Key: apiKey,
        Accept: 'application/json',
      },
    });

    if (!res.ok) throw new Error(`AbuseIPDB API ${res.status}`);
    const json = (await res.json()) as AbuseIPDBResponse;
    return parseResponse(json);
  } catch (err) {
    console.error(`[AbuseIPDB] enrichment failed for ${ioc.value}:`, err);
    return null;
  }
}

interface AbuseIPDBResponse {
  data?: {
    abuseConfidenceScore?: number;
    countryCode?: string;
    isp?: string;
    domain?: string;
    lastReportedAt?: string;
    totalReports?: number;
    usageType?: string;
  };
}

function parseResponse(json: AbuseIPDBResponse): IOCEnrichment {
  const d = json.data ?? {};
  return {
    provider: 'abuseipdb',
    reputationScore: d.abuseConfidenceScore,
    country: d.countryCode,
    asnOrg: d.isp,
    lastSeen: d.lastReportedAt,
    raw: {
      domain: d.domain,
      totalReports: d.totalReports,
      usageType: d.usageType,
    },
  };
}
