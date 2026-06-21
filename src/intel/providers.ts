// ─────────────────────────────────────────────────────────────────────────────
// Ticket Intelligence — multi-provider IOC reputation analysis.
//
// Runs all applicable providers concurrently against a single IOC, aggregates
// votes into a weighted consensus score and verdict, and surfaces network /
// hosting / WHOIS context. Every provider is required to NEVER throw — all
// errors must be caught internally and represented as a ProviderResult with
// verdict='error'. The main entrypoint, analyzeIOC(), wraps the whole fan-out
// in a hard outer timeout so a misbehaving upstream cannot stall the caller.
// ─────────────────────────────────────────────────────────────────────────────

import { scrapeAbuseIPDBPublic } from '../enrichment/abuseipdb.js';

export type ProviderVerdict =
  | 'malicious'
  | 'suspicious'
  | 'clean'
  | 'unknown'
  | 'no_key'
  | 'manual_check'
  | 'error'
  | 'n/a';

export interface ProviderResult {
  source: string;
  verdict: ProviderVerdict;
  confidence: number; // 0-100
  evidence: string[];
  country?: string;
  asn?: string;
  org?: string;
  network?: string;
  registrar?: string;
  created?: string;
  lastSeen?: string;
  abuseScore?: number;
  maliciousCount?: number;
  suspiciousCount?: number;
  harmlessCount?: number;
  certCount?: number;
  earliestCert?: string;
  tags?: string[];
  raw?: Record<string, unknown>;
  link?: string;
  error?: string;
}

export interface TicketIntelResult {
  ioc: string;
  iocType: string;
  providers: Record<string, ProviderResult>;
  score: number; // 0-100 weighted
  verdict:
    | 'CLEAN'
    | 'LOW RISK'
    | 'SUSPICIOUS'
    | 'MALICIOUS'
    | 'HIGH CONFIDENCE MALICIOUS';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-100
  consensus: 'weak' | 'moderate' | 'strong' | 'unanimous';
  tags: string[];
  org?: string;
  asn?: string;
  country?: string;
  network?: string;
  registrar?: string;
  created?: string;
  analyzedAt: string;
}

// ── helpers ──────────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 8_000;
const OUTER_TIMEOUT_MS = 18_000; // must beat frontend 30s limit; 18s gives backend+network 12s headroom

const BAD_HOSTING = [
  'vultr',
  'choopa',
  'm247',
  'frantech',
  'leaseweb_abusive',
  'serverius',
  'combahton',
];

const CDN_ENTERPRISE = [
  'cloudflare',
  'akamai',
  'fastly',
  'amazon',
  'google',
  'microsoft',
  'apple',
  'azure',
];

const CLOUD_HOSTING = [
  'amazon',
  'aws',
  'google',
  'azure',
  'microsoft',
  'digitalocean',
  'linode',
  'vultr',
  'ovh',
  'hetzner',
  'oracle',
  'alibaba',
];

function lc(s: string | undefined): string {
  return (s ?? '').toLowerCase();
}

function matchesAny(haystack: string, needles: string[]): boolean {
  const h = haystack.toLowerCase();
  return needles.some((n) => h.includes(n));
}

function emptyResult(
  source: string,
  verdict: ProviderVerdict,
  evidence: string[] = [],
  extra: Partial<ProviderResult> = {},
): ProviderResult {
  return {
    source,
    verdict,
    confidence: 0,
    evidence,
    ...extra,
  };
}

function errorResult(source: string, err: unknown, link?: string): ProviderResult {
  const msg = err instanceof Error ? err.message : String(err);
  return {
    source,
    verdict: 'error',
    confidence: 0,
    evidence: [`Provider error: ${msg}`],
    error: msg,
    link,
  };
}

// Safe fetch with timeout. Returns the Response or throws.
async function safeFetch(
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = { Accept: 'application/json', ...(init.headers ?? {}) };
  // Use AbortController + setTimeout rather than AbortSignal.timeout() —
  // AbortSignal.timeout() is not reliable in all Bun versions.
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, headers, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ── VirusTotal ───────────────────────────────────────────────────────────────

interface VTStats {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
}

interface VTAttributes {
  last_analysis_stats?: VTStats;
  country?: string;
  asn?: number | string;
  as_owner?: string;
  network?: string;
  tags?: string[];
  reputation?: number;
  last_analysis_date?: number;
  last_modification_date?: number;
  whois?: string;
  registrar?: string;
  creation_date?: number;
}

interface VTResponse {
  data?: { attributes?: VTAttributes };
}

function vtGuiLink(value: string, type: string): string {
  switch (type) {
    case 'ip':
    case 'ipv6':
      return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}`;
    case 'domain':
    case 'hostname':
      return `https://www.virustotal.com/gui/domain/${encodeURIComponent(value)}`;
    case 'url':
      try {
        return `https://www.virustotal.com/gui/url/${btoa(value).replace(/=/g, '')}`;
      } catch {
        return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
      }
    default:
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
  }
}

function vtApiEndpoint(value: string, type: string): string | null {
  switch (type) {
    case 'ip':
    case 'ipv6':
      return `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`;
    case 'domain':
    case 'hostname':
      return `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(value)}`;
    case 'url':
      try {
        return `https://www.virustotal.com/api/v3/urls/${btoa(value).replace(/=/g, '')}`;
      } catch {
        return null;
      }
    case 'sha256':
    case 'sha1':
    case 'md5':
      return `https://www.virustotal.com/api/v3/files/${encodeURIComponent(value)}`;
    default:
      return null;
  }
}

// VT internal UI endpoint — same JSON shape as v3 API, no key required.
function vtUIEndpoint(value: string, type: string): string | null {
  switch (type) {
    case 'ip':
    case 'ipv6':
      return `https://www.virustotal.com/ui/ip_addresses/${encodeURIComponent(value)}`;
    case 'domain':
    case 'hostname':
      return `https://www.virustotal.com/ui/domains/${encodeURIComponent(value)}`;
    case 'sha256':
    case 'sha1':
    case 'md5':
      return `https://www.virustotal.com/ui/files/${encodeURIComponent(value)}`;
    default:
      return null;
  }
}

const VT_BROWSER_HEADERS: Record<string, string> = {
  'Accept': 'application/json',
  'Accept-Language': 'en-US,en;q=0.9',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'X-Tool': 'vt-ui-main',
  'Referer': 'https://www.virustotal.com/',
};

function parseVTAttributes(json: VTResponse, link: string): ProviderResult {
  const attrs = json.data?.attributes ?? {};
  const stats = attrs.last_analysis_stats ?? {};
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);
  const harmless = Number(stats.harmless ?? 0);
  const undetected = Number(stats.undetected ?? 0);
  const total = malicious + suspicious + harmless + undetected;

  let verdict: ProviderVerdict = 'unknown';
  let confidence = 0;
  const evidence: string[] = [];

  if (malicious >= 5) {
    verdict = 'malicious';
    confidence = Math.min(95, 80 + malicious);
    evidence.push(`Detected as malicious by ${malicious}/${total} vendors`);
  } else if (malicious >= 1) {
    verdict = 'suspicious';
    confidence = 50;
    evidence.push(`Detected as malicious by ${malicious}/${total} vendors`);
  } else if (total > 0) {
    verdict = 'clean';
    if (harmless > 5) {
      confidence = Math.min(85, 50 + harmless);
      evidence.push(`${harmless}/${total} vendors report harmless, 0 malicious`);
    } else {
      confidence = Math.min(50, 20 + total);
      evidence.push(`0/${total} malicious detections (${harmless} harmless, ${undetected} undetected)`);
    }
  } else {
    verdict = 'unknown';
    confidence = 15;
    evidence.push(`No analysis data from VirusTotal`);
  }

  const asnStr = attrs.asn !== undefined ? String(attrs.asn) : undefined;
  const created = attrs.creation_date
    ? new Date(Number(attrs.creation_date) * 1000).toISOString()
    : undefined;
  const lastSeen = attrs.last_analysis_date
    ? new Date(Number(attrs.last_analysis_date) * 1000).toISOString()
    : undefined;

  return {
    source: 'virustotal',
    verdict,
    confidence,
    evidence,
    country: attrs.country,
    asn: asnStr,
    org: attrs.as_owner,
    network: attrs.network,
    registrar: attrs.registrar,
    created,
    lastSeen,
    maliciousCount: malicious,
    suspiciousCount: suspicious,
    harmlessCount: harmless,
    tags: attrs.tags,
    link,
  };
}

async function providerVirusTotal(
  value: string,
  type: string,
  keyOverride?: string,
): Promise<ProviderResult> {
  const link = vtGuiLink(value, type);
  const apiKey = keyOverride || process.env.VT_API_KEY;

  // Build ordered attempt list: keyed API first, UI scrape as fallback
  const attempts: Array<{ url: string; headers: Record<string, string> }> = [];
  if (apiKey) {
    const apiUrl = vtApiEndpoint(value, type);
    if (apiUrl) attempts.push({ url: apiUrl, headers: { 'x-apikey': apiKey } });
  }
  const uiUrl = vtUIEndpoint(value, type);
  if (uiUrl) attempts.push({ url: uiUrl, headers: VT_BROWSER_HEADERS });

  if (attempts.length === 0) {
    return emptyResult('virustotal', 'n/a', ['VirusTotal does not support this IOC type'], { link });
  }

  let lastErr: unknown;
  for (const { url, headers } of attempts) {
    try {
      const res = await safeFetch(url, { headers });
      if (res.status === 404) {
        return emptyResult('virustotal', 'unknown', ['Not found in VirusTotal'], { link });
      }
      if (res.status === 429) {
        lastErr = new Error('VT rate limited');
        continue;
      }
      if (!res.ok) {
        lastErr = new Error(`HTTP ${res.status}`);
        continue;
      }
      const json = (await res.json()) as VTResponse;
      return parseVTAttributes(json, link);
    } catch (err) {
      lastErr = err;
      // timeout or network error — try next path
    }
  }
  return errorResult('virustotal', lastErr, link);
}

// ── AbuseIPDB ────────────────────────────────────────────────────────────────

interface AbuseAPIResponse {
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

async function providerAbuseIPDB(
  value: string,
  type: string,
  keyOverride?: string,
): Promise<ProviderResult> {
  if (type !== 'ip' && type !== 'ipv6') {
    return emptyResult('abuseipdb', 'n/a', ['AbuseIPDB is IP-only']);
  }
  const link = `https://www.abuseipdb.com/check/${encodeURIComponent(value)}`;
  const apiKey = keyOverride || process.env.ABUSEIPDB_API_KEY;

  // API key path first; falls through to HTML scrape on any failure
  if (apiKey) {
    try {
      const res = await safeFetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`,
        { headers: { Key: apiKey, Accept: 'application/json' } },
      );
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = (await res.json()) as AbuseAPIResponse;
      const d = json.data ?? {};
      const score = Number(d.abuseConfidenceScore ?? 0);
      const reports = Number(d.totalReports ?? 0);
      const usage = d.usageType ?? '';
      return classifyAbuse({ score, reports, usage, country: d.countryCode, isp: d.isp, lastSeen: d.lastReportedAt }, link);
    } catch {
      // API key path failed (timeout / network / non-2xx) — fall through to HTML scrape
    }
  }

  // No key or API path failed — scrape public check page
  try {
    const scraped = await scrapeAbuseIPDBPublic(value);
    if (scraped) {
      return classifyAbuse({
        score: scraped.abuseConfidence,
        reports: scraped.reportCount,
        country: scraped.country,
        isp: scraped.isp,
        usage: scraped.usageType,
        lastSeen: scraped.lastReported,
      }, link);
    }
  } catch { /* fall through */ }
  return emptyResult('abuseipdb', 'unknown', ['AbuseIPDB: API and scrape both failed — check manually'], { link });
}

function classifyAbuse(
  d: { score: number; reports: number; usage?: string; country?: string; isp?: string; lastSeen?: string },
  link: string,
): ProviderResult {
  let verdict: ProviderVerdict;
  let confidence: number;
  const evidence: string[] = [];

  if (d.score > 75) {
    verdict = 'malicious';
    confidence = 85;
  } else if (d.score > 40) {
    verdict = 'suspicious';
    confidence = 60;
  } else if (d.score > 0) {
    verdict = 'suspicious';
    confidence = 40;
  } else {
    verdict = 'clean';
    confidence = 50;
  }

  evidence.push(`AbuseIPDB score: ${d.score}/100, ${d.reports} reports`);
  if (d.usage) evidence.push(`Usage: ${d.usage}`);
  if (d.reports > 0 && /scan|probe|brute/i.test(d.usage ?? '')) {
    evidence.push('Reports mention scanning activity');
  }

  return {
    source: 'abuseipdb',
    verdict,
    confidence,
    evidence,
    country: d.country,
    org: d.isp,
    abuseScore: d.score,
    lastSeen: d.lastSeen,
    link,
  };
}

// ── ipinfo ───────────────────────────────────────────────────────────────────

interface IPInfoResponse {
  ip?: string;
  hostname?: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string;
  org?: string;
  postal?: string;
  timezone?: string;
}

async function providerIPInfo(
  value: string,
  type: string,
): Promise<ProviderResult> {
  if (type !== 'ip' && type !== 'ipv6') {
    return emptyResult('ipinfo', 'n/a', ['ipinfo provides IP context only']);
  }
  const link = `https://ipinfo.io/${encodeURIComponent(value)}`;
  try {
    const res = await safeFetch(`https://ipinfo.io/${encodeURIComponent(value)}/json`);
    if (!res.ok) return errorResult('ipinfo', `HTTP ${res.status}`, link);
    const d = (await res.json()) as IPInfoResponse;
    const orgRaw = d.org ?? '';
    const asnMatch = orgRaw.match(/^AS(\d+)\s+(.+)$/);
    const asn = asnMatch ? `AS${asnMatch[1]}` : undefined;
    const org = asnMatch ? asnMatch[2] : orgRaw || undefined;
    const country = d.country;
    const evidence: string[] = [];
    const locationParts = [d.city, d.region, country].filter(Boolean);
    if (locationParts.length) evidence.push(`Location: ${locationParts.join(', ')}`);
    if (asn) evidence.push(`ASN: ${asn} — ${org ?? ''}`);
    if (d.hostname) evidence.push(`Hostname: ${d.hostname}`);
    if (d.postal) evidence.push(`Postal: ${d.postal}`);
    return {
      source: 'ipinfo',
      verdict: 'unknown',
      confidence: 0,
      evidence,
      country,
      asn,
      org,
      network: undefined,
      link,
      raw: { city: d.city, region: d.region, timezone: d.timezone, hostname: d.hostname } as Record<string, unknown>,
    };
  } catch (err) {
    return errorResult('ipinfo', err, link);
  }
}

// ── ARIN RDAP ────────────────────────────────────────────────────────────────

interface RDAPCidr {
  v4prefix?: string;
  v6prefix?: string;
  length?: number;
}

interface RDAPResponse {
  name?: string;
  handle?: string;
  startAddress?: string;
  endAddress?: string;
  country?: string;
  cidr0_cidrs?: RDAPCidr[];
  entities?: Array<{ vcardArray?: unknown[]; roles?: string[] }>;
}

async function providerARIN(value: string, type: string): Promise<ProviderResult> {
  if (type !== 'ip' && type !== 'ipv6') {
    return emptyResult('arin', 'n/a', ['ARIN RDAP is IP-only']);
  }
  const link = `https://rdap.arin.net/registry/ip/${encodeURIComponent(value)}`;
  try {
    const res = await safeFetch(link);
    if (!res.ok) return errorResult('arin', `HTTP ${res.status}`, link);
    const d = (await res.json()) as RDAPResponse;
    const name = d.name ?? d.handle;
    let cidr: string | undefined;
    const c0 = d.cidr0_cidrs?.[0];
    if (c0) {
      if (c0.v4prefix && c0.length !== undefined) cidr = `${c0.v4prefix}/${c0.length}`;
      else if (c0.v6prefix && c0.length !== undefined) cidr = `${c0.v6prefix}/${c0.length}`;
    }
    if (!cidr && d.startAddress && d.endAddress) cidr = `${d.startAddress} - ${d.endAddress}`;
    const evidence: string[] = [];
    if (name) evidence.push(`ARIN: ${name}${cidr ? ` (${cidr})` : ''}`);
    return {
      source: 'arin',
      verdict: 'unknown',
      confidence: 0,
      evidence,
      country: d.country,
      org: name,
      network: cidr,
      link,
    };
  } catch (err) {
    return errorResult('arin', err, link);
  }
}

// ── crt.sh ───────────────────────────────────────────────────────────────────

interface CrtShEntry {
  issuer_ca_id?: number;
  issuer_name?: string;
  name_value?: string;
  id?: number;
  entry_timestamp?: string;
  not_before?: string;
  not_after?: string;
  serial_number?: string;
}

async function providerCrtSh(value: string, type: string): Promise<ProviderResult> {
  if (type !== 'domain' && type !== 'hostname') {
    return emptyResult('crtsh', 'n/a', ['crt.sh is domain-only']);
  }
  const link = `https://crt.sh/?q=${encodeURIComponent(value)}`;
  try {
    const res = await safeFetch(`https://crt.sh/?q=${encodeURIComponent(value)}&output=json`);
    if (!res.ok) return errorResult('crtsh', `HTTP ${res.status}`, link);
    const text = await res.text();
    let arr: CrtShEntry[];
    try {
      arr = JSON.parse(text) as CrtShEntry[];
    } catch {
      // crt.sh sometimes returns invalid concatenated JSON — wrap it
      try {
        arr = JSON.parse(`[${text.replace(/}\s*{/g, '},{')}]`) as CrtShEntry[];
      } catch {
        return errorResult('crtsh', 'Failed to parse JSON response', link);
      }
    }
    if (!Array.isArray(arr) || arr.length === 0) {
      return emptyResult('crtsh', 'unknown', ['No certificates found on crt.sh'], { link });
    }
    let earliestTs: number | null = null;
    for (const e of arr) {
      const nb = e.not_before;
      if (!nb) continue;
      const t = Date.parse(nb);
      if (Number.isFinite(t) && (earliestTs === null || t < earliestTs)) earliestTs = t;
    }
    const earliest = earliestTs !== null ? new Date(earliestTs).toISOString() : undefined;
    const certCount = arr.length;
    const ageDays =
      earliestTs !== null ? Math.floor((Date.now() - earliestTs) / 86_400_000) : null;

    let verdict: ProviderVerdict = 'unknown';
    let confidence = 0;
    const evidence: string[] = [];

    if (ageDays !== null && ageDays < 30) {
      verdict = 'suspicious';
      confidence = 55;
      evidence.push(`Newly registered: ${ageDays}d old`);
    } else if (ageDays !== null && ageDays < 90) {
      verdict = 'unknown';
      confidence = 20;
      evidence.push(`Recently registered: ${ageDays}d old`);
    } else if (certCount > 50) {
      verdict = 'clean';
      confidence = 35;
      evidence.push(`Mature domain: ${certCount} certs over time`);
    } else if (ageDays !== null) {
      evidence.push(`Domain age: ${ageDays}d`);
    }

    if (earliest) {
      evidence.push(`First cert: ${earliest.slice(0, 10)}, ${certCount} certs found`);
    } else {
      evidence.push(`${certCount} certs found`);
    }

    return {
      source: 'crtsh',
      verdict,
      confidence,
      evidence,
      certCount,
      earliestCert: earliest,
      created: earliest,
      link,
    };
  } catch (err) {
    return errorResult('crtsh', err, link);
  }
}

// ── urlscan ──────────────────────────────────────────────────────────────────

interface UrlscanVerdict {
  malicious?: boolean;
  score?: number;
  hasVerdicts?: boolean;
}
interface UrlscanResult {
  task?: { url?: string; time?: string };
  verdicts?: { overall?: UrlscanVerdict };
  page?: { domain?: string; ip?: string };
}
interface UrlscanSearch {
  results?: UrlscanResult[];
  total?: number;
}

async function providerUrlscan(
  value: string,
  type: string,
): Promise<ProviderResult> {
  let q: string;
  let size: number;
  let link: string;
  switch (type) {
    case 'ip':
    case 'ipv6':
      q = `ip:${value}`;
      size = 5;
      link = `https://urlscan.io/search/#ip%3A${encodeURIComponent(value)}`;
      break;
    case 'domain':
    case 'hostname':
      q = `page.domain:${value}`;
      size = 10;
      link = `https://urlscan.io/domain/${encodeURIComponent(value)}`;
      break;
    case 'url':
      q = `page.url:"${value}"`;
      size = 5;
      link = `https://urlscan.io/search/#${encodeURIComponent(value)}`;
      break;
    default:
      return emptyResult('urlscan', 'n/a', ['urlscan does not support this IOC type']);
  }

  try {
    const apiKey = process.env.URLSCAN_API_KEY;
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (apiKey) headers['Authorization'] = `API-Key ${apiKey}`;
    const res = await safeFetch(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=${size}`,
      { headers },
    );
    if (!res.ok) return errorResult('urlscan', `HTTP ${res.status}`, link);
    const d = (await res.json()) as UrlscanSearch;
    const results = d.results ?? [];
    let maliciousCount = 0;
    let scanned = results.length;
    for (const r of results) {
      const v = r.verdicts?.overall;
      if (v?.malicious) maliciousCount++;
    }
    let verdict: ProviderVerdict = 'unknown';
    let confidence = 0;
    const evidence: string[] = [];

    if (maliciousCount > 0) {
      verdict = 'malicious';
      confidence = Math.min(85, 50 + maliciousCount * 10);
      evidence.push(`urlscan: ${maliciousCount}/${scanned} scans flagged malicious`);
    } else if (scanned > 0) {
      verdict = 'clean';
      confidence = 35;
      evidence.push(`urlscan: ${scanned} scans, none flagged malicious`);
    } else {
      verdict = 'unknown';
      confidence = 0;
      evidence.push('urlscan: no previous scans');
    }

    return {
      source: 'urlscan',
      verdict,
      confidence,
      evidence,
      maliciousCount,
      link,
    };
  } catch (err) {
    return errorResult('urlscan', err, link);
  }
}

// ── Talos (link-only, manual check) ──────────────────────────────────────────

function providerTalos(value: string, type: string): ProviderResult {
  if (type !== 'ip' && type !== 'ipv6' && type !== 'domain' && type !== 'hostname') {
    return emptyResult('talos', 'n/a', ['Talos supports IPs and domains only']);
  }
  return {
    source: 'talos',
    verdict: 'manual_check',
    confidence: 0,
    evidence: ['Talos Intelligence — manual verification required'],
    link: `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(value)}`,
  };
}

// ── Main entrypoint ──────────────────────────────────────────────────────────

function applicableProviders(type: string): Array<(v: string, t: string) => Promise<ProviderResult> | ProviderResult> {
  const list: Array<(v: string, t: string) => Promise<ProviderResult> | ProviderResult> = [];
  list.push(providerVirusTotal);
  if (type === 'ip' || type === 'ipv6') {
    list.push(providerAbuseIPDB, providerIPInfo, providerARIN, providerUrlscan, providerTalos);
  } else if (type === 'domain' || type === 'hostname') {
    list.push(providerCrtSh, providerUrlscan, providerTalos);
  } else if (type === 'url') {
    list.push(providerUrlscan);
  } else if (type === 'sha256' || type === 'sha1' || type === 'md5') {
    // VT already added above — hashes only supported by VT
  } else if (type === 'email') {
    // VT domain lookup on the domain part — handled in providerVirusTotal
  }
  return list;
}

export interface AnalyzeOptions {
  vtKey?: string;
  abuseKey?: string;
}

export async function analyzeIOC(value: string, type: string, opts: AnalyzeOptions = {}): Promise<TicketIntelResult> {
  const analyzedAt = new Date().toISOString();
  const vtKey = opts.vtKey || undefined;
  const abuseKey = opts.abuseKey || undefined;

  // Build provider list with keys injected via closures — no env mutation.
  const baselist = applicableProviders(type);
  const providersList = baselist.map((fn) => {
    if (fn === providerVirusTotal) return (v: string, t: string) => providerVirusTotal(v, t, vtKey);
    if (fn === providerAbuseIPDB) return (v: string, t: string) => providerAbuseIPDB(v, t, abuseKey);
    return fn;
  });

  // Run all providers concurrently; race the whole batch against an outer
  // timeout so a single misbehaving upstream can't stall the response.
  const settled = await Promise.race<PromiseSettledResult<ProviderResult>[]>([
    Promise.allSettled(providersList.map((fn) => Promise.resolve(fn(value, type)))),
    new Promise<PromiseSettledResult<ProviderResult>[]>((resolve) =>
      setTimeout(
        () =>
          resolve(
            providersList.map(
              () =>
                ({
                  status: 'rejected',
                  reason: new Error(`Outer timeout (${OUTER_TIMEOUT_MS}ms)`),
                }) as PromiseRejectedResult,
            ),
          ),
        OUTER_TIMEOUT_MS,
      ),
    ),
  ]);

  const providers: Record<string, ProviderResult> = {};
  for (let i = 0; i < settled.length; i++) {
    const s = settled[i];
    if (s.status === 'fulfilled') {
      providers[s.value.source] = s.value;
    } else {
      // Provider promise rejected outright — shouldn't happen, but be safe.
      const fnName = providersList[i].name.replace(/^provider/i, '').toLowerCase() || `p${i}`;
      providers[fnName] = errorResult(fnName, s.reason);
    }
  }

  // ── Consensus engine ───────────────────────────────────────────────────────
  const allResults = Object.values(providers);
  const active = allResults.filter(
    (r) => !['error', 'no_key', 'manual_check', 'n/a', 'unknown'].includes(r.verdict),
  );
  const maliciousVotes = active.filter((r) => r.verdict === 'malicious').length;
  const cleanVotes = active.filter((r) => r.verdict === 'clean').length;

  let consensus: TicketIntelResult['consensus'] = 'weak';
  if (active.length === 0) {
    consensus = 'weak';
  } else if (maliciousVotes === active.length && active.length >= 2) {
    consensus = 'unanimous';
  } else if (maliciousVotes >= 3) {
    consensus = 'strong';
  } else if (maliciousVotes >= 2) {
    consensus = 'moderate';
  } else if (maliciousVotes >= 1 && cleanVotes >= 1) {
    consensus = 'weak';
  } else {
    consensus = 'weak';
  }

  // ── Weighted scoring ───────────────────────────────────────────────────────
  let score = 0;
  const vt = providers['virustotal'];
  if (vt && (vt.maliciousCount ?? 0) >= 5) score += 40;
  else if (vt && (vt.maliciousCount ?? 0) >= 1) score += 20;

  const abuse = providers['abuseipdb'];
  if (abuse && (abuse.abuseScore ?? 0) > 75) score += 25;
  else if (abuse && (abuse.abuseScore ?? 0) > 40) score += 15;

  const urlscan = providers['urlscan'];
  if (urlscan && (urlscan.maliciousCount ?? 0) > 0) score += 20;

  const crt = providers['crtsh'];
  if (crt?.earliestCert) {
    const ageDays = Math.floor((Date.now() - Date.parse(crt.earliestCert)) / 86_400_000);
    if (Number.isFinite(ageDays)) {
      if (ageDays < 30) score += 15;
      else if (ageDays > 365) score -= 20;
    }
  }

  // org-based scoring uses the first non-empty org we can find
  const orgPool = [
    providers['ipinfo']?.org,
    providers['arin']?.org,
    providers['virustotal']?.org,
    providers['abuseipdb']?.org,
  ].filter((s): s is string => Boolean(s));
  const orgJoined = orgPool.join(' ').toLowerCase();
  if (orgJoined && matchesAny(orgJoined, BAD_HOSTING)) score += 10;
  if (orgJoined && matchesAny(orgJoined, CDN_ENTERPRISE)) score -= 10;

  // 2+ providers report clean → bias score down
  if (cleanVotes >= 2) score -= 15;

  if (score < 0) score = 0;
  if (score > 100) score = 100;

  // ── Verdict + severity ─────────────────────────────────────────────────────
  let verdict: TicketIntelResult['verdict'];
  let severity: TicketIntelResult['severity'];
  if (score >= 85) {
    verdict = 'HIGH CONFIDENCE MALICIOUS';
    severity = 'critical';
  } else if (score >= 70) {
    verdict = 'MALICIOUS';
    severity = 'high';
  } else if (score >= 40) {
    verdict = 'SUSPICIOUS';
    severity = 'medium';
  } else if (score >= 20) {
    verdict = 'LOW RISK';
    severity = 'low';
  } else {
    verdict = 'CLEAN';
    severity = 'info';
  }

  // ── Confidence ─────────────────────────────────────────────────────────────
  let confidence = 0;
  if (active.length > 0) {
    const sum = active.reduce((a, r) => a + r.confidence, 0);
    confidence = Math.round(sum / active.length);
    // Bonus for stronger consensus
    if (consensus === 'unanimous') confidence = Math.min(100, confidence + 15);
    else if (consensus === 'strong') confidence = Math.min(100, confidence + 10);
    else if (consensus === 'moderate') confidence = Math.min(100, confidence + 5);
  }

  // ── Tag generation ─────────────────────────────────────────────────────────
  const tags = new Set<string>();
  if (crt?.earliestCert) {
    const ageDays = Math.floor((Date.now() - Date.parse(crt.earliestCert)) / 86_400_000);
    if (Number.isFinite(ageDays) && ageDays < 30) tags.add('newly-registered');
  }
  if (orgJoined && matchesAny(orgJoined, CLOUD_HOSTING)) tags.add('cloud-hosted');
  if (orgJoined && matchesAny(orgJoined, BAD_HOSTING)) tags.add('bulletproof-hosting');
  const abuseEvidence = (abuse?.evidence ?? []).join(' ').toLowerCase();
  if (/scan|probe/.test(abuseEvidence)) tags.add('scanning');
  if (score >= 70) tags.add('malicious');
  else if (score >= 50) tags.add('suspicious');
  else if (score <= 20) tags.add('clean');
  if (consensus === 'weak' && maliciousVotes >= 1 && cleanVotes >= 1) tags.add('disputed');

  // ── Unified intel fields (first non-null wins) ─────────────────────────────
  const ipinfoR = providers['ipinfo'];
  const arinR = providers['arin'];
  const vtR = providers['virustotal'];

  const pickFirst = (...vals: Array<string | undefined>): string | undefined =>
    vals.find((v) => v !== undefined && v !== null && v !== '');

  const org = pickFirst(ipinfoR?.org, arinR?.org, vtR?.org, abuse?.org);
  const asn = pickFirst(ipinfoR?.asn, vtR?.asn);
  const country = pickFirst(ipinfoR?.country, arinR?.country, vtR?.country, abuse?.country);
  const network = pickFirst(arinR?.network, vtR?.network);
  const registrar = pickFirst(vtR?.registrar);
  const created = pickFirst(crt?.earliestCert, vtR?.created);

  return {
    ioc: value,
    iocType: type,
    providers,
    score,
    verdict,
    severity,
    confidence,
    consensus,
    tags: Array.from(tags),
    org,
    asn,
    country,
    network,
    registrar,
    created,
    analyzedAt,
  };
}

// Touch lc() so the helper isn't pruned by tree-shakers — it's part of the
// public surface for future provider implementations.
export const _internal = { lc };
