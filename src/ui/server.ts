import { scrapeURL } from '../ingestion/scraper.js';
import { parseBulkText } from '../ingestion/manual.js';
import { parseBuffer } from '../ingestion/file-parser.js';
import { upsertIOC, bulkUpsertIOCs, bulkLinkSourceUrl, listIOCs, countIOCs, getStats, deleteIOC, deleteByTag, getIOC, ignoreIOC, annotateIOC, restoreAllIgnored, getStatsByType, getFeeds, getFeedsWithTypes, getStatsBySource, deleteBySourceUrl, clearAllIOCs } from '../storage/db.js';
import { analyzeIOC, type AnalyzeOptions } from '../intel/providers.js';
import { enrichIOC } from '../enrichment/index.js';
import { classifyBatch } from '../classification/classifier.js';
import { generateHuntQueries } from '../hunting/index.js';
import { generateExecutiveReport } from '../reporting/executive.js';
import { generateAnalystReport, formatAnalystReportText } from '../reporting/analyst.js';
import { generateDetectionRules } from '../detection/index.js';
import type { IOCFilter, IOCType } from '../types/index.js';
import { randomUUID, randomBytes, createHash, timingSafeEqual } from 'crypto';
import { readFile } from 'fs/promises';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { normalizeIOC } from '../extractor/normalizer.js';
import { validateSSRFUrl } from '../security/net.js';
import { VALID_IOC_TYPES, sanitizeTimeRange } from '../security/validate.js';

const PORT = Number(process.env.IOC_PORT ?? 8847);
const HOST = process.env.IOC_HOST ?? '127.0.0.1';
const AUTH_TOKEN = process.env.IOC_API_TOKEN ?? '';
const ALLOWED_ORIGIN = process.env.IOC_ALLOWED_ORIGIN ?? '';
// Only honour X-Forwarded-For / X-Real-IP when a trusted proxy sets them
// (Vercel always does); otherwise they are client-controlled and would let
// anyone dodge the rate limiter by rotating a header.
const TRUST_PROXY = Boolean(process.env.VERCEL) || process.env.IOC_TRUST_PROXY === '1';
// Server-side enrichment keys (VT/AbuseIPDB/Shodan from env) are only spent
// when the instance is private: auth is on, or it is a local loopback-only
// server. A public, unauthenticated deployment would otherwise let anyone
// burn the operator's API quota. IOC_SHARE_SERVER_KEYS=1 overrides.
const IS_LOOPBACK_ONLY = !process.env.VERCEL && ['127.0.0.1', 'localhost', '::1'].includes(HOST);
const SHARE_SERVER_KEYS = Boolean(AUTH_TOKEN) || IS_LOOPBACK_ONLY || process.env.IOC_SHARE_SERVER_KEYS === '1';
const MAX_BODY_BYTES = 6 * 1024 * 1024;
const MAX_TEXT_CHARS = 2 * 1024 * 1024;
const MAX_RAW_IOCS = 5000;

// Static client assets — a fixed allow-list, never a path taken from the
// request. Resolved from this module's location (not the working directory),
// so the server runs the same from any folder on Windows, macOS and Linux.
let _publicDir: string | undefined;
function publicDir(): string {
  if (!_publicDir) {
    try { _publicDir = fileURLToPath(new URL('../../public/', import.meta.url)); }
    catch { _publicDir = join(process.cwd(), 'public'); }  // bundlers that drop import.meta.url
  }
  return _publicDir;
}
const JS_TYPE = 'application/javascript; charset=utf-8';
const STATIC_FILES = new Map<string, { file: string[]; type: string; cache: string }>([
  ['/cheatsheet.js', { file: ['cheatsheet.js'], type: JS_TYPE, cache: 'no-store' }],
  ['/detection.js', { file: ['detection.js'], type: JS_TYPE, cache: 'no-store' }],
  ['/ttp-library.js', { file: ['ttp-library.js'], type: JS_TYPE, cache: 'no-store' }],
  ['/frameworks.js', { file: ['frameworks.js'], type: JS_TYPE, cache: 'no-store' }],
  // Title font is self-hosted so the page makes no third-party requests and
  // the CSP needs no font-src exception.
  ['/fonts/ChakraPetch-Bold.woff2', { file: ['fonts', 'ChakraPetch-Bold.woff2'], type: 'font/woff2', cache: 'public, max-age=31536000, immutable' }],
]);

function serverKey(name: 'VT_API_KEY' | 'ABUSEIPDB_API_KEY' | 'SHODAN_API_KEY'): string | undefined {
  return SHARE_SERVER_KEYS ? (process.env[name] || undefined) : undefined;
}

// ── Auth ────────────────────────────────────────────────────────────────────
// Open when IOC_API_TOKEN is unset (each visitor is still isolated to their
// own session data). Setting IOC_API_TOKEN requires a Bearer token on every
// API request.
function tokensEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

function checkAuth(req: Request, path: string): Response | null {
  if (!AUTH_TOKEN) return null;
  // The page shell and its static assets carry no data; every API route needs the token.
  if (req.method === 'OPTIONS' || path === '/' || path === '/index.html' || STATIC_FILES.has(path)) return null;
  const header = req.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!tokensEqual(token, AUTH_TOKEN)) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer' },
    });
  }
  return null;
}

// ── Per-instance session isolation (no login) ───────────────────────────────
// Every visitor gets an opaque, unguessable token that scopes all of their
// data in the DB (see session_id in src/storage/db.ts) — invisible to any
// other visitor, with no signup/password/account involved. `/` and
// `/index.html` always mint a brand-new token, overwriting any existing
// cookie, so a real browser refresh always starts a genuinely empty
// instance; every other request (including same-tab client-side navigation
// within the SPA, which never re-requests `/`) reuses whatever cookie came
// in, so multiple tabs opened from the same load — or repeated API calls
// within one page life — keep sharing one instance's data.
const SESSION_COOKIE = 'lth_session';
const IS_PROD = Boolean(process.env.VERCEL || process.env.NODE_ENV === 'production');

function parseCookies(header: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) out[key] = value;
  }
  return out;
}

function isValidSessionId(s: string): boolean {
  return /^[a-f0-9]{64}$/.test(s);
}

function resolveSession(req: Request, path: string): { sessionId: string; setCookie?: string } {
  const isFreshLoad = path === '/' || path === '/index.html';
  if (!isFreshLoad) {
    const existing = parseCookies(req.headers.get('Cookie') ?? '')[SESSION_COOKIE];
    if (existing && isValidSessionId(existing)) return { sessionId: existing };
  }
  const sessionId = randomBytes(32).toString('hex');
  const attrs = [`${SESSION_COOKIE}=${sessionId}`, 'HttpOnly', 'SameSite=Strict', 'Path=/'];
  if (IS_PROD) attrs.push('Secure');
  return { sessionId, setCookie: attrs.join('; ') };
}

// ── Rate limiting ────────────────────────────────────────────────────────────
// Per-IP fixed-window limiter with no external dependency, applied to every
// endpoint that calls an outside service (enrichment lookups, URL scraping).
// Multi-instance deployments should add their platform's shared limiter or
// firewall in front as well.
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 20;
const RATE_LIMITED_PATHS = new Set(['/api/enrich', '/api/intel/analyze', '/api/ingest/url', '/api/feeds/update', '/api/ingest/file']);
const RATE_LIMITED_PREFIXES = ['/api/check/abuse/', '/api/check/live/'];
const _rateBuckets = new Map<string, { count: number; windowStart: number }>();

function clientIP(req: Request, socketIP?: string): string {
  if (TRUST_PROXY) {
    return req.headers.get('x-real-ip')
      || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      || socketIP || 'unknown';
  }
  return socketIP || 'unknown';
}

function checkRateLimit(req: Request, path: string, socketIP?: string): Response | null {
  const bucketPath = RATE_LIMITED_PATHS.has(path) ? path : RATE_LIMITED_PREFIXES.find(p => path.startsWith(p));
  if (!bucketPath) return null;
  const key = `${clientIP(req, socketIP)}:${bucketPath}`;
  const now = Date.now();
  if (_rateBuckets.size > 5000) {
    for (const [k, b] of _rateBuckets) if (now - b.windowStart > RATE_LIMIT_WINDOW_MS) _rateBuckets.delete(k);
    if (_rateBuckets.size > 20000) _rateBuckets.clear();
  }
  const bucket = _rateBuckets.get(key);
  if (!bucket || now - bucket.windowStart > RATE_LIMIT_WINDOW_MS) {
    _rateBuckets.set(key, { count: 1, windowStart: now });
    return null;
  }
  bucket.count++;
  if (bucket.count > RATE_LIMIT_MAX) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded — wait a bit and try again.' }), {
      status: 429,
      headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
    });
  }
  return null;
}

// ── Input validation ─────────────────────────────────────────────────────────
// SSRF validation for scraped URLs lives in src/security/net.ts.
function isValidIP(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || (/^[0-9a-fA-F:]+$/.test(s) && s.includes(':') && s.length <= 45);
}

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function readJSON<T>(req: Request): Promise<T> {
  try {
    const body = await req.json();
    if (!body || typeof body !== 'object') throw new Error();
    return body as T;
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
}

function requireString(v: unknown, field: string, max = 4096): string {
  if (typeof v !== 'string' || !v || v.length > max) throw new HttpError(400, `${field} must be a non-empty string (max ${max} chars)`);
  return v;
}

// Validate a client-supplied list of {value,type} pairs (Hunt/Detect custom lists).
function parseRawIOCs(raw: unknown): Array<{ value: string; type: IOCType }> {
  if (!Array.isArray(raw)) return [];
  if (raw.length > MAX_RAW_IOCS) throw new HttpError(413, `Too many IOCs (max ${MAX_RAW_IOCS})`);
  return raw
    .filter((r): r is { value: string; type: string } =>
      !!r && typeof r.value === 'string' && typeof r.type === 'string'
      && r.value.length <= 2048 && VALID_IOC_TYPES.has(r.type as IOCType))
    .map(r => ({ value: r.value, type: r.type as IOCType }));
}

function stringArray(v: unknown, max = MAX_RAW_IOCS): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string' && x.length <= 256).slice(0, max);
}

// SSRF guard: validate IOC value matches expected pattern for the declared type
function isValidIOCValue(ioc: string, type: string): boolean {
  if (!ioc || ioc.length > 500) return false;
  switch (type) {
    case 'ip':
      return /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    case 'ipv6':
      return /^[0-9a-fA-F:]+$/.test(ioc) && ioc.length <= 45;
    case 'domain':
    case 'hostname':
      return /^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*\.[a-zA-Z]{2,}$/.test(ioc);
    case 'url':
      try {
        const u = new URL(ioc);
        return ['http:', 'https:'].includes(u.protocol);
      } catch { return false; }
    case 'sha256':
      return /^[a-fA-F0-9]{64}$/.test(ioc);
    case 'sha1':
      return /^[a-fA-F0-9]{40}$/.test(ioc);
    case 'md5':
      return /^[a-fA-F0-9]{32}$/.test(ioc);
    case 'email':
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(ioc);
    case 'cve':
      return /^CVE-\d{4}-\d{4,}$/i.test(ioc);
    case 'filename':
      return /^[a-zA-Z0-9_\-\.]+$/.test(ioc) && ioc.length <= 255;
    case 'registry_key':
      return /^[A-Z_\\]+$/i.test(ioc) && ioc.length <= 500;
    default:
      return false;
  }
}

export async function handleRequest(req: Request, socketIP?: string): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (!['GET', 'HEAD', 'POST', 'DELETE', 'OPTIONS'].includes(req.method)) return new Response(null, { status: 405 });

  const cors: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    // Same-origin only: no third-party scripts, styles, fonts or connections,
    // no plugins, no framing, no <base> rewriting, no cross-site form posts.
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'",
  };
  if (IS_PROD) cors['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  if (ALLOWED_ORIGIN) { cors['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN; cors['Vary'] = 'Origin'; }

  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  // CSRF: browsers always send Origin on cross-site POST/DELETE. Reject any
  // state-changing request from an origin that is neither this host nor the
  // configured allowed origin.
  if (req.method === 'POST' || req.method === 'DELETE') {
    const origin = req.headers.get('origin');
    if (origin && origin !== url.origin && origin !== ALLOWED_ORIGIN) {
      let sameHost = false;
      try { sameHost = new URL(origin).host === (req.headers.get('host') ?? url.host); } catch {}
      if (!sameHost) return json({ error: 'Cross-origin request rejected' }, cors, 403);
    }
    const len = Number(req.headers.get('content-length') ?? 0);
    if (len > MAX_BODY_BYTES) return json({ error: 'Request body too large' }, cors, 413);
  }

  const authErr = checkAuth(req, path);
  if (authErr) return authErr;

  const rateErr = checkRateLimit(req, path, socketIP);
  if (rateErr) return rateErr;

  const { sessionId, setCookie } = resolveSession(req, path);
  if (setCookie) cors['Set-Cookie'] = setCookie;

  try {
        // === API Routes ===

        if (path === '/api/iocs' && req.method === 'GET') {
          const filter = parseFilter(url, sessionId);
          const iocs = await listIOCs(filter);
          const countFilter = { ...filter, limit: undefined, offset: undefined };
          const total = await countIOCs(countFilter);
          return json({ iocs, total, page: filter.offset ?? 0, limit: filter.limit ?? 100 }, cors);
        }

        if (path === '/api/stats' && req.method === 'GET') {
          return json(await getStats(sessionId), cors);
        }

        if (path === '/api/feeds' && req.method === 'GET') {
          return json(await getFeeds(sessionId), cors);
        }

        if (path === '/api/feeds/iocs' && req.method === 'GET') {
          return json(await getFeedsWithTypes(sessionId), cors);
        }

        if (path === '/api/stats/by-source' && req.method === 'GET') {
          return json(await getStatsBySource(sessionId), cors);
        }

        if (path === '/api/feeds/update' && req.method === 'POST') {
          const body = await readJSON<{ url?: unknown }>(req);
          const url = requireString(body.url, 'url', 2048);
          await validateSSRFUrl(url);
          const result = await scrapeURL(url);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified, sessionId);
          const { updated } = await bulkLinkSourceUrl(classified, url, sessionId);
          return json({ ok: true, inserted, updated, total: result.stats.total }, cors);
        }

        if (path === '/api/feeds/delete' && req.method === 'POST') {
          const body = await readJSON<{ url?: unknown }>(req);
          await deleteBySourceUrl(requireString(body.url, 'url', 2048), sessionId);
          return json({ ok: true }, cors);
        }

        if (path === '/api/iocs' && req.method === 'DELETE') {
          const body = await readJSON<{ id?: unknown }>(req);
          await deleteIOC(requireString(body.id, 'id', 128), sessionId);
          return json({ ok: true }, cors);
        }

        if (path === '/api/iocs/delete-by-tag' && req.method === 'POST') {
          const body = await readJSON<{ tag?: unknown }>(req);
          const tag = requireString(body.tag, 'tag', 32);
          if (!/^[a-z0-9_-]{1,32}$/.test(tag)) return json({ error: 'invalid tag' }, cors, 400);
          const { deleted } = await deleteByTag(tag, sessionId);
          return json({ ok: true, deleted }, cors);
        }

        // Extract-only — parses text, returns IOCs, does NOT save to DB
        if (path === '/api/extract/text' && req.method === 'POST') {
          const body = await readJSON<{ text?: unknown }>(req);
          const text = requireString(body.text, 'text', MAX_TEXT_CHARS);
          const result = parseBulkText(text);
          const classified = classifyBatch(result.iocs);
          return json({ ...result.stats, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
        }

        if (path === '/api/ingest/text' && req.method === 'POST') {
          const body = await readJSON<{ text?: unknown; returnIOCs?: boolean }>(req);
          const text = requireString(body.text, 'text', MAX_TEXT_CHARS);
          const returnIOCs = body.returnIOCs === true;
          const result = parseBulkText(text);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified, sessionId);
          const base = { ...result.stats, inserted };
          if (returnIOCs) return json({ ...base, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
          return json(base, cors);
        }

        if (path === '/api/ingest/url' && req.method === 'POST') {
          const body = await readJSON<{ url?: unknown; returnIOCs?: boolean }>(req);
          const targetUrl = requireString(body.url, 'url', 2048);
          const returnIOCs = body.returnIOCs === true;
          await validateSSRFUrl(targetUrl);
          const result = await scrapeURL(targetUrl);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified, sessionId);
          const base = { ...result.stats, inserted, sourceUrl: targetUrl };
          if (returnIOCs) return json({ ...base, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
          return json(base, cors);
        }

        if (path === '/api/ingest/file' && req.method === 'POST') {
          let formData: FormData;
          try { formData = await req.formData(); } catch { return json({ error: 'Invalid multipart body' }, cors, 400); }
          const file = formData.get('file');
          if (!file || typeof file === 'string') return json({ error: 'No file provided' }, cors, 400);
          if (file.size > 5 * 1024 * 1024) return json({ error: 'File too large (max 5 MB)' }, cors, 413);

          const buf = Buffer.from(await file.arrayBuffer());
          const filename = (file.name || 'upload').replace(/[^\w.\- ]/g, '_').slice(0, 200);
          const result = await parseBuffer(buf, file.type, filename);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified, sessionId);
          return json({ ...result.stats, inserted, filename }, cors);
        }

        // Explicit value+type pairs (e.g. from the Hunt Builder's manual add/paste
        // inputs, where the type is already known/user-picked) — skips regex
        // re-extraction, just normalizes, classifies, and persists directly so
        // these IOCs also show up in the IOC List and Enrichment tabs.
        if (path === '/api/iocs/add-manual' && req.method === 'POST') {
          const { iocs: rawIOCs, tags: rawTags } = await readJSON<{ iocs: Array<{ value: string; type: string }>; tags?: unknown }>(req);
          if (!Array.isArray(rawIOCs) || !rawIOCs.length) return json({ error: 'iocs must be a non-empty array' }, cors, 400);
          if (rawIOCs.length > MAX_RAW_IOCS) return json({ error: `Too many IOCs (max ${MAX_RAW_IOCS})` }, cors, 413);
          // Optional caller-supplied tags (e.g. 'sample' for demo data so it can
          // be removed in one click). Restricted to a safe slug charset so a tag
          // can't later break out when rendered or matched with LIKE.
          const tags = Array.isArray(rawTags)
            ? rawTags.filter((t): t is string => typeof t === 'string' && /^[a-z0-9_-]{1,32}$/.test(t)).slice(0, 8)
            : [];
          // This is the only ingestion path that takes `type` directly from
          // the client instead of deriving it from regex-pattern extraction
          // (extract() always assigns type from a fixed literal per pattern),
          // and the only one that doesn't format-check `value` at all — so it
          // needs its own validation or a crafted type/value pair (e.g.
          // containing a quote or angle bracket) can end up stored and later
          // rendered unescaped in an HTML attribute or inline event handler
          // elsewhere in the UI (Analyst View's IOC links/buttons).
          const BREAKOUT_CHARS = /[<>"'`\u0000-\u001f\u007f]/;
          const now = new Date().toISOString();
          const built = rawIOCs
            .filter(r => typeof r?.value === 'string' && typeof r?.type === 'string' && r.value
              && VALID_IOC_TYPES.has(r.type as IOCType)
              && r.value.length <= 500
              && !BREAKOUT_CHARS.test(r.value))
            .map(r => ({
              id: randomUUID(),
              value: normalizeIOC(r.value.trim(), r.type as IOCType),
              type: r.type as IOCType,
              classification: 'unknown' as const,
              source: 'manual' as const,
              extractedAt: now,
              tags: [...tags],
            }));
          const classified = classifyBatch(built);
          const { inserted } = await bulkUpsertIOCs(classified, sessionId);
          return json({ total: classified.length, inserted, duplicatesRemoved: classified.length - inserted, rejected: rawIOCs.length - classified.length }, cors);
        }

        if (path === '/api/enrich' && req.method === 'POST') {
          const body = await readJSON<{ id?: unknown; vtKey?: unknown; abuseKey?: unknown }>(req);
          const ioc = await getIOC(requireString(body.id, 'id', 128), sessionId);
          if (!ioc) return json({ error: 'IOC not found' }, cors, 404);
          const userKey = (k: unknown) => (typeof k === 'string' && k && k.length <= 256 ? k : undefined);
          const cfg = {
            virusTotal: userKey(body.vtKey) || serverKey('VT_API_KEY'),
            abuseIpDb: userKey(body.abuseKey) || serverKey('ABUSEIPDB_API_KEY'),
            shodan: serverKey('SHODAN_API_KEY'),
          };
          if (!cfg.virusTotal && !cfg.abuseIpDb && !cfg.shodan) {
            return json({ error: 'No API keys configured. Add VT or AbuseIPDB keys in Settings.' }, cors, 400);
          }
          const enriched = await enrichIOC(ioc, cfg, sessionId);
          return json({ ioc: enriched }, cors);
        }

        // AbuseIPDB check — uses real API if key configured, otherwise returns curl commands
        if (path.startsWith('/api/check/abuse/') && req.method === 'GET') {
          const ip = decodeURIComponent(path.replace('/api/check/abuse/', ''));
          if (!ip || !isValidIP(ip)) return json({ error: 'Invalid IP address' }, cors, 400);

          const apiKey = serverKey('ABUSEIPDB_API_KEY');

          if (apiKey) {
            // Use the real API
            try {
              const r = await fetch(
                `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
                { headers: { Key: apiKey, Accept: 'application/json' } }
              );
              if (!r.ok) throw new Error(`AbuseIPDB API ${r.status}`);
              const d = (await r.json()) as { data?: Record<string, unknown> };
              const data = d.data ?? {};
              return json({
                ip,
                hasKey: true,
                abuseConfidence: data.abuseConfidenceScore ?? 0,
                reportCount: data.totalReports ?? 0,
                country: data.countryCode,
                isp: data.isp,
                usageType: data.usageType,
                lastReported: data.lastReportedAt,
                domain: data.domain,
                vtLink: `https://www.virustotal.com/gui/ip-address/${ip}`,
                abuseLink: `https://www.abuseipdb.com/check/${ip}`,
                curlCmd: `curl -s -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip}" --data-urlencode "maxAgeInDays=90" -H "Key: $ABUSEIPDB_API_KEY" -H "Accept: application/json" | jq '.data | {score: .abuseConfidenceScore, reports: .totalReports, isp: .isp, country: .countryCode}'`,
              }, cors);
            } catch (err) {
              return json({ error: String(err), ip }, cors, 500);
            }
          }

          // No API key — return links + curl template
          return json({
            ip,
            hasKey: false,
            abuseLink: `https://www.abuseipdb.com/check/${ip}`,
            vtLink: `https://www.virustotal.com/gui/ip-address/${ip}`,
            otxLink: `https://otx.alienvault.com/indicator/ip/${ip}`,
            shodanLink: `https://www.shodan.io/host/${ip}`,
            curlCmd: `curl -s -G https://api.abuseipdb.com/api/v2/check --data-urlencode "ipAddress=${ip}" --data-urlencode "maxAgeInDays=90" -H "Key: YOUR_ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data | {score: .abuseConfidenceScore, reports: .totalReports, isp: .isp, country: .countryCode}'`,
            vtCurlCmd: `curl -s "https://www.virustotal.com/api/v3/ip_addresses/${ip}" -H "x-apikey: YOUR_VT_KEY" | jq '.data.attributes | {score: .last_analysis_stats, country: .country, asn: .asn}'`,
            note: 'No ABUSEIPDB_API_KEY configured. Add to .env for inline results.',
          }, cors);
        }

        // Live IP check — no API key required (ipinfo.io + ipwho.is + Google DoH), HTTPS only
        if (path.startsWith('/api/check/live/') && req.method === 'GET') {
          const ip = decodeURIComponent(path.replace('/api/check/live/', ''));
          if (!ip || !isValidIP(ip)) return json({ error: 'Invalid IP address' }, cors, 400);

          let org: string | null = null, country: string | null = null, city: string | null = null;
          let rdns: string | null = null, proxy: boolean | null = null, hosting: boolean | null = null;
          let source = '';

          const liveCtrl = (ms: number) => { const c = new AbortController(); setTimeout(() => c.abort(), ms); return c.signal; };

          // Try ipinfo.io first — 50k/month free, no key
          try {
            const r = await fetch(`https://ipinfo.io/${ip}/json`, {
              headers: { Accept: 'application/json' },
              signal: liveCtrl(4000),
            });
            if (r.ok) {
              const d = await r.json() as Record<string, unknown>;
              org = String(d.org ?? '').replace(/^AS\d+\s+/, '') || null;
              country = (d.country as string) ?? null;
              city = (d.city as string) ?? null;
              rdns = (d.hostname as string) ?? null;
              source = 'ipinfo.io';
            }
          } catch { /* fallthrough */ }

          // Fallback: ipwho.is (free, no key, HTTPS)
          if (!source) {
            try {
              const r = await fetch(`https://ipwho.is/${ip}?fields=success,country_code,city,connection`, { signal: liveCtrl(4000) });
              if (r.ok) {
                const d = await r.json() as { success?: boolean; country_code?: string; city?: string; connection?: { org?: string; isp?: string } };
                if (d.success) {
                  org = String(d.connection?.org || d.connection?.isp || '') || null;
                  country = d.country_code ?? null;
                  city = d.city ?? null;
                  source = 'ipwho.is';
                }
              }
            } catch { /* fallthrough */ }
          }

          // Reverse DNS via Google DoH if still no hostname
          if (!rdns) {
            try {
              const reversed = ip.split('.').reverse().join('.');
              const r = await fetch(
                `https://dns.google/resolve?name=${reversed}.in-addr.arpa&type=PTR`,
                { headers: { Accept: 'application/json' }, signal: liveCtrl(3000) }
              );
              if (r.ok) {
                const d = await r.json() as { Answer?: Array<{ data: string }> };
                rdns = d.Answer?.[0]?.data?.replace(/\.$/, '') ?? null;
              }
            } catch { /* fallthrough */ }
          }

          return json({
            ip, source, org, country, city, rdns, proxy, hosting,
            vtLink: `https://www.virustotal.com/gui/ip-address/${ip}`,
            abuseLink: `https://www.abuseipdb.com/check/${ip}`,
            otxLink: `https://otx.alienvault.com/indicator/ip/${ip}`,
            shodanLink: `https://www.shodan.io/host/${ip}`,
          }, cors);
        }

        // Type-specific stats for sidebar navigator — single aggregate query, fast
        if (path === '/api/stats/by-type' && req.method === 'GET') {
          const srcParam = url.searchParams.get('source') ?? undefined;
          return json(await getStatsByType(sessionId, srcParam), cors);
        }

        if (path === '/api/iocs/ignore' && req.method === 'POST') {
          const { id, ignored } = await readJSON<{ id?: unknown; ignored?: unknown }>(req);
          await ignoreIOC(requireString(id, 'id', 128), ignored === true, sessionId);
          return json({ ok: true }, cors);
        }

        // Per-IOC analyst enrichment: found/not-found status, and a list of
        // ticket/host entries (one IOC can be found on several hosts, each
        // with its own ticket). Only the fields present in the body are updated.
        if (path === '/api/iocs/annotate' && req.method === 'POST') {
          const body = await readJSON<{
            id: string;
            huntStatus?: 'found' | 'not_found' | null;
            ticketEntries?: Array<{ ticket?: string; host?: string; environment?: string }> | null;
          }>(req);
          if (!body.id || typeof body.id !== 'string' || body.id.length > 128) return json({ error: 'id is required' }, cors, 400);
          if (Array.isArray(body.ticketEntries)) {
            const str = (s: unknown) => (typeof s === 'string' ? s.slice(0, 1000) : '');
            body.ticketEntries = body.ticketEntries.slice(0, 200).map(e => ({
              ticket: str(e?.ticket), host: str(e?.host), environment: str(e?.environment),
            }));
          }
          if ('huntStatus' in body && body.huntStatus !== null && body.huntStatus !== 'found' && body.huntStatus !== 'not_found') {
            return json({ error: 'huntStatus must be "found", "not_found", or null' }, cors, 400);
          }
          if ('ticketEntries' in body && body.ticketEntries !== null && !Array.isArray(body.ticketEntries)) {
            return json({ error: 'ticketEntries must be an array or null' }, cors, 400);
          }
          const fields: Record<string, unknown> = {};
          if ('huntStatus' in body) fields.huntStatus = body.huntStatus;
          if ('ticketEntries' in body) {
            fields.ticketEntries = body.ticketEntries
              ?.map(e => ({ ticket: (e.ticket ?? '').trim(), host: (e.host ?? '').trim(), environment: (e.environment ?? '').trim() }))
              .filter(e => e.ticket || e.host || e.environment) ?? null;
          }
          await annotateIOC(body.id, fields, sessionId);
          return json({ ok: true }, cors);
        }

        if (path === '/api/iocs/restore-all' && req.method === 'POST') {
          const n = await restoreAllIgnored(sessionId);
          return json({ ok: true, restored: n }, cors);
        }

        if (path === '/api/hunt' && req.method === 'POST') {
          const raw = await readJSON<{
            platform?: unknown;
            iocIds?: unknown;
            overrideTypes?: unknown;
            rawIOCs?: unknown;
            timeRange?: unknown;
          }>(req);
          const HUNT_PLATFORMS = ['all', 'splunk', 'elastic', 'kql', 'cql', 's1ql', 'wazuh', 'tql', 'sigma', 'yara'] as const;
          const platform = HUNT_PLATFORMS.find(p => p === raw.platform) ?? 'all';
          const timeRange = sanitizeTimeRange(raw.timeRange);
          const huntOptions = timeRange ? { timeRange } : undefined;
          const body = { iocIds: stringArray(raw.iocIds), overrideTypes: stringArray(raw.overrideTypes, 50), rawIOCs: parseRawIOCs(raw.rawIOCs) };

          let iocs: Awaited<ReturnType<typeof listIOCs>>;

          if (body.rawIOCs.length) {
            // Custom list mode — build minimal IOC objects directly, skip DB
            iocs = body.rawIOCs.map((r, i) => ({
              id: `raw-${i}`,
              value: r.value,
              type: r.type,
              classification: 'unknown' as const,
              source: 'manual' as const,
              extractedAt: new Date().toISOString(),
              tags: [],
            }));
          } else {
            iocs = await listIOCs({ classification: ['malicious', 'suspicious'], limit: 5000, sessionId });

            if (body.iocIds.length) {
              const idSet = new Set(body.iocIds);
              iocs = iocs.filter(i => idSet.has(i.id));
              if (iocs.length === 0) {
                const all = await listIOCs({ limit: 5000, sessionId });
                iocs = all.filter(i => idSet.has(i.id));
              }
            }

            if (body.overrideTypes.length) {
              const typeSet = new Set(body.overrideTypes);
              iocs = iocs.filter(i => typeSet.has(i.type));
            }
          }

          const queries = generateHuntQueries(iocs, platform, huntOptions);
          return json({ queries }, cors);
        }

        // Detection Engineering — generate detection rules from IOCs
        if (path === '/api/detect' && req.method === 'POST') {
          const raw = await readJSON<{ platform?: unknown; iocIds?: unknown; rawIOCs?: unknown }>(req);
          const DETECT_PLATFORMS = ['all', 'sigma', 'kql', 'splunk', 'elastic'] as const;
          const platform = DETECT_PLATFORMS.find(p => p === raw.platform) ?? 'all';
          const body = { iocIds: stringArray(raw.iocIds), rawIOCs: parseRawIOCs(raw.rawIOCs) };
          let iocs: Awaited<ReturnType<typeof listIOCs>>;
          if (body.rawIOCs.length) {
            iocs = body.rawIOCs.map((r, i) => ({
              id: 'raw-' + i, value: r.value, type: r.type,
              classification: 'unknown' as const, source: 'manual' as const,
              extractedAt: new Date().toISOString(), tags: [],
            }));
          } else {
            iocs = await listIOCs({ classification: ['malicious', 'suspicious'], limit: 5000, sessionId });
            if (body.iocIds.length) {
              const idSet = new Set(body.iocIds);
              iocs = iocs.filter(i => idSet.has(i.id));
              if (iocs.length === 0) { const all = await listIOCs({ limit: 5000, sessionId }); iocs = all.filter(i => idSet.has(i.id)); }
            }
          }
          const rules = generateDetectionRules(iocs, platform);
          return json({ rules }, cors);
        }

        if (path === '/api/report/executive' && req.method === 'GET') {
          const since = url.searchParams.get('since') ?? new Date(Date.now() - 7 * 86400000).toISOString();
          const iocs = await listIOCs({ since, sessionId });
          const report = generateExecutiveReport(iocs, since, new Date().toISOString());
          return json({ report }, cors);
        }

        if (path === '/api/report/analyst' && req.method === 'GET') {
          // Defaults to every IOC currently tracked in this session — a
          // wrap-up report should cover the whole hunt, not an arbitrary
          // recent window; pass ?since= to scope it narrower.
          const since = url.searchParams.get('since') ?? undefined;
          const iocs = await listIOCs({ since, limit: 5000, sessionId });
          const report = generateAnalystReport(iocs);
          const text = formatAnalystReportText(report);
          return json({ report, text }, cors);
        }

        // New session init — wipe all stored IOCs so each page load starts fresh.
        if (path === '/api/session/init' && req.method === 'POST') {
          await clearAllIOCs(sessionId);
          return json({ ok: true }, cors);
        }

        // Ticket Intelligence — multi-provider reputation analysis (no server-side cache)
        if (path === '/api/intel/analyze' && req.method === 'POST') {
          const body = await readJSON<{ ioc?: unknown; type?: unknown; vtKey?: unknown; abuseKey?: unknown }>(req);
          const { ioc, type } = body;
          if (typeof ioc !== 'string' || typeof type !== 'string' || !ioc || !type) return json({ error: 'ioc and type required' }, cors, 400);
          // SSRF guard: validate IOC value matches expected pattern for the type
          if (!isValidIOCValue(ioc, type)) return json({ error: 'Invalid IOC value for type' }, cors, 400);
          const userKey = (k: unknown) => (typeof k === 'string' && k && k.length <= 256 ? k : undefined);
          const opts: AnalyzeOptions = { vtKey: userKey(body.vtKey), abuseKey: userKey(body.abuseKey), useServerKeys: SHARE_SERVER_KEYS };
          const result = await analyzeIOC(ioc, type, opts);
          return json({ result, cached: false }, cors);
        }

        // === UI ===
        if (path === '/' || path === '/index.html') {
          const acceptGzip = req.headers.get('accept-encoding')?.includes('gzip');
          if (acceptGzip && _cachedHTMLGzip) {
            return new Response(_cachedHTMLGzip.buffer as ArrayBuffer, {
              headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding', 'Cache-Control': 'no-store', ...cors },
            });
          }
          return new Response(_cachedHTML, {
            headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', ...cors },
          });
        }

        
        const asset = STATIC_FILES.get(path);
        if (asset && (req.method === 'GET' || req.method === 'HEAD')) {
          try {
            return new Response(await readFile(join(publicDir(), ...asset.file)), {
              headers: { 'Content-Type': asset.type, 'Cache-Control': asset.cache, ...cors },
            });
          } catch { return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain', ...cors } }); }
        }

return json({ error: 'Not found' }, cors, 404);
  } catch (err) {
    if (err instanceof HttpError) return json({ error: err.message }, cors, err.status);
    console.error('[server error]', err instanceof Error ? err.message : err);
    const msg = err instanceof Error ? err.message : 'Internal server error';
    // Only expose message for validation errors (user-facing); mask internal details
    const safe = /protocol not allowed|invalid url|private.*ip|resolves to|dns resolution|invalid ip|file too large|too many redirects|remote content too large|unsupported file type/i.test(msg) ? msg : 'Internal server error';
    const status = safe === 'Internal server error' ? 500 : 400;
    return json({ error: safe }, cors, status);
  }
}

async function gzipBytes(data: string): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  await writer.write(new TextEncoder().encode(data));
  await writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function withGzip(req: Request, socketIP?: string): Promise<Response> {
  const res = await handleRequest(req, socketIP);
  const ct = res.headers.get('content-type') ?? '';
  if (!ct.includes('application/json')) return res;
  const acceptGzip = req.headers.get('accept-encoding')?.includes('gzip') ?? false;
  if (!acceptGzip) return res;
  const text = await res.text();
  if (text.length < 1024) return new Response(text, { status: res.status, headers: res.headers });
  const compressed = await gzipBytes(text);
  const headers = new Headers(res.headers);
  headers.set('Content-Encoding', 'gzip');
  headers.set('Vary', 'Accept-Encoding');
  return new Response(compressed.buffer as ArrayBuffer, { status: res.status, headers });
}

export function startServer(): void {
  Bun.serve({
    port: PORT,
    hostname: HOST,
    maxRequestBodySize: MAX_BODY_BYTES,
    fetch: (req, server) => withGzip(req, server.requestIP(req)?.address),
  });
  const shown = HOST === '0.0.0.0' || HOST === '::' ? 'localhost' : HOST;
  console.log(`IOC Tool running at http://${shown}:${PORT}${AUTH_TOKEN ? ' (auth enabled)' : ' (no auth — set IOC_API_TOKEN to require a token)'}`);
  if (!AUTH_TOKEN && !IS_LOOPBACK_ONLY) {
    console.warn('WARNING: listening on a non-loopback interface without IOC_API_TOKEN. Anyone who can reach this port can use the API.');
  }
}

function json(data: unknown, extraHeaders: Record<string, string> = {}, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    // API responses hold one visitor's data: never let a cache keep them.
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

function parseFilter(url: URL, sessionId: string): IOCFilter {
  const filter: IOCFilter = { sessionId };
  const type = url.searchParams.get('type');
  const cls = url.searchParams.get('classification');
  const since = url.searchParams.get('since');
  const search = url.searchParams.get('search');
  const limit = url.searchParams.get('limit');
  const offset = url.searchParams.get('offset');
  const sourceUrl = url.searchParams.get('sourceUrl');

  if (type) filter.type = type.split(',') as IOCFilter['type'];
  if (cls) filter.classification = cls.split(',') as IOCFilter['classification'];
  if (since) filter.since = since;
  if (search) filter.search = search;
  if (sourceUrl !== null) filter.sourceUrl = sourceUrl;
  if (url.searchParams.get('includeIgnored') === '1') filter.includeIgnored = true;
  const source = url.searchParams.get('source');
  if (source) filter.source = source.split(',') as IOCFilter['source'];
  filter.limit = limit ? Math.max(1, Math.min(Number(limit) || 100, 1000)) : 100;
  filter.offset = Math.max(0, Number(offset) || 0);

  return filter;
}

function getHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lazy Threat Hunt</title>
  <!-- This page ships its own dark/light themes — tell forced-dark-mode tools to leave it alone. -->
  <meta name="darkreader-lock">
  <meta name="color-scheme" content="dark light">
  <script>try{var t=localStorage.getItem('lth_theme');if(t)document.documentElement.setAttribute('data-theme',t);if(localStorage.getItem('lth_high_contrast')==='1')document.documentElement.classList.add('high-contrast');}catch(e){}</script>
  <style>
    /* Theme "1337" — the original, and default when no data-theme is set.
       color-scheme:dark here is inherited by ghost/crimson/neon below too
       (they don't redeclare it) — only "eww" overrides it to light.
       Back to the original full-saturation neon-on-near-black per explicit
       request, reverting the earlier eye-strain desaturation pass. The
       High Contrast toggle's :root.high-contrast overrides below are now
       redundant (same near-black values either way) but left in place —
       harmless no-op rather than ripping out a whole feature unasked. */
    :root {
      color-scheme: dark;
      --bg:#050505;--bg2:#0a0a0a;--bg3:#111111;--bg4:#020202;
      --border:#1a2a1a;--text:#d0d0d0;--text2:#606060;
      --accent:#00ff41;--accent2:#00cc33;
      --red:#f85149;--yellow:#e3b341;--green:#3fb950;--orange:#d29922;--purple:#bc8cff;
    }
    /* Theme "Ghost Protocol" — cyan/blue terminal. */
    :root[data-theme="ghost"] {
      --bg:#030a0d;--bg2:#071319;--bg3:#0d1f28;--bg4:#020608;
      --border:#123340;--text:#cfeef5;--text2:#5c8a99;
      --accent:#22e5ff;--accent2:#00b8d4;
      --red:#ff4d6d;--yellow:#ffcf4d;--green:#39e0a8;--orange:#ff9d4d;--purple:#7d7dff;
    }
    /* Theme "Crimson Shell" — aggressive red/black. */
    :root[data-theme="crimson"] {
      --bg:#0a0303;--bg2:#150606;--bg3:#210a0a;--bg4:#050101;
      --border:#4a1414;--text:#f0d0d0;--text2:#8a5c5c;
      --accent:#ff1f3d;--accent2:#cc1830;
      --red:#ff3355;--yellow:#ffb84d;--green:#5fd97a;--orange:#ff8a3d;--purple:#e066ff;
    }
    /* Theme "Neon Grid" — synthwave purple/magenta. */
    :root[data-theme="neon"] {
      --bg:#07030d;--bg2:#0f0618;--bg3:#1a0d28;--bg4:#040208;
      --border:#3a1a5a;--text:#e8d8ff;--text2:#8a6ca8;
      --accent:#ff2ee6;--accent2:#cc1fb8;
      --red:#ff4d6d;--yellow:#ffd24d;--green:#3dffb8;--orange:#ff8a4d;--purple:#b380ff;
    }
    /* Theme "Eww" — bright/light, for the anti-dark-mode crowd. Status colors
       are darkened from the neon defaults so they stay readable on a light bg. */
    :root[data-theme="eww"] {
      color-scheme: light;
      --bg:#f5f5f0;--bg2:#ffffff;--bg3:#eceae4;--bg4:#e4e1d8;
      --border:#c9c5b8;--text:#1a1a1a;--text2:#6b6b60;
      --accent:#0a8f3c;--accent2:#067a30;
      --red:#d32f2f;--yellow:#a37400;--green:#1f8a3d;--orange:#b56a00;--purple:#7b3fcc;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    /* Title font — self-hosted (public/fonts/, served at /fonts/..., see
       the route in server.ts) rather than pulled from Google Fonts' CDN,
       so it works same-origin under the existing CSP with zero relaxation
       and this tool makes no third-party request just to render its own
       header. Chakra Petch, OFL-licensed (public/fonts/ChakraPetch-OFL.txt). */
    @font-face{font-family:'Chakra Petch';src:url('/fonts/ChakraPetch-Bold.woff2') format('woff2');font-weight:700;font-style:normal;font-display:swap;}
    body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:13px;height:100vh;overflow:hidden;display:flex;flex-direction:column;}
    header{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 18px;display:flex;align-items:center;gap:14px;}
    header h1{font-family:'Chakra Petch','Segoe UI',system-ui,sans-serif;font-size:22px;color:var(--accent);font-weight:700;letter-spacing:1px;text-shadow:0 0 16px color-mix(in srgb, var(--accent) 45%, transparent);}
    header .subtitle{color:var(--text2);font-size:11px;}
    .stats-bar{display:flex;gap:10px;padding:8px 18px;background:var(--bg4);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center;}
    .stat{background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:5px 12px;text-align:center;min-width:75px;cursor:pointer;transition:border-color .15s;}
    .stat:hover{border-color:var(--accent);}
    .stat .n{font-size:19px;font-weight:700;color:var(--accent);}
    .stat .label{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;}
    .stat.red .n{color:var(--red);}
    .stat.yellow .n{color:var(--yellow);}
    .layout{display:grid;grid-template-columns:290px 1fr;flex:1 1 auto;min-height:0;overflow-x:hidden;}
    .sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;overflow-x:hidden;display:flex;flex-direction:column;min-width:0;}
    .main{overflow-y:auto;overflow-x:hidden;padding:14px;min-width:0;}
    .main-sticky-top{position:sticky;top:-14px;z-index:5;background:var(--bg);padding-top:14px;margin-bottom:11px;}

    /* IOC Navigator */
    .nav-section{border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s;}
    .nav-section:hover{background:var(--bg3);}
    .nav-section.active{background:#001a00;border-left:3px solid var(--accent);}
    .nav-section-header{display:flex;align-items:center;gap:8px;padding:9px 14px;}
    .nav-icon{font-size:15px;width:20px;text-align:center;}
    .nav-label{flex:1;font-size:13px;font-weight:600;}
    .nav-count{font-size:12px;color:var(--text2);}
    .nav-threat{display:flex;gap:5px;padding:0 14px 7px 42px;}
    .pill{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:700;cursor:pointer;}
    .pill.m{background:#3d1a1a;color:var(--red);border:1px solid #6e211e;}
    .pill.s{background:#2d2008;color:var(--yellow);border:1px solid #5a3e00;}
    .pill.ok{background:#0d2d0d;color:var(--green);border:1px solid #1e5e1e;}

    /* Ingest panel */
    .ingest-panel{border-top:2px solid var(--border);padding:12px;}
    .ingest-toggle{display:flex;align-items:center;justify-content:space-between;cursor:pointer;color:var(--text2);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;position:sticky;top:-12px;z-index:5;background:var(--bg2);padding-top:12px;}
    .ingest-toggle:hover{color:var(--text);}
    .ingest-body{display:flex;flex-direction:column;gap:10px;}
    .ingest-section{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px;}
    .ingest-section label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.4px;display:block;margin-bottom:6px;}

    /* Playbook */
    .playbook{padding:12px 14px;border-top:1px solid var(--border);}
    .playbook-title{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:8px;font-weight:700;}
    .playbook-step{display:flex;gap:8px;padding:4px 0;font-size:12px;color:var(--text2);}
    .playbook-step .num{color:var(--accent);font-weight:700;min-width:16px;}
    .playbook-step .txt{color:var(--text);}
    .playbook-step a{color:var(--accent);text-decoration:none;}
    .playbook-step a:hover{text-decoration:underline;}

    /* Main panels */
    .panel{background:var(--bg2);border:1px solid var(--border);border-radius:7px;overflow:hidden;}
    .panel-header{padding:9px 13px;background:var(--bg3);border-bottom:1px solid var(--border);font-weight:600;font-size:12px;display:flex;align-items:center;gap:8px;}
    .panel-body{padding:13px;}
    textarea,input[type=text],input[type=url],select{
      width:100%;background:var(--bg3);border:1px solid var(--border);color:var(--text);
      padding:7px 9px;border-radius:5px;font-size:12px;font-family:monospace;resize:vertical;
    }
    textarea:focus,input:focus,select:focus{outline:none;border-color:var(--accent);}
    button{
      background:var(--accent2);color:#fff;border:none;padding:6px 14px;
      border-radius:5px;cursor:pointer;font-size:12px;font-weight:600;transition:background .15s;
    }
    button:hover{background:var(--accent);}
    button.secondary{background:var(--bg3);border:1px solid var(--border);color:var(--text);}
    button.secondary:hover{border-color:var(--accent);color:var(--accent);}
    button.danger{background:#3d1a1a;color:var(--red);border:1px solid #6e211e;}
    button.danger:hover{background:var(--red);color:#fff;}
    button:disabled{opacity:.4;cursor:not-allowed;}
    .badge{display:inline-block;padding:1px 7px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.3px;}
    .badge.malicious{background:#3d1a1a;color:var(--red);border:1px solid #6e211e;}
    .badge.suspicious{background:#2d2008;color:var(--yellow);border:1px solid #5a3e00;}
    .badge.unknown{background:var(--bg3);color:var(--text2);border:1px solid var(--border);}
    .badge.internal{background:#001a00;color:var(--accent);border:1px solid #1a4a1a;}
    .badge.external{background:#0d2d0d;color:var(--green);border:1px solid #1e5e1e;}
    .badge.type{background:var(--bg3);color:var(--purple);border:1px solid #3d2a5a;font-size:9px;}
    table{width:100%;border-collapse:collapse;}
    th{text-align:left;padding:7px 11px;font-size:10px;text-transform:uppercase;color:var(--text2);border-bottom:1px solid var(--border);background:var(--bg3);}
    td{padding:6px 11px;border-bottom:1px solid var(--border);font-size:12px;}
    tr:hover td{background:var(--bg3);}
    .val{font-family:monospace;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .tabs{display:flex;gap:3px;margin-bottom:11px;border-bottom:2px solid var(--accent);}
    .tab{padding:5px 13px 7px;border-radius:6px 6px 0 0;cursor:pointer;font-size:12px;border-bottom:3px solid transparent;margin-bottom:-2px;transition:color .15s,border-color .15s;position:relative;}
    .tab:not(:last-child){border-right:2px solid var(--accent);}
    .tab.active{background:var(--bg2);color:var(--accent);font-weight:700;border-bottom-color:var(--accent);text-shadow:0 0 8px color-mix(in srgb, var(--accent) 70%, transparent);}
    .tab:not(.active){color:var(--text2);}
    .tab:not(.active):hover{color:var(--text);}
    /* Same glitch-text hover effect as the Environments checkboxes (see
       .glitch-checkbox-container / glitch-anim-text above) — just the text
       jitter, no checkbox mark; data-text is filled in by JS from each
       tab's own label so it works for any tab without hardcoding strings. */
    .tab:hover::before, .tab:hover::after {
      content: attr(data-text); position: absolute; inset: 0;
      padding: 5px 13px 7px; box-sizing: border-box; border-radius: inherit;
      background-color: var(--bg2);
    }
    .tab:hover::before { color: var(--purple); animation: glitch-anim-text .3s cubic-bezier(.25,.46,.45,.94) both; }
    .tab:hover::after { color: var(--accent); animation: glitch-anim-text .3s cubic-bezier(.25,.46,.45,.94) reverse both; }
    .filter-row{display:flex;gap:7px;align-items:center;margin-bottom:10px;flex-wrap:wrap;}
    .filter-row select{width:auto;}
    pre{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:10px;overflow:auto;font-size:11px;max-height:360px;}
    .alert{padding:8px 12px;border-radius:5px;margin-bottom:9px;font-size:12px;}
    .alert.success{background:#0d2d0d;border:1px solid #1e5e1e;color:var(--green);}
    .alert.error{background:#3d1a1a;border:1px solid #6e211e;color:var(--red);}
    .alert.info{background:#001a00;border:1px solid #1a4a1a;color:var(--accent);}
    .hypothesis-warning-banner{background:#2d2008;border-bottom:1px solid #5a3e00;color:var(--yellow);padding:7px 18px;font-size:11px;font-weight:600;text-align:center;}
    /* Glitch, adapted from https://uiverse.io/andrew-demchenk0/silent-earwig-10
       — the original runs its chromatic-aberration jitter continuously
       (infinite) plus a heavier skewX/skewY distortion on top. Kept only
       the color-offset jitter (legible, brief) and dropped the skew (would
       make an actual warning message hard to read mid-glitch); the
       ".glitching" class is added/removed briefly by JS at long random
       intervals instead of running infinite, so it reads as an occasional
       flicker, not a constant distraction. */
    .hw-text{position:relative;display:inline-block;}
    .hypothesis-warning-banner.glitching .hw-text::before,
    .hypothesis-warning-banner.glitching .hw-text::after{content:attr(data-text);position:absolute;top:0;left:0;width:100%;opacity:.85;}
    .hypothesis-warning-banner.glitching .hw-text::before{color:var(--purple);animation:hw-glitch .4s cubic-bezier(.25,.46,.45,.94) both;}
    .hypothesis-warning-banner.glitching .hw-text::after{color:var(--accent);animation:hw-glitch .4s cubic-bezier(.25,.46,.45,.94) reverse both;}
    @keyframes hw-glitch{
      0%{transform:translate(0);}
      20%{transform:translate(-3px,3px);}
      40%{transform:translate(-3px,-3px);}
      60%{transform:translate(3px,3px);}
      80%{transform:translate(3px,-3px);}
      100%{transform:translate(0);}
    }
    .loading{color:var(--text2);font-style:italic;padding:18px;text-align:center;}
    /* Feed sections */
    .feed-section{border-bottom:1px solid var(--border);}
    .feed-section-hdr{display:flex;align-items:center;gap:7px;padding:5px 12px;cursor:pointer;font-size:11px;}
    .feed-section-hdr:hover{background:var(--bg3);}
    .feed-section-hdr.disabled{opacity:.45;}
    .feed-type-pill{display:inline-flex;align-items:center;gap:3px;padding:2px 6px;border-radius:8px;font-size:10px;font-weight:600;background:var(--bg3);border:1px solid var(--border);color:var(--text2);margin:2px;}
    .feed-ioc-body{padding:5px 14px 8px 28px;display:flex;flex-wrap:wrap;gap:3px;}
    .qblock{margin-bottom:11px;}
    .qplat{font-size:10px;font-weight:700;color:var(--purple);text-transform:uppercase;margin-bottom:3px;display:flex;align-items:center;gap:6px;}
    .qdesc{font-size:11px;color:var(--text2);margin-bottom:4px;}
    .exec-section{background:var(--bg3);border:1px solid var(--border);border-radius:5px;padding:12px;margin-bottom:11px;}
    .exec-section h3{font-size:12px;color:var(--accent);margin-bottom:7px;}
    .sev-critical{color:var(--red);font-weight:700;}
    .sev-high{color:var(--orange);font-weight:700;}
    .sev-medium{color:var(--yellow);}
    .sev-low{color:var(--green);}
    ul.recs li{padding:3px 0;color:var(--text);font-size:12px;}
    ul.recs li::before{content:"→ ";color:var(--accent);}
    .geo-tag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:1px 5px;font-size:10px;margin:2px;}

    /* Enrichment card */
    .enrich-card{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-top:6px;}
    .enrich-row{display:flex;align-items:center;gap:8px;padding:3px 0;font-size:12px;}
    .enrich-label{color:var(--text2);min-width:90px;font-size:11px;}
    .enrich-value{color:var(--text);font-family:monospace;}
    .link-btn{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:600;text-decoration:none;border:1px solid;cursor:pointer;}
    .link-btn.vt{color:#3b82f6;border-color:#1e4a6e;background:#0d2535;}
    .link-btn.vt:hover{background:#1e4a6e;}
    .link-btn.abuse{color:#f59e0b;border-color:#5a3e00;background:#2d2008;}
    .link-btn.abuse:hover{background:#5a3e00;}
    .link-btn.hybrid{color:#a78bfa;border-color:#3d2a5a;background:#1a1028;}
    .link-btn.hybrid:hover{background:#3d2a5a;}
    .link-btn.otx{color:#34d399;border-color:#1e5e3e;background:#0d2d1e;}
    .link-btn.otx:hover{background:#1e5e3e;}
    .abuse-inline{font-size:11px;color:var(--text2);}
    .abuse-conf-high{color:var(--red);font-weight:700;}
    .abuse-conf-med{color:var(--yellow);font-weight:700;}
    .abuse-conf-low{color:var(--green);font-weight:700;}
    .hunt-type-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:10px;}
    .ioc-block{display:inline-flex;align-items:center;gap:5px;padding:3px 8px 3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;font-size:11px;font-family:monospace;}
    .ioc-block .ioc-type{color:var(--purple);font-size:9px;font-weight:700;text-transform:uppercase;background:var(--bg3);padding:1px 4px;border-radius:8px;}
    .ioc-block .ioc-val{color:var(--text);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .ioc-block .ioc-rm{color:var(--text2);cursor:pointer;font-size:13px;line-height:1;margin-left:2px;}
    .ioc-block .ioc-rm:hover{color:var(--red);}
    .feed-chip{display:inline-flex;align-items:center;gap:7px;background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-size:11px;}
    .feed-chip .feed-url{color:var(--accent);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .feed-chip .feed-count{color:var(--text2);}

    .mode-bar{display:flex;gap:6px;padding:7px 18px;background:var(--bg4);border-bottom:1px solid var(--border);align-items:center;}
    .mode-bar .mb-label{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:.4px;margin-right:4px;}
    /* High Contrast toggle — what the original threat-hunter feedback was
       actually asking for: a genuinely true-black option, clearly distinct
       from the 4 regular themes (which are all variations on the same
       neon-on-near-black look — "not drastic" from each other). Fixed,
       pure-black values, the SAME across every theme on purpose — this is
       meant to be the one deliberately different option, not a themed
       variant. Does NOT reuse/match the base theme's own --bg/--bg2/--bg3/
       --bg4 values (that was the repeated no-op bug: whenever the base
       theme's values changed, this stopped doing anything because it was
       copying them). No rule for "eww" (the light theme) — not relevant
       there. */
    :root.high-contrast,
    :root[data-theme="ghost"].high-contrast,
    :root[data-theme="crimson"].high-contrast,
    :root[data-theme="neon"].high-contrast {
      --bg:#000000; --bg2:#030303; --bg3:#080808; --bg4:#000000;
    }

    /* Shared mode-bar / High Contrast button style. Solid-fill-on-hover
       background came from https://uiverse.io/pharmacist-sabot/funny-gecko-48,
       but its text transition (fade the real label to 0 opacity, then a
       dramatic clip-path glitch swap) read as too much — toned down to
       reuse the same subtle glitch-anim-text jitter the tabs use (see
       .tab:hover::before/::after below): the real label stays visible, a
       brief colored double-vision wobble plays over it, the button still
       goes solid/bright. Used by every button in the mode-bar (mode
       toggles, load-data actions, High Contrast) for a consistent look.
       data-text is filled in by the same JS that already fills it for
       tabs, from each button's own label. ".active" is this app's own
       addition — a toggled-on button (the current mode, or High Contrast
       when on) stays filled permanently; action buttons (Load
       Hypothesis/IOC Data) never get .active, so they only react on
       hover/focus. */
    .hc-toggle {
      --hc-primary: var(--accent); --hc-secondary: var(--purple); --hc-bg: var(--bg);
      box-sizing: border-box; display: inline-flex; align-items: center; justify-content: center;
      padding: 4px 11px; background: transparent; border: 1px solid var(--border); border-radius: 5px;
      color: var(--text2); font: 700 11px 'Segoe UI', system-ui, monospace;
      text-transform: uppercase; letter-spacing: .05em;
      cursor: pointer; transition: all .15s; overflow: hidden; position: relative;
    }
    .hc-toggle:hover, .hc-toggle:focus, .hc-toggle.active {
      background: var(--hc-primary); color: var(--hc-bg); outline: none;
    }
    .hc-toggle span { position: relative; z-index: 1; }
    .hc-toggle:hover::before, .hc-toggle:hover::after,
    .hc-toggle:focus::before, .hc-toggle:focus::after,
    .hc-toggle.active::before, .hc-toggle.active::after {
      content: attr(data-text); position: absolute; inset: 0;
      display: flex; align-items: center; justify-content: center;
      background-color: var(--hc-primary);
    }
    .hc-toggle:hover::before, .hc-toggle:focus::before, .hc-toggle.active::before {
      color: var(--hc-secondary); animation: glitch-anim-text .3s cubic-bezier(.25,.46,.45,.94) both;
    }
    .hc-toggle:hover::after, .hc-toggle:focus::after, .hc-toggle.active::after {
      color: var(--hc-bg); animation: glitch-anim-text .3s cubic-bezier(.25,.46,.45,.94) reverse both;
    }
    .hc-toggle:active { transform: scale(.97); }
    .hc-toggle:disabled { cursor: not-allowed; opacity: .4; }
    @media (prefers-reduced-motion: reduce) {
      .hc-toggle:hover::before, .hc-toggle:hover::after,
      .hc-toggle:focus::before, .hc-toggle:focus::after,
      .hc-toggle.active::before, .hc-toggle.active::after { animation: none; content: none; }
    }
    /* Momentary class applied by syncHCButton() during an explicit
       click-off, so the button snaps straight to idle instead of fading
       through the .15s background/color transition and .3s glitch
       animation at different rates (which looked like mismatched colors
       mid-fade). Inline styles on the button itself can't reach its
       ::before/::after pseudo-elements, hence a real CSS class here. */
    .hc-toggle.hc-instant, .hc-toggle.hc-instant::before, .hc-toggle.hc-instant::after {
      transition: none !important; animation: none !important; content: none !important;
    }

    /* Environment checkboxes — "glitch" style, adapted from
       https://uiverse.io/pharmacist-sabot/great-falcon-83. Colors mapped
       to this app's theme vars instead of the original's fixed
       cyan/purple, so it matches whichever theme is active. The standalone
       card wrapper (dark bg/padding) from the original is dropped — these
       checkboxes live inline in the existing Environments bar. */
    .glitch-checkbox-container {
      --primary-color: var(--accent); --secondary-color: var(--purple);
      --text-color: var(--text2); --disabled-color: var(--text2);
      --glitch-anim-duration: .3s;
      display: flex; align-items: center; gap: 6px; cursor: pointer;
      user-select: none; position: relative; font-size: 11px;
    }
    .glitch-checkbox-container input[type="checkbox"] { position: absolute; opacity: 0; width: 0; height: 0; }
    .checkbox-box {
      width: 1.3em; height: 1.3em; border: 2px solid var(--primary-color);
      position: relative; transition: all .3s ease; flex-shrink: 0;
      clip-path: polygon(15% 0,85% 0,100% 15%,100% 85%,85% 100%,15% 100%,0 85%,0 15%);
    }
    .checkbox-mark {
      position: absolute; top: 50%; left: 50%; width: 60%; height: 60%;
      background-color: var(--primary-color); transform: translate(-50%, -50%) scale(0);
      opacity: 0; transition: all .3s cubic-bezier(.18,.89,.32,1.28); clip-path: inherit;
    }
    .checkbox-label {
      color: var(--text-color); font-weight: 600; text-transform: uppercase;
      letter-spacing: .05em; position: relative;
      transition: color .3s ease, text-shadow .3s ease;
    }
    .glitch-checkbox-container input:checked + .checkbox-box .checkbox-mark {
      transform: translate(-50%, -50%) scale(1); opacity: 1;
      animation: glitch-anim-checkbox var(--glitch-anim-duration) both;
    }
    .glitch-checkbox-container input:checked ~ .checkbox-label {
      color: var(--primary-color); text-shadow: 0 0 8px color-mix(in srgb, var(--primary-color) 70%, transparent);
    }
    .glitch-checkbox-container:hover .checkbox-box { box-shadow: 0 0 10px var(--primary-color); }
    .glitch-checkbox-container:hover .checkbox-label::before,
    .glitch-checkbox-container:hover .checkbox-label::after {
      content: attr(data-text); position: absolute; top: 0; left: 0; width: 100%; height: 100%;
      background-color: var(--bg3);
    }
    .glitch-checkbox-container:hover .checkbox-label::before {
      color: var(--secondary-color);
      animation: glitch-anim-text var(--glitch-anim-duration) cubic-bezier(.25,.46,.45,.94) both;
    }
    .glitch-checkbox-container:hover .checkbox-label::after {
      color: var(--primary-color);
      animation: glitch-anim-text var(--glitch-anim-duration) cubic-bezier(.25,.46,.45,.94) reverse both;
    }
    .glitch-checkbox-container:has(input:disabled) { cursor: not-allowed; }
    .glitch-checkbox-container input:disabled + .checkbox-box { border-color: var(--disabled-color); opacity: .5; box-shadow: none; }
    .glitch-checkbox-container input:disabled ~ .checkbox-label { color: var(--disabled-color); text-shadow: none; }
    .glitch-checkbox-container:has(input:disabled):hover .checkbox-box { box-shadow: none; }
    .glitch-checkbox-container:has(input:disabled):hover .checkbox-label::before,
    .glitch-checkbox-container:has(input:disabled):hover .checkbox-label::after { content: none; }
    @keyframes glitch-anim-checkbox {
      0% { transform: translate(-50%, -50%); clip-path: inset(0 0 0 0); }
      20% { transform: translate(calc(-50% - 3px), calc(-50% + 2px)); clip-path: inset(50% 0 20% 0); }
      40% { transform: translate(calc(-50% + 2px), calc(-50% - 1px)); clip-path: inset(20% 0 60% 0); }
      60% { transform: translate(calc(-50% - 2px), calc(-50% + 1px)); clip-path: inset(80% 0 5% 0); }
      80% { transform: translate(calc(-50% + 2px), calc(-50% - 2px)); clip-path: inset(30% 0 45% 0); }
      100% { transform: translate(-50%, -50%); clip-path: inset(0 0 0 0); }
    }
    @keyframes glitch-anim-text {
      0% { transform: translate(0); clip-path: inset(0 0 0 0); }
      20% { transform: translate(-3px, 2px); clip-path: inset(50% 0 20% 0); }
      40% { transform: translate(2px, -1px); clip-path: inset(20% 0 60% 0); }
      60% { transform: translate(-2px, 1px); clip-path: inset(80% 0 5% 0); }
      80% { transform: translate(2px, -2px); clip-path: inset(30% 0 45% 0); }
      100% { transform: translate(0); clip-path: inset(0 0 0 0); }
    }
  </style>
</head>
<body>
<div id="appRoot" style="display:contents">
<div class="mode-bar">
  <span class="mb-label">Mode</span>
  <span class="hc-toggle" id="modeBarHyp" onclick="selectMode('hypothesis')"><span>Hypothesis Hunt</span></span>
  <span class="hc-toggle" id="modeBarIoc" onclick="selectMode('ioc')"><span>IOC Hunt</span></span>
  <span class="hc-toggle" id="modeBarFrameworks" onclick="selectMode('frameworks')"><span>Frameworks</span></span>
  <div style="margin-left:auto;display:flex;gap:6px;">
    <span class="hc-toggle" onclick="loadDemoData('hypothesis')"><span>Load Hypothesis Hunt Data</span></span>
    <span class="hc-toggle" onclick="loadDemoData('iocs')"><span>Load IOC Demo Data</span></span>
    <span class="hc-toggle" style="--hc-primary:var(--red);" onclick="removeSampleData(this)"><span>Remove Sample Data</span></span>
  </div>
</div>
<div id="hypothesisWarning" class="hypothesis-warning-banner" style="display:none;">⚠ <span class="hw-text">Hypothesis mode is currently under dev — I am learning and need more white board to dive deeper into this — hAckDHD</span></div>
  <header>
    <div>
      <h1>Lazy Threat Hunt</h1>
      <div class="subtitle">Extraction · Classification · Enrichment · Hunt · Report</div>
    </div>
  <div style="margin-left:auto;display:flex;gap:7px;align-items:center;">
    <span id="ingestAlert" style="font-size:11px;"></span>
    <span style="font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.4px;">Theme</span>
    <select id="themePicker" onchange="setTheme(this.value)" style="width:auto;font-size:11px;padding:4px 8px;">
      <option value="1337">1337</option>
      <option value="ghost">Ghost Protocol</option>
      <option value="crimson">Crimson Shell</option>
      <option value="neon">Neon Grid</option>
      <option value="eww">Eww</option>
    </select>
    <button class="hc-toggle" id="hcToggle" onclick="toggleHighContrast()" title="Put a true-black background back (no effect on Eww)"><span>High Contrast</span></button>
    <button class="hc-toggle" onclick="refresh()"><span>⟳ Refresh</span></button>
  </div>
</header>

<div class="stats-bar" id="statsBar">
  <div class="loading" style="padding:4px">Loading...</div>
</div>
<div id="feedsPanel" style="background:var(--bg4);border-bottom:1px solid var(--border);">
  <div style="padding:5px 14px;display:flex;align-items:center;gap:8px;font-size:11px;">
    <span style="color:var(--text2);cursor:pointer;user-select:none;" onclick="toggleFeedsPanel()">📡 <strong style="color:var(--text);">Feeds</strong> <span id="feedsTotalBadge" style="color:var(--text2);"></span> <span id="feedsPanelChev" style="font-size:9px;color:var(--text2);">▼</span></span>
    <span style="margin-left:auto;display:flex;gap:5px;align-items:center;">
      <span id="feedAddToggle" style="color:var(--accent);cursor:pointer;padding:2px 8px;border:1px solid var(--border);border-radius:4px;font-size:10px;" onclick="toggleAddFeed();event.stopPropagation()">+ Add Feed</span>
    </span>
  </div>
  <div id="feedAddForm" style="display:none;padding:5px 14px 8px;gap:5px;align-items:center;">
    <input type="url" id="feedAddUrl" placeholder="https://raw.githubusercontent.com/…/ips.txt" style="width:340px;padding:3px 7px;font-size:11px;background:var(--bg2);border:1px solid var(--border);color:var(--text);border-radius:4px;" onkeydown="if(event.key==='Enter')addFeed()">
    <button class="hc-toggle" onclick="addFeed()" style="font-size:10px;padding:2px 10px;"><span>Import</span></button>
    <button class="hc-toggle" onclick="toggleAddFeed()" style="font-size:10px;padding:2px 7px;"><span>Cancel</span></button>
    <span id="feedAddStatus" style="font-size:11px;color:var(--text2);"></span>
  </div>
  <div id="feedsBody" style="max-height:160px;overflow-y:auto;"></div>
</div>

<div class="layout">

<!-- ═══ SIDEBAR ═══ -->
<div class="sidebar">

  <!-- Custom Hunt / Ingest Panel — TOP -->
  <div class="ingest-panel" style="border-bottom:2px solid var(--border);border-top:none;">
    <div class="ingest-toggle" onclick="toggleIngest()">
      <span>⚡ CUSTOM HUNT</span>
      <span id="ingestChevron">▼</span>
    </div>
    <div class="ingest-body" id="ingestBody" style="display:none;">
      <label style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text2);cursor:pointer;padding:2px 4px 6px;">
        <input type="checkbox" id="autoAddHunt" style="accent-color:var(--accent);">
        Auto-add to Hunt Builder
      </label>
      <div class="ingest-section">
        <label>Paste Text / IOCs</label>
        <textarea id="pasteInput" rows="4" placeholder="Paste IPs, hashes, domains, report text..."></textarea>
        <button class="hc-toggle" onclick="ingestText()" style="margin-top:6px;width:100%"><span>Add IOCs</span></button>
      </div>
      <div class="ingest-section">
        <label>Scrape URLs (one per line)</label>
        <textarea id="urlInput" rows="3" placeholder="https://threat-report.example.com/apt29&#10;https://raw.githubusercontent.com/..."></textarea>
        <button class="hc-toggle" onclick="ingestURL()" style="margin-top:6px;width:100%"><span>Scrape & Extract</span></button>
      </div>
      <div class="ingest-section">
        <label>Upload File (.txt .csv .json .pdf .docx)</label>
        <input type="file" id="fileInput" accept=".txt,.csv,.json,.pdf,.docx,.md,.log" style="color:var(--text2);font-size:11px;">
        <button class="hc-toggle" onclick="ingestFile()" style="margin-top:6px;width:100%"><span>Parse & Extract</span></button>
      </div>

      <!-- Current Hunt (sidebar mirror) -->
      <div class="ingest-section" style="padding-bottom:6px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;">
          <label style="margin:0;">Current Hunt</label>
          <button class="hc-toggle" style="font-size:10px;padding:1px 7px;" onclick="huntClearBlocks()"><span>Clear</span></button>
        </div>
        <div id="huntBlocksSidebar" style="min-height:28px;padding:6px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;font-size:11px;">
          <span style="color:var(--text2);">No IOCs added yet</span>
        </div>
        <div id="huntBlocksSidebarCount" style="font-size:10px;color:var(--text2);margin-top:3px;"></div>
      </div>
    </div>
  </div>

  <!-- IOC Navigator — 3 tabs -->
  <div style="display:flex;border-bottom:1px solid var(--border);">
    <button id="navBtnHunt" onclick="setNavMode('hunt')" style="flex:1;border-radius:0;background:var(--bg2);border:none;color:var(--text2);font-size:11px;padding:6px 0;cursor:pointer;">Hunt</button>
    <button id="navBtnType" onclick="setNavMode('type')" style="flex:1;border-radius:0;background:var(--accent);border:none;border-left:1px solid var(--border);border-right:1px solid var(--border);color:var(--bg);font-size:11px;padding:6px 0;cursor:pointer;font-weight:700;">By Type</button>
    <button id="navBtnSource" onclick="setNavMode('source')" style="flex:1;border-radius:0;background:var(--bg2);border:none;color:var(--text2);font-size:11px;padding:6px 0;cursor:pointer;">By Source</button>
  </div>
  <!-- By Type sub-pills -->
  <div id="typeNavSubPills" style="display:flex;gap:4px;padding:5px 8px;border-bottom:1px solid var(--border);">
    <button id="typePillAll"  class="hc-toggle" style="font-size:10px;padding:2px 9px;background:var(--accent);color:var(--bg);border-color:var(--accent);" onclick="setTypeSubFilter('all')"><span>All</span></button>
    <button id="typePillFeed" class="hc-toggle" style="font-size:10px;padding:2px 9px;" onclick="setTypeSubFilter('feed')"><span>Feed</span></button>
    <button id="typePillHunt" class="hc-toggle" style="font-size:10px;padding:2px 9px;" onclick="setTypeSubFilter('hunt')"><span>Hunt</span></button>
  </div>
  <div id="iocNavHunt" style="display:none;"></div>
  <div id="iocNavType"></div>
  <div id="iocNavSource" style="display:none;"></div>

  <!-- Jr Analyst Playbook -->
  <div class="playbook" id="playbook" style="display:none;">
    <div class="playbook-title" id="playbookTitle">Playbook</div>
    <div id="playbookSteps"></div>
  </div>

</div>

<!-- ═══ MAIN ═══ -->
<div class="main">
  <!-- Pinned while tab content below scrolls -->
  <div class="main-sticky-top">
  <!-- Global Environment Selector -->
  <div id="globalEnvBar" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:7px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;margin-bottom:9px;">
    <span style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;white-space:nowrap;">Environments</span>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-splunk" onchange="toggleHuntEnv('splunk',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="SPLUNK SPL">SPLUNK SPL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-kql" onchange="toggleHuntEnv('kql',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="SENTINEL/DEFENDER KQL">SENTINEL/DEFENDER KQL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-cql" onchange="toggleHuntEnv('cql',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="CROWDSTRIKE CQL">CROWDSTRIKE CQL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-s1ql" onchange="toggleHuntEnv('s1ql',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="SENTINELONE S1QL">SENTINELONE S1QL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-wazuh" onchange="toggleHuntEnv('wazuh',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="WAZUH WQL">WAZUH WQL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-elastic" onchange="toggleHuntEnv('elastic',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="ELASTIC DSL">ELASTIC DSL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-tql" onchange="toggleHuntEnv('tql',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="TRELLIX TQL">TRELLIX TQL</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-sigma" onchange="toggleHuntEnv('sigma',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="SIGMA">SIGMA</span></label>
    <label class="glitch-checkbox-container"><input type="checkbox" id="genv-yara" onchange="toggleHuntEnv('yara',this.checked)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="YARA">YARA</span></label>
  </div>
  <div class="tabs">
    <div class="tab" id="tabBtnHypothesis" style="display:none;" onclick="showTab('hypothesis')">Hypothesis Builder</div>
    <div class="tab" id="tabBtnTtp" style="display:none;" onclick="showTab('ttp')">TTP Library</div>
    <div class="tab active" onclick="showTab('hunt')">Hunt Builder</div>
    <div class="tab" onclick="showTab('iocs')">IOC List</div>
    <div class="tab" onclick="showTab('enrichment')">Enrichment</div>
    <div class="tab" id="tabBtnCheatsheet" onclick="showTab('cheatsheet')">Cheat Sheet</div>
    <div class="tab" id="tabBtnDetect" onclick="showTab('detect')">Detection Engineering</div>
    <div class="tab" onclick="showTab('analyst')">Analyst View</div>
    <div class="tab" id="tabBtnDescription" onclick="showTab('description')">IOC Description</div>
    <div class="tab" id="tabBtnHypreport" style="display:none;" onclick="showTab('hypreport')">Hypothesis Hunt Report</div>
    <div class="tab" id="tabBtnFrameworks" style="display:none;" onclick="showTab('frameworks')">Hunt Frameworks</div>
  </div>
  </div>

  <!-- ── Hypothesis Builder ── -->
  <div id="tab-hypothesis" style="display:none;">
    <div class="panel" style="margin-bottom:12px;">
      <div class="panel-header">🎯 Hypothesis Builder — The 5 W's</div>
      <div class="panel-body" style="display:flex;flex-direction:column;gap:10px;">
        <div class="ingest-section">
          <label>What — what are you looking for?</label>
          <textarea id="hypWhat" rows="2" placeholder="e.g. Evidence of lateral movement using living-off-the-land binaries (LOLBins)"></textarea>
        </div>
        <div class="ingest-section">
          <label>Why — how did you get to this suspicion?</label>
          <textarea id="hypWhy" rows="2" placeholder="e.g. Threat intel report, anomalous alert, past incident pattern..."></textarea>
        </div>
        <div class="ingest-section">
          <label>Who — target individual or threat actor group</label>
          <input type="text" id="hypWho" placeholder="e.g. APT29, insider in finance dept, unknown external actor">
        </div>
        <div class="ingest-section">
          <label>Suspected Threat Actor (optional)</label>
          <select id="hypActor"><option value="">— none / unknown —</option></select>
        </div>
        <div class="ingest-section">
          <label>When — behaviors and baselines</label>
          <textarea id="hypWhen" rows="2" placeholder="e.g. Outside normal business hours; deviation from baseline process execution..."></textarea>
        </div>
        <div class="ingest-section">
          <label>Where — data source(s) — is it logged?</label>
          <textarea id="hypWhere" rows="2" placeholder="e.g. EDR process logs, Windows Security Event Log 4688 — confirmed logged"></textarea>
        </div>
        <div class="ingest-section">
          <label>Testable / Measurable — pass/fail criteria</label>
          <textarea id="hypTestable" rows="2" placeholder="e.g. Query process creation logs for parent/child pairs matching X over last 30 days"></textarea>
        </div>
        <button class="hc-toggle" onclick="saveHypothesis()"><span>Save Hypothesis</span></button>
      </div>
    </div>

    <!-- Shareable plain-text summary of the draft above, for getting feedback before saving -->
    <div class="panel" style="margin-bottom:12px;">
      <div class="panel-header">
        <span>Share Draft</span>
        <span style="font-size:10px;color:var(--text2);font-weight:400;">plain-text summary of the form above, ready to paste into a message for feedback</span>
        <button class="hc-toggle" style="margin-left:auto;font-size:11px;padding:3px 10px;" onclick="generateHypothesisShareText()"><span>Generate Summary</span></button>
        <button class="hc-toggle" id="hypShareCopyBtn" style="font-size:11px;padding:3px 10px;display:none;" onclick="copyHypothesisShare(this)"><span>Copy</span></button>
      </div>
      <div class="panel-body" id="hypShareBody" style="display:none;">
        <pre id="hypShareText" style="max-height:300px;"></pre>
      </div>
    </div>

    <div id="hypothesesList"></div>
  </div>

  <!-- ── Hypothesis Hunt Report ── -->
  <div id="tab-hypreport" style="display:none;">
    <div class="panel" style="margin-bottom:12px;">
      <div class="panel-header">
        <span>Hypothesis Hunt Report</span>
        <span style="font-size:10px;color:var(--text2);font-weight:400;">every saved hypothesis, with linked/suggested TTPs — full report ready to copy</span>
        <button class="hc-toggle" style="margin-left:auto;font-size:11px;padding:3px 10px;" onclick="copyFullHypothesisReport(this)"><span>Copy Full Report</span></button>
      </div>
    </div>
    <div id="hypReportList"></div>
  </div>

  <!-- ── TTP / Behavioral Hunt Template Library ── -->
  <div id="tab-ttp" style="display:none;">
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:14px;flex-wrap:wrap;">
      <span style="font-size:11px;color:var(--text2);text-transform:uppercase;font-weight:700;">Platform Filter</span>
      <div id="ttpPlatformFilterGroup" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="splunk" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Splunk SPL">Splunk SPL</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="kql" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Sentinel/Defender KQL">Sentinel/Defender KQL</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="cql" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="CrowdStrike CQL">CrowdStrike CQL</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="s1ql" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="SentinelOne S1QL">SentinelOne S1QL</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="wazuh" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Wazuh">Wazuh</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="elastic" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Elastic DSL">Elastic DSL</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="tql" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Trellix">Trellix</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="sigma" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="Sigma">Sigma</span></label>
        <label class="glitch-checkbox-container" style="font-size:10px;"><input type="checkbox" value="yara" checked onchange="renderTTPLibrary()"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="YARA">YARA</span></label>
      </div>
      <span style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;margin-left:8px;">Actor</span>
      <select id="ttpActorFilter" onchange="renderTTPLibrary()" style="width:auto;font-size:11px;padding:3px 8px;"><option value="">All actors</option></select>
      <span style="margin-left:auto;"><input type="text" id="ttpSearch" placeholder="Search techniques..." style="width:200px;font-size:11px;" oninput="filterTTPLibrary()"></span>
    </div>
    <div id="ttpResults"></div>
  </div>

  <!-- ── IOC List ── -->
  <div id="tab-iocs" style="display:none;">
    <div class="filter-row">
      <input type="text" id="searchInput" placeholder="Search…" style="width:170px;" oninput="currentPage=0;loadIOCs()">
      <select id="typeFilter" onchange="currentPage=0;loadIOCs()">
        <option value="">All Types</option>
        <option>ip</option><option>ipv6</option><option>domain</option><option>url</option>
        <option>sha256</option><option>sha1</option><option>md5</option>
        <option>email</option><option>cve</option><option>hostname</option>
        <option>registry_key</option><option>filename</option>
      </select>
      <select id="classFilter" onchange="currentPage=0;loadIOCs()">
        <option value="">All Classifications</option>
        <option>malicious</option><option>suspicious</option>
        <option>unknown</option><option>internal</option><option>external</option>
      </select>
      <select id="sourceTypeFilter" onchange="activeSourceUrl=undefined;currentPage=0;loadIOCs()">
        <option value="">All Sources</option>
        <option value="scraper">Scraper (feeds)</option>
        <option value="manual">Manual</option>
        <option value="file">File upload</option>
      </select>
      <select id="feedUrlFilter" onchange="currentPage=0;applyFeedFilter()" style="max-width:200px;">
        <option value="">All Feeds</option>
      </select>
      <label style="display:flex;align-items:center;gap:4px;font-size:11px;color:var(--text2);cursor:pointer;white-space:nowrap;">
        <input type="checkbox" id="showIgnored" onchange="currentPage=0;loadIOCs()" style="accent-color:var(--yellow);">
        Show Ignored
      </label>
      <button id="restoreAllBtn" class="hc-toggle" style="display:none;--hc-primary:var(--yellow);" onclick="restoreAll()"><span>↺ Restore All</span></button>
      <button class="hc-toggle" onclick="exportCSV()"><span>⬇ Export CSV</span></button>
    </div>
    <div id="paginationBar" style="display:flex;gap:7px;align-items:center;margin-bottom:9px;font-size:11px;color:var(--text2);"></div>
    <div class="panel">
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
              <th>Value</th><th>Type</th><th>Class</th>
              <th>Country</th><th>Score</th><th>Source</th><th>Extracted</th><th>Actions</th>
            </tr>
          </thead>
          <tbody id="iocTable"><tr><td colspan="9" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
    </div>
    <div id="selectionBar" style="display:none;margin-top:8px;display:flex;gap:7px;align-items:center;font-size:12px;">
      <span id="selCount" style="color:var(--text2);"></span>
      <button class="hc-toggle" onclick="huntSelected()"><span>Hunt Selected →</span></button>
      <button class="hc-toggle" onclick="huntAddAll()"><span>+ Add All to Hunt</span></button>
      <button class="hc-toggle" onclick="clearSelection()"><span>Clear</span></button>
    </div>
  </div>

  <!-- ── Enrichment (per-IOC analyst tracking: found/not-found, ticket ref, affected host) ── -->
  <div id="tab-enrichment" style="display:none;">
    <div class="filter-row">
      <select id="enrichClassFilter" onchange="loadEnrichmentTab()">
        <option value="">All Classifications</option>
        <option value="malicious,suspicious">Malicious + Suspicious</option>
      </select>
      <span style="font-size:11px;color:var(--text2);">Mark whether each IOC was found in your environment, and attach which environment, a ticket/event reference, and affected host.</span>
    </div>
    <datalist id="envNameOptions">
      <option>Splunk</option><option>Sentinel/Defender</option><option>CrowdStrike</option>
      <option>SentinelOne</option><option>Wazuh</option><option>Elastic</option><option>Trellix</option>
    </datalist>
    <div class="panel">
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Value</th><th>Type</th><th>Status</th>
              <th>Environment + Ticket / Event ID + Affected Host</th>
            </tr>
          </thead>
          <tbody id="enrichmentTable"><tr><td colspan="4" class="loading">Loading…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ── Hunt Builder ── -->
  <div id="tab-hunt">

    <!-- Mode toggle -->
    <div style="display:flex;gap:6px;margin-bottom:14px;">
      <button id="huntModeCustom" class="hc-toggle" style="font-size:11px;padding:4px 13px;border-color:var(--accent);color:var(--accent);" onclick="setHuntMode('custom')"><span>⚡ Custom Hunt</span></button>
      <button id="huntModeDB" class="hc-toggle" style="font-size:11px;padding:4px 13px;" onclick="setHuntMode('db')"><span>📦 From Database</span></button>
    </div>

    <!-- ── Custom Hunt (default) ── -->
    <div id="huntCustomControls">
      <div style="margin-bottom:10px;">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Hunt Name</div>
        <input type="text" id="huntName" placeholder="Lazy Hunt Name" style="font-family:monospace;width:100%;box-sizing:border-box;" oninput="if(window._descBaseLines)_rebuildDescText()">
      </div>

      <div style="display:flex;gap:7px;margin-bottom:8px;align-items:flex-end;">
        <div style="flex:1;">
          <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Add IOC</div>
          <input type="text" id="huntAddVal" placeholder="IP, hash, domain, CVE, registry key…" style="font-family:monospace;" onkeydown="if(event.key==='Enter')huntAddOne()">
        </div>
        <div>
          <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Type</div>
          <select id="huntAddType" style="width:120px;">
            <option value="auto">Auto-detect</option>
            <option value="ip">IP</option>
            <option value="ipv6">IPv6</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="sha256">SHA256</option>
            <option value="sha1">SHA1</option>
            <option value="md5">MD5</option>
            <option value="email">Email</option>
            <option value="cve">CVE</option>
            <option value="filename">Filename</option>
            <option value="registry_key">Registry Key</option>
            <option value="hostname">Hostname</option>
          </select>
        </div>
        <button class="hc-toggle" onclick="huntAddOne()"><span>+ Add</span></button>
      </div>

      <!-- Paste area — always visible -->
      <div id="huntPasteArea" style="margin-bottom:8px;">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Paste IOCs</div>
        <textarea id="huntPasteInput" rows="4" placeholder="Paste IOCs — one per line (auto-detected; unknown types will prompt)" style="font-family:monospace;font-size:12px;" oninput="huntPastePreview()"></textarea>
        <div style="display:flex;gap:6px;margin-top:5px;align-items:center;">
          <span id="huntPasteInfo" style="font-size:11px;color:var(--text2);flex:1;"></span>
          <button class="hc-toggle" onclick="huntPasteAdd()"><span>→ Add to Hunt</span></button>
        </div>
      </div>

      <!-- Current hunt — sorted by type -->
      <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Current Hunt</div>
      <div id="huntBlocks" style="min-height:38px;padding:8px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;">
        <span style="color:var(--text2);font-size:11px;">No IOCs added yet</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
        <span id="huntBlockCount" style="font-size:11px;color:var(--text2);flex:1;"></span>
        <button class="hc-toggle" style="font-size:10px;padding:2px 8px;" onclick="huntClearBlocks()"><span>Clear All</span></button>
      </div>
    </div>

    <!-- ── DB mode ── -->
    <div id="huntDbControls" style="display:none;">
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
        <div>
          <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;font-weight:700;">IOC Types</div>
          <div class="hunt-type-grid" id="huntTypeGrid">
            <label class="glitch-checkbox-container"><input type="checkbox" value="ip" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="🌐 IPs">🌐 IPs</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="domain" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="🔗 Domains">🔗 Domains</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="url" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="🔗 URLs">🔗 URLs</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="sha256" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="# SHA256"># SHA256</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="md5" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="# MD5"># MD5</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="sha1" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="# SHA1"># SHA1</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="email" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="✉ Email">✉ Email</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="cve" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="⚠ CVEs">⚠ CVEs</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="registry_key" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="🗝 Registry">🗝 Registry</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="filename" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="📄 Files">📄 Files</span></label>
            <label class="glitch-checkbox-container"><input type="checkbox" value="hostname" checked onchange="toggleHuntType(this)"><div class="checkbox-box"><div class="checkbox-mark"></div></div><span class="checkbox-label" data-text="💻 Hosts">💻 Hosts</span></label>
          </div>
        </div>
        <div>
          <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;font-weight:700;">Classification</div>
          <select id="huntClassFilter" style="width:180px;">
            <option value="malicious,suspicious">Malicious + Suspicious</option>
            <option value="malicious">Malicious Only</option>
            <option value="suspicious">Suspicious Only</option>
            <option value="all">All IOCs</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Build (shared) — platform selection now comes from the Environments
         checkboxes at the top of the page, not a separate dropdown here. -->
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;">
      <div style="font-size:11px;color:var(--text2);">Generates for whatever's checked in <b>Environments</b> above — all platforms if none are checked.</div>
      <div style="margin-left:auto;">
        <button class="hc-toggle" onclick="buildHuntQueries()"><span>⚡ Build Queries</span></button>
      </div>
    </div>

    <!-- Date range picker -->
    <div style="margin-bottom:14px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;">
      <div style="font-size:11px;color:var(--text2);text-transform:uppercase;font-weight:700;margin-bottom:7px;">Time Range</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:6px;" id="huntTimePresets">
        <button data-preset="1d"  class="hunt-preset hc-toggle" onclick="setHuntTimePreset('1d')"  style="font-size:11px;padding:3px 10px;"><span>24h</span></button>
        <button data-preset="7d"  class="hunt-preset hc-toggle active" onclick="setHuntTimePreset('7d')"  style="font-size:11px;padding:3px 10px;"><span>7d</span></button>
        <button data-preset="14d" class="hunt-preset hc-toggle" onclick="setHuntTimePreset('14d')" style="font-size:11px;padding:3px 10px;"><span>14d</span></button>
        <button data-preset="30d" class="hunt-preset hc-toggle" onclick="setHuntTimePreset('30d')" style="font-size:11px;padding:3px 10px;"><span>30d</span></button>
        <button data-preset="90d" class="hunt-preset hc-toggle" onclick="setHuntTimePreset('90d')" style="font-size:11px;padding:3px 10px;"><span>90d</span></button>
        <button data-preset="custom" class="hunt-preset hc-toggle" onclick="setHuntTimePreset('custom')" style="font-size:11px;padding:3px 10px;"><span>Custom…</span></button>
      </div>
      <div id="huntCustomRange" style="display:none;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <div>
          <div style="font-size:10px;color:var(--text2);margin-bottom:2px;">Start</div>
          <input type="date" id="huntRangeStart" style="font-size:11px;padding:3px 6px;" onchange="validateHuntRange()">
        </div>
        <div>
          <div style="font-size:10px;color:var(--text2);margin-bottom:2px;">End</div>
          <input type="date" id="huntRangeEnd" style="font-size:11px;padding:3px 6px;" onchange="validateHuntRange()">
        </div>
        <span id="huntRangeErr" style="font-size:11px;color:var(--red);"></span>
      </div>
    </div>

    <div id="huntResults" style="color:var(--text2);font-size:12px;">Add IOCs above and click Build Queries.</div>
  </div>

  <!-- ── Analyst View ── -->
  <div id="tab-analyst" style="display:none;">

    <!-- Manual IOC entry -->
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:11px;">
      <div style="font-size:11px;color:var(--accent);font-weight:700;text-transform:uppercase;margin-bottom:7px;">⚡ Quick Analyze — no DB required</div>
      <div style="display:flex;gap:7px;margin-bottom:7px;align-items:flex-end;">
        <input type="text" id="analystManualVal" placeholder="Enter IP, hash, domain, CVE…" style="flex:1;font-family:monospace;" onkeydown="if(event.key==='Enter')analystAddManual()">
        <button class="hc-toggle" onclick="analystAddManual()"><span>+ Add</span></button>
        <button class="hc-toggle" style="font-size:11px;" onclick="analystPasteOpen()"><span>⊞ Paste Many</span></button>
        <button class="hc-toggle" style="font-size:11px;" onclick="analystAddFromHunt()"><span>⚡ From Hunt</span></button>
      </div>
      <div id="analystPasteArea" style="display:none;margin-bottom:7px;">
        <textarea id="analystPasteInput" rows="4" placeholder="Paste IOCs — one per line" style="font-family:monospace;font-size:12px;" oninput="analystPastePreview()"></textarea>
        <div style="display:flex;gap:6px;margin-top:4px;align-items:center;">
          <span id="analystPasteInfo" style="font-size:11px;color:var(--text2);flex:1;"></span>
          <button class="hc-toggle" onclick="analystPasteAdd()"><span>Add All</span></button>
          <button class="hc-toggle" onclick="document.getElementById('analystPasteArea').style.display='none'"><span>Cancel</span></button>
        </div>
      </div>
      <div id="analystManualBlocks" style="display:flex;flex-wrap:wrap;gap:5px;min-height:28px;"></div>
      <div style="display:flex;gap:7px;margin-top:7px;align-items:center;">
        <span id="analystManualCount" style="font-size:11px;color:var(--text2);flex:1;"></span>
        <button class="hc-toggle" style="font-size:10px;padding:2px 7px;" onclick="analystClearManual()"><span>Clear</span></button>
        <button class="hc-toggle" onclick="loadAnalystView(true)"><span>Analyze</span></button>
      </div>
    </div>

    <!-- DB filter -->
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:10px;font-size:11px;color:var(--text2);">
      <span>Or load from DB:</span>
      <select id="analystTypeFilter" style="width:140px;">
        <option value="">All Types</option>
        <option>ip</option><option>ipv6</option><option>domain</option><option>url</option>
        <option>sha256</option><option>sha1</option><option>md5</option>
        <option>email</option><option>cve</option><option>filename</option><option>registry_key</option>
      </select>
      <select id="analystClassFilter" style="width:160px;">
        <option value="malicious,suspicious">Malicious + Suspicious</option>
        <option value="malicious">Malicious Only</option>
        <option value="">All IOCs</option>
      </select>
      <button class="hc-toggle" onclick="loadAnalystView(false)"><span>Load from DB</span></button>
    </div>

    <!-- Hunt wrap-up report — plain text, ready to paste into an email -->
    <div class="panel" style="margin-bottom:16px;">
      <div class="panel-header">
        <span>📧 Hunt Report</span>
        <span style="font-size:10px;color:var(--text2);font-weight:400;">summary + findings + hunt queries, ready to paste into an email</span>
        <button class="hc-toggle" style="margin-left:auto;font-size:11px;padding:3px 10px;" onclick="generateHuntReport(this)"><span>Generate Report</span></button>
        <button class="hc-toggle" id="copyReportBtn" style="font-size:11px;padding:3px 10px;display:none;" onclick="copyHuntReport(this)"><span>Copy for Email</span></button>
      </div>
      <div class="panel-body" id="huntReportBody" style="display:none;">
        <pre id="huntReportText" style="max-height:420px;"></pre>
      </div>
    </div>

    <!-- IOC Links table — directly after Quick Analyze + DB filter -->
    <div id="analystResults" style="margin-top:16px;"></div>

    <!-- ── Ticket Intelligence ── -->
    <div id="ticketIntelSection" style="margin-top:16px;">
      <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px 6px 0 0;cursor:pointer;user-select:none;" onclick="toggleTicketIntel()">
        <span style="font-size:13px;color:var(--accent);font-weight:700;">🎯 Ticket Intelligence</span>
        <span style="font-size:11px;color:var(--text2);">deep reputation analysis · driven by Quick Analyze</span>
        <span id="tiCollapseIcon" style="margin-left:auto;color:var(--text2);font-size:12px;">▼</span>
      </div>
      <div id="ticketIntelBody" style="background:var(--bg2);border:1px solid var(--border);border-top:none;border-radius:0 0 6px 6px;padding:12px;">
        <!-- API Keys panel -->
        <div id="tiKeyPanel" style="margin-bottom:10px;">
          <div style="display:flex;align-items:center;gap:8px;padding:5px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;cursor:pointer;" onclick="tiToggleKeys()">
            <span style="font-size:10px;color:var(--accent);font-weight:700;text-transform:uppercase;">🔑 API Keys</span>
            <span style="font-size:10px;color:var(--text2);">VirusTotal · AbuseIPDB</span>
            <span id="tiKeyIcon" style="margin-left:auto;font-size:10px;color:var(--text2);">▶</span>
          </div>
          <div id="tiKeyBody" style="display:none;padding:10px;background:var(--bg3);border:1px solid var(--border);border-top:none;border-radius:0 0 4px 4px;">
            <div style="display:flex;flex-wrap:wrap;gap:10px;">
              <div style="flex:1;min-width:200px;">
                <div style="font-size:10px;color:var(--text2);margin-bottom:3px;">VirusTotal API Key</div>
                <input type="password" id="tiVtKey" placeholder="VT API key…" style="width:100%;box-sizing:border-box;font-family:monospace;font-size:11px;">
              </div>
              <div style="flex:1;min-width:200px;">
                <div style="font-size:10px;color:var(--text2);margin-bottom:3px;">AbuseIPDB API Key</div>
                <input type="password" id="tiAbuseKey" placeholder="AbuseIPDB API key…" style="width:100%;box-sizing:border-box;font-family:monospace;font-size:11px;">
              </div>
            </div>
            <div style="font-size:10px;color:var(--text2);margin-top:6px;">Session-only — keys never persist. Sent only to this tool's backend for lookup requests.</div>
          </div>
        </div>
        <!-- Rescan with keys -->
        <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
          <button class="hc-toggle" onclick="rescanWithKeys()" style="background:var(--accent);color:#000;font-weight:700;white-space:nowrap;"><span>🔑 Rescan with Keys</span></button>
          <span style="font-size:11px;color:var(--text2);">Re-runs the last batch using the API keys above. Bypasses cache.</span>
        </div>
        <!-- Source selector -->
        <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:6px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:4px;margin-bottom:10px;">
          <span style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;white-space:nowrap;">Sources</span>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;"><input type="checkbox" id="tis-virustotal" checked onchange="toggleTiSource('virustotal',this.checked)"><span>VirusTotal</span><span style="font-size:9px;color:var(--red);margin-left:2px;">KEY</span></label>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;"><input type="checkbox" id="tis-abuseipdb" checked onchange="toggleTiSource('abuseipdb',this.checked)"><span>AbuseIPDB</span><span style="font-size:9px;color:var(--red);margin-left:2px;">KEY</span></label>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;"><input type="checkbox" id="tis-ipinfo" checked onchange="toggleTiSource('ipinfo',this.checked)"><span>ipinfo</span></label>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;"><input type="checkbox" id="tis-arin" checked onchange="toggleTiSource('arin',this.checked)"><span>ARIN</span></label>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;"><input type="checkbox" id="tis-urlscan" checked onchange="toggleTiSource('urlscan',this.checked)"><span>urlscan</span></label>
          <span style="border-left:1px solid var(--border);height:14px;margin:0 2px;"></span>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;" title="Reference link only — no score"><input type="checkbox" id="tis-crtsh" checked onchange="toggleTiSource('crtsh',this.checked)"><span style="color:var(--text2);">crt.sh</span><span style="font-size:9px;color:var(--text2);margin-left:2px;">ref</span></label>
          <label style="display:flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;" title="Reference link only — no score"><input type="checkbox" id="tis-talos" checked onchange="toggleTiSource('talos',this.checked)"><span style="color:var(--text2);">Talos</span><span style="font-size:9px;color:var(--text2);margin-left:2px;">ref</span></label>
        </div>
        <div id="tiResults"></div>
      </div>
    </div>

    <!-- ── Ticket Information (combined intel summary) ── -->
    <div id="ticketInfoSection" style="margin-top:16px;"></div>
  </div>

  <!-- ── IOC Description ── -->
  <div id="tab-description" style="display:none;">
    <div class="loading">Click the tab to generate a ticket-ready description.</div>
  </div>

  <!-- Cheat Sheet Tab -->
  <div id="tab-cheatsheet" style="display:none;">
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:14px;flex-wrap:wrap;">
      <span style="font-size:11px;color:var(--text2);text-transform:uppercase;font-weight:700;">Platform Filter</span>
      <button id="cs-plat-all" class="cs-plat-btn hc-toggle" onclick="setCSPlatform('all')" style="font-size:11px;padding:3px 10px;background:var(--accent);color:var(--bg);border-color:var(--accent);"><span>All</span></button>
      <button id="cs-plat-kql" class="cs-plat-btn hc-toggle" onclick="setCSPlatform('kql')" style="font-size:11px;padding:3px 10px;"><span>KQL</span></button>
      <button id="cs-plat-splunk" class="cs-plat-btn hc-toggle" onclick="setCSPlatform('splunk')" style="font-size:11px;padding:3px 10px;"><span>Splunk</span></button>
      <button id="cs-plat-elastic" class="cs-plat-btn hc-toggle" onclick="setCSPlatform('elastic')" style="font-size:11px;padding:3px 10px;"><span>Elastic</span></button>
      <button id="cs-plat-sigma" class="cs-plat-btn hc-toggle" onclick="setCSPlatform('sigma')" style="font-size:11px;padding:3px 10px;"><span>Sigma</span></button>
      <span style="margin-left:auto;"><input type="text" id="csSearch" placeholder="Search scenarios..." style="width:200px;font-size:11px;" oninput="filterCheatSheet()"></span>
    </div>
    <div id="csResults"></div>
  </div>

  <!-- Detection Engineering Tab -->
  <div id="tab-detect" style="display:none;">
    <div style="display:flex;gap:6px;margin-bottom:14px;">
      <button id="detectModeCustom" class="hc-toggle active" onclick="setDetectMode('custom')"><span>Custom IOCs</span></button>
      <button id="detectModeDB" class="hc-toggle" onclick="setDetectMode('db')"><span>From Database</span></button>
      <button id="detectModeHunt" class="hc-toggle" onclick="setDetectMode('hunt')"><span>From Hunt</span></button>
    </div>
    <div id="detectCustomControls">
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:11px;">
        <div style="font-size:11px;color:var(--accent);font-weight:700;text-transform:uppercase;margin-bottom:7px;">Quick Add IOCs</div>
        <div style="display:flex;gap:7px;margin-bottom:7px;align-items:flex-end;">
          <input type="text" id="detectAddVal" placeholder="IP, hash, domain, CVE..." style="flex:1;font-family:monospace;" onkeydown="if(event.key==='Enter')detectAddOne()">
          <select id="detectAddType" style="width:120px;"><option value="auto">Auto-detect</option><option value="ip">IP</option><option value="domain">Domain</option><option value="sha256">SHA256</option><option value="md5">MD5</option><option value="email">Email</option><option value="cve">CVE</option></select>
          <button class="hc-toggle" onclick="detectAddOne()"><span>+ Add</span></button>
        </div>
        <textarea id="detectPasteInput" rows="3" placeholder="Or paste IOCs - one per line" style="font-family:monospace;font-size:12px;" oninput="detectPastePreview()"></textarea>
        <div style="display:flex;gap:6px;margin-top:5px;align-items:center;">
          <span id="detectPasteInfo" style="font-size:11px;color:var(--text2);flex:1;"></span>
          <button class="hc-toggle" onclick="detectPasteAdd()"><span>Add to List</span></button>
        </div>
      </div>
      <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Current IOCs</div>
      <div id="detectBlocks" style="min-height:38px;padding:8px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"><span style="color:var(--text2);font-size:11px;">No IOCs added yet</span></div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
        <span id="detectBlockCount" style="font-size:11px;color:var(--text2);flex:1;"></span>
        <button class="hc-toggle" style="font-size:10px;padding:2px 8px;" onclick="detectClearBlocks()"><span>Clear All</span></button>
      </div>
    </div>
    <div id="detectDbControls" style="display:none;">
      <div style="margin-bottom:10px;">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;font-weight:700;">Classification</div>
        <select id="detectClassFilter" style="width:180px;"><option value="malicious,suspicious">Malicious + Suspicious</option><option value="malicious">Malicious Only</option><option value="all">All IOCs</option></select>
      </div>
      <div style="margin-bottom:10px;">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;font-weight:700;">IOC Types</div>
        <div id="detectTypeGrid" style="display:flex;flex-wrap:wrap;gap:6px;">
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="ip" checked> IP</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="domain" checked> Domain</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="sha256" checked> SHA256</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="md5" checked> MD5</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="email" checked> Email</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="cve" checked> CVE</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="filename" checked> Filename</label>
          <label style="font-size:11px;display:flex;align-items:center;gap:4px;cursor:pointer;"><input type="checkbox" value="url" checked> URL</label>
        </div>
      </div>
    </div>
    <div id="detectHuntControls" style="display:none;">
      <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:11px;">
        <div style="font-size:11px;color:var(--accent);font-weight:700;text-transform:uppercase;margin-bottom:7px;">Load IOCs from Current Hunt</div>
        <div style="font-size:12px;color:var(--text2);margin-bottom:8px;">Pulls all IOCs from the active hunt session in the IOC List tab.</div>
        <div style="display:flex;gap:8px;align-items:center;">
          <span id="detectHuntCount" style="font-size:12px;color:var(--text2);flex:1;">0 IOCs in current hunt</span>
          <button class="hc-toggle" onclick="detectLoadFromHunt()"><span>Load from Hunt</span></button>
        </div>
      </div>
    </div>
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;flex-wrap:wrap;">
      <div>
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Detection Platform</div>
        <select id="detectPlatform" style="width:210px;"><option value="all">All Platforms</option><option value="sigma">Sigma</option><option value="kql">KQL Analytics Rule</option><option value="splunk">Splunk Correlation</option><option value="elastic">Elastic Detection</option></select>
      </div>
      <div style="align-self:flex-end;"><button class="hc-toggle" onclick="buildDetectionRules()"><span>Generate Rules</span></button></div>
    </div>
    <div id="detectResults" style="color:var(--text2);font-size:12px;">Add IOCs above and click Generate Rules.</div>
  </div>

  <!-- ── Hunt Frameworks ── -->
  <div id="tab-frameworks" style="display:none;">
    <div class="panel" style="margin-bottom:12px;">
      <div class="panel-header">Pick a framework — it drives the worksheet below</div>
      <div class="panel-body">
        <div id="fwSelector"></div>
        <div style="font-size:11px;color:var(--text2);margin-top:4px;">Choose the methodology that fits the hunt, work through its phases, then compile a hunt plan you can copy into your ticket or report. Notes are saved in this browser.</div>
      </div>
    </div>
    <div class="panel" style="margin-bottom:12px;">
      <div class="panel-header">Models &amp; maturity — reference</div>
      <div class="panel-body"><div id="fwModels" class="grid-auto" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px;"></div></div>
    </div>
    <div id="fwBody"></div>
    <div style="display:flex;gap:8px;align-items:center;margin:10px 0;flex-wrap:wrap;">
      <button class="hc-toggle" onclick="fwCompile()"><span>Compile Hunt Plan</span></button>
      <button class="hc-toggle" id="fwCopyBtn" style="display:none;" onclick="fwCopyPlan(this)"><span>Copy</span></button>
      <button class="hc-toggle" style="font-size:10px;padding:2px 9px;" onclick="fwClear()"><span>Clear this framework</span></button>
    </div>
    <textarea id="fwPlan" rows="14" style="width:100%;font-family:monospace;font-size:11px;display:none;" readonly></textarea>
  </div>

</div><!-- /main -->
</div><!-- /layout -->
</div><!-- /appRoot -->

<script>
let currentMode = null;
// Hypothesis mode: Hypothesis Builder + TTP Library + the tabs useful for
// running down a hypothesis (structured hunt templates, IOC tracking,
// enrichment, analyst findings). IOC mode: every original tab, unchanged,
// no Hypothesis Builder or TTP Library.
const IOC_ONLY_TABS = ['cheatsheet','detect','description'];
const HYPOTHESIS_ONLY_TABS = ['hypothesis','ttp','hypreport'];
const FRAMEWORKS_ONLY_TABS = ['frameworks'];
const MODE_LANDING = { hypothesis: 'hypothesis', ioc: 'hunt', frameworks: 'frameworks' };
function selectMode(mode){
  const changed = currentMode !== mode;
  currentMode = mode;
  localStorage.setItem('lth_mode', mode);
  document.getElementById('modeBarHyp').classList.toggle('active', mode==='hypothesis');
  document.getElementById('modeBarIoc').classList.toggle('active', mode==='ioc');
  document.getElementById('modeBarFrameworks').classList.toggle('active', mode==='frameworks');
  document.getElementById('hypothesisWarning').style.display = mode==='hypothesis' ? '' : 'none';
  if(mode==='hypothesis') scheduleHypothesisGlitch(); else stopHypothesisGlitch();
  HYPOTHESIS_ONLY_TABS.forEach(t=>{
    document.getElementById('tabBtn'+t[0].toUpperCase()+t.slice(1)).style.display = mode==='hypothesis' ? '' : 'none';
  });
  IOC_ONLY_TABS.forEach(t=>{
    document.getElementById('tabBtn'+t[0].toUpperCase()+t.slice(1)).style.display = mode==='ioc' ? '' : 'none';
  });
  FRAMEWORKS_ONLY_TABS.forEach(t=>{
    document.getElementById('tabBtn'+t[0].toUpperCase()+t.slice(1)).style.display = mode==='frameworks' ? '' : 'none';
  });
  if(changed) showTab(MODE_LANDING[mode] || 'hunt');
}
// No more landing-page mode gate — go straight into the app, defaulting to
// IOC mode (or whatever was last used, from localStorage). appRoot is
// display:contents from the start now (see its tag above) so it's never
// hidden; this just sets the mode-bar/tabs/banner to match on load.
function initMode(){
  const saved = localStorage.getItem('lth_mode');
  selectMode(['hypothesis','frameworks'].includes(saved) ? saved : 'ioc');
}

// Random-interval glitch for the Hypothesis warning banner — brief (450ms)
// flicker every 8-20s while in Hypothesis mode, not a constant animation,
// per explicit "don't want it too distracting" instruction.
let _hwGlitchTimer = null;
function scheduleHypothesisGlitch(){
  if(_hwGlitchTimer) return;
  const fire = () => {
    const el = document.getElementById('hypothesisWarning');
    if(el && el.style.display !== 'none'){
      el.classList.add('glitching');
      setTimeout(()=>el.classList.remove('glitching'), 450);
    }
    _hwGlitchTimer = setTimeout(fire, 8000 + Math.random()*12000);
  };
  _hwGlitchTimer = setTimeout(fire, 8000 + Math.random()*12000);
}
function stopHypothesisGlitch(){
  clearTimeout(_hwGlitchTimer);
  _hwGlitchTimer = null;
  const el = document.getElementById('hypothesisWarning');
  if(el) el.classList.remove('glitching');
}

// Demo data — one-click, on-demand only (never auto-populated, so it never
// interferes with real usage). Both paths reuse existing storage: IOCs go
// through the same /api/iocs/add-manual endpoint the Hunt Builder paste/add
// flow uses; the hypothesis goes straight into the same localStorage helpers
// saveHypothesis() uses.
async function loadDemoData(kind){
  if(kind==='iocs'){
    const sample = [
      {value:'185.220.101.45', type:'ip'},
      {value:'45.142.214.219', type:'ip'},
      {value:'secure-update-portal.com', type:'domain'},
      {value:'cdn-assets-delivery.net', type:'domain'},
      {value:'http://185.220.101.45/payload.bin', type:'url'},
      {value:'a3b9e2c7d4f1e8a5b6c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1', type:'sha256'},
      {value:'attacker@secure-update-portal.com', type:'email'},
      {value:'CVE-2024-21412', type:'cve'},
    ];
    const r = await api('/api/iocs/add-manual', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({iocs: sample, tags: ['sample']})});
    if(r && r.error){ showAlert('error', 'Demo data failed: '+r.error); return; }
    showAlert('success', 'Loaded '+(r && r.inserted!=null ? r.inserted : sample.length)+' sample IOC(s) — tagged "sample", use Remove Sample Data to clear');
    refresh();
  } else if(kind==='hypothesis'){
    if(currentMode!=='hypothesis') selectMode('hypothesis');
    populateHypActorSelect();
    // Saved straight into the hunt (sample-flagged) rather than only staged in
    // the builder form, so it shows up immediately in the list and report.
    const h = {
      id: Date.now(),
      what: 'Evidence of lateral movement using living-off-the-land binaries (LOLBins) and scheduled-task persistence',
      why: 'Unusual rundll32/regsvr32 activity flagged by EDR on finance-dept workstations, pattern resembles public APT29 reporting',
      who: 'Suspected APT29 activity targeting finance department',
      when: 'Outside business hours over the last 72 hours, deviation from normal admin baseline',
      where: 'EDR process logs (DeviceProcessEvents), Windows Security Event Log 4688/4698 — confirmed logged in Sentinel',
      testable: 'Query process creation logs for rundll32/regsvr32 spawning network connections, and new scheduled tasks, over the last 7 days',
      actorId: 'apt29',
      created: new Date().toISOString(),
      sample: true,
    };
    // Replace any prior sample so repeated clicks don't pile up duplicates.
    const list = getHypotheses().filter(x => !x.sample);
    list.unshift(h);
    setHypotheses(list);
    showTab('hypothesis');
    renderHypothesesList();
    showAlert('success', 'Sample hypothesis added to your hunt — use Remove Sample Data to clear it');
  }
}

// Clears everything loaded by the "Load … Data" buttons: sample-tagged IOCs
// from this session's DB, and the sample-flagged hypothesis from local storage.
async function removeSampleData(btn){
  const before = getHypotheses();
  const kept = before.filter(h => !h.sample);
  const removedHyp = before.length - kept.length;
  setHypotheses(kept);
  renderHypothesesList();
  let removedIoc = 0;
  try{
    const r = await api('/api/iocs/delete-by-tag', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({tag: 'sample'})});
    if(r && r.error){ showAlert('error', 'Remove failed: '+r.error); return; }
    removedIoc = (r && r.deleted) || 0;
  }catch(e){ showAlert('error', 'Remove failed: '+(e && e.message ? e.message : String(e))); return; }
  refresh();
  if(removedIoc || removedHyp){
    showAlert('success', 'Removed sample data — '+removedIoc+' IOC(s)'+(removedHyp ? ', '+removedHyp+' hypothesis(es)' : ''));
  } else {
    showAlert('success', 'No sample data to remove');
  }
}

function getHypotheses(){
  // Stored in this browser only. ids are forced to numbers because they are written into onclick handlers.
  try{
    const list = JSON.parse(localStorage.getItem('lth_hypotheses')||'[]');
    return Array.isArray(list) ? list.filter(h=>h && typeof h==='object').map(h=>({...h, id:Number(h.id)||0})) : [];
  }catch(e){return [];}
}
function setHypotheses(list){localStorage.setItem('lth_hypotheses', JSON.stringify(list));}
function populateHypActorSelect(){
  const sel = document.getElementById('hypActor');
  if(!sel || sel.dataset.filled || typeof THREAT_ACTORS==='undefined') return;
  THREAT_ACTORS.forEach(a=>{
    const opt = document.createElement('option');
    opt.value = a.id; opt.textContent = a.name;
    sel.appendChild(opt);
  });
  sel.dataset.filled = '1';
}
function saveHypothesis(){
  const h = {
    id: Date.now(),
    what: document.getElementById('hypWhat').value.trim(),
    why: document.getElementById('hypWhy').value.trim(),
    who: document.getElementById('hypWho').value.trim(),
    when: document.getElementById('hypWhen').value.trim(),
    where: document.getElementById('hypWhere').value.trim(),
    testable: document.getElementById('hypTestable').value.trim(),
    actorId: document.getElementById('hypActor').value || null,
    created: new Date().toISOString(),
  };
  if(!h.what){ alert('What — what are you looking for? is required.'); return; }
  const list = getHypotheses();
  list.unshift(h);
  setHypotheses(list);
  ['hypWhat','hypWhy','hypWho','hypWhen','hypWhere','hypTestable'].forEach(id=>document.getElementById(id).value='');
  document.getElementById('hypActor').value = '';
  renderHypothesesList();
}
function deleteHypothesis(id){
  setHypotheses(getHypotheses().filter(h=>h.id!==id));
  renderHypothesesList();
}
// Lightweight, deterministic keyword match (no AI) — not technique.id or
// already linked via actorId.
function suggestedTechniquesFor(h){
  if(typeof TTP_TECHNIQUES==='undefined') return [];
  const linked = h.actorId && typeof ttpActorById==='function' ? (ttpActorById(h.actorId)||{techniqueIds:[]}).techniqueIds : [];
  const text = [h.what,h.why,h.who,h.when,h.where].join(' ').toLowerCase();
  return TTP_TECHNIQUES.filter(t=>{
    if(linked.indexOf(t.id)!==-1) return false;
    const words = t.name.toLowerCase().split(/[^a-z0-9]+/).filter(w=>w.length>3);
    return words.some(w=>text.indexOf(w)!==-1);
  });
}
function techniqueChip(t){
  return '<span class="badge type" style="cursor:pointer;margin-right:4px;" title="'+escHtml(t.description)+'" onclick="jumpToTechnique(\\''+t.id+'\\')">'+escHtml(t.id)+' '+escHtml(t.name)+'</span>';
}
// Shared by the Hypothesis Builder list and the Hypothesis Hunt Report tab
// — actor-linked (exact) + keyword-suggested technique chips for one hypothesis.
function ttpChipsBlock(h){
  const actor = h.actorId && typeof ttpActorById==='function' ? ttpActorById(h.actorId) : null;
  const actorTechniques = actor && typeof ttpTechniqueById==='function' ? actor.techniqueIds.map(ttpTechniqueById).filter(Boolean) : [];
  const suggested = suggestedTechniquesFor(h);
  let block = '';
  if(actor){
    block += '<div style="margin-top:8px;"><div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;">'+escHtml(actor.name)+' — known techniques</div>'+actorTechniques.map(techniqueChip).join('')+'</div>';
  }
  if(suggested.length){
    block += '<div style="margin-top:8px;"><div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;">You might also consider</div>'+suggested.map(techniqueChip).join('')+'</div>';
  }
  return block;
}
// Plain-text version of the same hypothesis + TTP data — used by every
// "copy for sharing" path (draft summary, per-card copy, full report).
function formatHypothesisText(h){
  const lines = [];
  lines.push('HYPOTHESIS' + (h.created ? ' — '+new Date(h.created).toLocaleString() : ' (draft)'));
  lines.push('='.repeat(60));
  if(h.what) lines.push('WHAT: '+h.what);
  if(h.why) lines.push('WHY: '+h.why);
  if(h.who) lines.push('WHO: '+h.who);
  if(h.when) lines.push('WHEN: '+h.when);
  if(h.where) lines.push('WHERE: '+h.where);
  if(h.testable) lines.push('TESTABLE/MEASURABLE: '+h.testable);
  const actor = h.actorId && typeof ttpActorById==='function' ? ttpActorById(h.actorId) : null;
  if(actor){
    lines.push('');
    lines.push('SUSPECTED ACTOR: '+actor.name);
    lines.push('  '+actor.description);
    const techs = actor.techniqueIds.map(ttpTechniqueById).filter(Boolean);
    if(techs.length) lines.push('KNOWN TECHNIQUES: '+techs.map(t=>t.id+' '+t.name).join(', '));
  }
  const suggested = suggestedTechniquesFor(h);
  if(suggested.length){
    lines.push('');
    lines.push('ALSO CONSIDER: '+suggested.map(t=>t.id+' '+t.name).join(', '));
  }
  return lines.join('\\n');
}
function generateHypothesisShareText(){
  const draft = {
    what: document.getElementById('hypWhat').value.trim(),
    why: document.getElementById('hypWhy').value.trim(),
    who: document.getElementById('hypWho').value.trim(),
    when: document.getElementById('hypWhen').value.trim(),
    where: document.getElementById('hypWhere').value.trim(),
    testable: document.getElementById('hypTestable').value.trim(),
    actorId: document.getElementById('hypActor').value || null,
  };
  if(!draft.what){ alert('Fill in at least "What" before generating a shareable summary.'); return; }
  const text = formatHypothesisText(draft);
  document.getElementById('hypShareText').textContent = text;
  document.getElementById('hypShareBody').style.display = '';
  document.getElementById('hypShareCopyBtn').style.display = '';
  _hypShareText = text;
}
let _hypShareText = '';
function copyHypothesisShare(btn){
  if(!_hypShareText) return;
  copy(_hypShareText);
  const orig = btn.textContent;
  btn.textContent = 'Copied';
  setTimeout(()=>{ btn.textContent = orig; }, 1500);
}
function copyOneHypothesisReport(id, btn){
  const h = getHypotheses().find(x=>x.id===id);
  if(!h) return;
  copy(formatHypothesisText(h));
  if(btn){ const orig=btn.textContent; btn.textContent='Copied'; setTimeout(()=>{btn.textContent=orig;},1500); }
}
function copyFullHypothesisReport(btn){
  const list = getHypotheses();
  if(!list.length){ showAlert('error','No hypotheses saved yet'); return; }
  const text = list.map(formatHypothesisText).join('\\n\\n'+'='.repeat(60)+'\\n\\n');
  copy(text);
  if(btn){ const orig=btn.textContent; btn.textContent='Copied'; setTimeout(()=>{btn.textContent=orig;},1500); }
}
function renderHypothesisReport(){
  const el = document.getElementById('hypReportList');
  if(!el) return;
  const list = getHypotheses();
  if(!list.length){ el.innerHTML = '<div style="color:var(--text2);font-size:12px;padding:8px;">No hypotheses saved yet — build one in Hypothesis Builder.</div>'; return; }
  const row = (label,val) => val ? '<div style="margin-bottom:5px;"><span style="color:var(--accent);font-weight:700;">'+label+':</span> <span style="color:var(--text);">'+escHtml(val)+'</span></div>' : '';
  el.innerHTML = list.map(h =>
    '<div class="panel" style="margin-bottom:10px;">'+
      '<div class="panel-header"><span>Hypothesis — '+new Date(h.created).toLocaleString()+'</span>'+
        '<button class="hc-toggle" style="margin-left:auto;font-size:10px;padding:2px 8px;" onclick="copyOneHypothesisReport('+h.id+',this)"><span>Copy</span></button>'+
      '</div>'+
      '<div class="panel-body" style="font-size:12px;">'+
        row('What', h.what)+row('Why', h.why)+row('Who', h.who)+row('When', h.when)+row('Where', h.where)+row('Testable/Measurable', h.testable)+
        ttpChipsBlock(h)+
      '</div>'+
    '</div>'
  ).join('');
}
function renderHypothesesList(){
  populateHypActorSelect();
  const el = document.getElementById('hypothesesList');
  if(!el) return;
  const list = getHypotheses();
  if(!list.length){ el.innerHTML = '<div style="color:var(--text2);font-size:12px;padding:8px;">No hypotheses saved yet.</div>'; return; }
  const row = (label,val) => val ? '<div style="margin-bottom:5px;"><span style="color:var(--accent);font-weight:700;">'+label+':</span> <span style="color:var(--text);">'+escHtml(val)+'</span></div>' : '';
  el.innerHTML = list.map(h => {
    return '<div class="panel" style="margin-bottom:10px;">'+
      '<div class="panel-header">Hypothesis — '+new Date(h.created).toLocaleString()+
        (h.sample ? ' <span style="font-size:9px;font-weight:700;color:var(--yellow);border:1px solid var(--yellow);border-radius:3px;padding:1px 5px;margin-left:6px;">SAMPLE</span>' : '')+
        '<button class="hc-toggle" style="margin-left:auto;font-size:10px;padding:2px 8px;--hc-primary:var(--red);" onclick="deleteHypothesis('+h.id+')"><span>Delete</span></button>'+
      '</div>'+
      '<div class="panel-body" style="font-size:12px;">'+
        row('What', h.what)+row('Why', h.why)+row('Who', h.who)+row('When', h.when)+row('Where', h.where)+row('Testable/Measurable', h.testable)+
        ttpChipsBlock(h)+
      '</div>'+
    '</div>';
  }).join('');
}

const API = '';
const PAGE_SIZE = 100;
let currentPage = 0;
let selectedIOCIds = new Set();
let huntOverrideTypes = null; // set when "Hunt Selected" is clicked

function getToken(){return localStorage.getItem('ioc_token')||'';}
function setToken(t){localStorage.setItem('ioc_token',t);}
async function api(path, opts={}, _retry=false) {
  const headers={...(opts.headers||{})};
  const tok=getToken();
  if(tok) headers['Authorization']='Bearer '+tok;
  const timeoutMs = opts.timeoutMs || 30000;
  const ctrl = new AbortController();
  const timer = setTimeout(()=>ctrl.abort(), timeoutMs);
  let r;
  try {
    r = await fetch(API+path,{...opts,headers,signal:ctrl.signal});
  } catch(e){
    clearTimeout(timer);
    if(e && e.name==='AbortError') return {error:'Request timed out after '+(timeoutMs/1000)+'s'};
    return {error:'Network error: '+(e && e.message ? e.message : String(e))};
  }
  clearTimeout(timer);
  if(r.status===401&&!_retry){
    const t=prompt('IOC Platform — enter access token:');
    if(t){setToken(t);return api(path,opts,true);}
    return {error:'Authentication required'};
  }
  const ct = r.headers.get('content-type')||'';
  if(!ct.includes('application/json')){
    const text = await r.text();
    return {error: 'Server error ('+r.status+'): '+text.slice(0,120)};
  }
  return r.json();
}

function escHtml(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');}
function copy(t){navigator.clipboard.writeText(t);}

function setTheme(name){
  document.documentElement.setAttribute('data-theme', name);
  try{ localStorage.setItem('lth_theme', name); }catch(e){}
  syncHCButton();
}
// High Contrast — puts the original near-black background back (see the
// :root.high-contrast CSS rules, one per dark theme, none for "eww" so it's
// a deliberate no-op there).
function toggleHighContrast(){
  const wasOn = document.documentElement.classList.contains('high-contrast');
  const on = document.documentElement.classList.toggle('high-contrast');
  try{ localStorage.setItem('lth_high_contrast', on ? '1' : '0'); }catch(e){}
  syncHCButton(wasOn && !on);
}
function syncHCButton(instant){
  const btn = document.getElementById('hcToggle');
  if(!btn) return;
  const isEww = document.documentElement.getAttribute('data-theme') === 'eww';
  const on = document.documentElement.classList.contains('high-contrast');
  btn.disabled = isEww;
  // .hc-toggle (same system every other button uses): dull/idle until
  // hovered, or .active when genuinely toggled on — not the old plain
  // .secondary button, which looked "lit up" at rest even when off.
  if(instant){
    // Turning off must snap straight to the dull idle look, matching the
    // other buttons at rest — not fade through it. .hc-instant (CSS class,
    // reaches the ::before/::after glitch overlay too, unlike inline
    // styles on the button itself) kills both independently-timed effects
    // (the .15s background/color transition and the .3s glitch animation)
    // so the class removal is instant instead of visibly out of sync.
    btn.classList.add('hc-instant');
    btn.classList.remove('active');
    void btn.offsetWidth;
    btn.classList.remove('hc-instant');
  } else {
    btn.classList.toggle('active', on && !isEww);
  }
}
// Sync the picker/HC button to whatever the early <head> script already
// applied, so they don't just default back after a reload.
(function(){
  const picker = document.getElementById('themePicker');
  if(picker) picker.value = document.documentElement.getAttribute('data-theme') || '1337';
  syncHCButton();
})();

// Non-destructive refresh: reloads the top stat boxes, IOC List table, and
// sidebar type/source counts — WITHOUT clearing the in-progress Hunt Builder
// or Analyst working lists (unlike the full refresh() below, which is only
// for the explicit "⟳ Refresh" button / a full page reset).
function refreshIOCData(){ loadStats(); loadTypeNav(); if(navMode==='source')loadSourceNav(); loadIOCs(); }

function refresh(){huntIOCs=[];analystIOCs=[];_descText='';updateHuntBlocks();updateAnalystBlocks();refreshIOCData();loadFeeds();}

// ══════════════════ STATS BAR ══════════════════
async function loadStats(){
  const s = await api('/api/stats');
  const bar = document.getElementById('statsBar');
  const total = s.total ?? 0;
  const mal = s['class:malicious']??0, sus = s['class:suspicious']??0;
  const ign = s.ignored ?? 0;
  const ignStat = ign ? \`<div class="stat" style="opacity:.6;cursor:pointer;" onclick="showIgnoredList()"><div class="n" style="color:var(--yellow)">\${ign}</div><div class="label">Ignored</div></div>\` : '';
  bar.innerHTML=\`
    <div class="stat" onclick="filterByClass('')"><div class="n">\${total.toLocaleString()}</div><div class="label">Total</div></div>
    <div class="stat red" onclick="filterByClass('malicious')"><div class="n">\${mal}</div><div class="label">Malicious</div></div>
    <div class="stat yellow" onclick="filterByClass('suspicious')"><div class="n">\${sus}</div><div class="label">Suspicious</div></div>
    \${ignStat}
    <div class="stat" onclick="filterByType('ip')"><div class="n">\${(s['type:ip']??0).toLocaleString()}</div><div class="label">IPs</div></div>
    <div class="stat" onclick="filterByType('domain')"><div class="n">\${s['type:domain']??0}</div><div class="label">Domains</div></div>
    <div class="stat" onclick="filterByType('sha256,sha1,md5')"><div class="n">\${(s['type:sha256']??0)+(s['type:sha1']??0)+(s['type:md5']??0)}</div><div class="label">Hashes</div></div>
    <div class="stat" onclick="filterByType('url')"><div class="n">\${s['type:url']??0}</div><div class="label">URLs</div></div>
    <div class="stat" onclick="filterByType('email')"><div class="n">\${s['type:email']??0}</div><div class="label">Emails</div></div>
    <div class="stat" onclick="filterByType('cve')"><div class="n">\${s['type:cve']??0}</div><div class="label">CVEs</div></div>
    <div class="stat" onclick="filterByType('filename')"><div class="n">\${s['type:filename']??0}</div><div class="label">Files</div></div>
  \`;
}

function showIgnoredList(){
  activeSourceUrl=undefined;
  document.getElementById('showIgnored').checked=true;
  document.getElementById('typeFilter').value='';
  document.getElementById('classFilter').value='';
  currentPage=0; showTab('iocs'); loadIOCs();
}

function filterByClass(cls){
  activeSourceUrl=undefined;
  document.getElementById('classFilter').value=cls;
  document.getElementById('typeFilter').value='';
  currentPage=0; showTab('iocs'); loadIOCs();
}
function filterByType(t){
  activeSourceUrl=undefined;
  document.getElementById('typeFilter').value=t;
  currentPage=0; showTab('iocs'); loadIOCs();
}

// ══════════════════ SIDEBAR NAV ══════════════════
const NAV_SECTIONS = [
  {key:'ip',      label:'IP Addresses',  icon:'🌐', types:['ip','ipv6']},
  {key:'hash',    label:'File Hashes',   icon:'#',  types:['sha256','sha1','md5']},
  {key:'domain',  label:'Domains',       icon:'🔗', types:['domain']},
  {key:'url',     label:'URLs',          icon:'🌍', types:['url']},
  {key:'filename',label:'File Names',    icon:'📄', types:['filename']},
  {key:'email',   label:'Emails',        icon:'✉',  types:['email']},
  {key:'cve',     label:'CVEs',          icon:'⚠',  types:['cve']},
  {key:'registry',label:'Registry Keys', icon:'🗝',  types:['registry_key']},
  {key:'hostname',label:'Hostnames',     icon:'💻', types:['hostname']},
];

const PLAYBOOKS = {
  ip: {title:'IP Address Playbook', steps:[
    {n:'1',t:'Check AbuseIPDB — click "Check Abuse" in Analyst View'},
    {n:'2',t:'Check VirusTotal — click "VT" link'},
    {n:'3',t:'Look up ASN/org: is it known bulletproof hosting?'},
    {n:'4',t:'Search SIEM: <code>src_ip=&lt;ip&gt; OR dst_ip=&lt;ip&gt;</code>'},
    {n:'5',t:"Check if it's a TOR exit node or VPN endpoint"},
    {n:'6',t:'Block at perimeter if confidence ≥ 70%'},
  ]},
  hash: {title:'File Hash Playbook', steps:[
    {n:'1',t:'Search VirusTotal — click VT link for detection ratio'},
    {n:'2',t:'Check ANY.RUN or Hybrid Analysis for sandbox report'},
    {n:'3',t:'Search SIEM: <code>sha256=&lt;hash&gt;</code> across endpoints'},
    {n:'4',t:'Extract malware family name from VT classification'},
    {n:'5',t:'Add hash to EDR custom IOC block list'},
    {n:'6',t:'Pivot: find other files with same compile timestamp'},
  ]},
  domain: {title:'Domain Playbook', steps:[
    {n:'1',t:'Check VirusTotal for category/detection'},
    {n:'2',t:'Run WHOIS — new domain (&lt;30 days) = red flag'},
    {n:'3',t:'DNS lookup: what IP does it resolve to?'},
    {n:'4',t:'Check for DGA pattern: high consonant ratio, random chars'},
    {n:'5',t:'Search DNS logs: <code>query=&lt;domain&gt;</code>'},
    {n:'6',t:'Add to DNS sinkhole / RPZ if confirmed malicious'},
  ]},
  url: {title:'URL Playbook', steps:[
    {n:'1',t:'Submit to VirusTotal URL scan'},
    {n:'2',t:'Extract domain and check separately'},
    {n:'3',t:'Look for phishing patterns: login/update/secure in path'},
    {n:'4',t:'Search web proxy logs for access'},
    {n:'5',t:'Block in web proxy/NGFW URL filter'},
  ]},
  filename: {title:'Filename Playbook', steps:[
    {n:'1',t:'Search endpoint logs for process creation with this name'},
    {n:'2',t:'Check if signed: <code>Get-AuthenticodeSignature &lt;file&gt;</code>'},
    {n:'3',t:'Look for LOLBin abuse: certutil, mshta, regsvr32, wscript'},
    {n:'4',t:'Hash the file and check VirusTotal'},
    {n:'5',t:'Check parent process — what spawned this?'},
    {n:'6',t:'Check file path — temp dirs = high suspicion'},
  ]},
  email: {title:'Email Playbook', steps:[
    {n:'1',t:'Extract sender domain and check reputation'},
    {n:'2',t:'Check SPF/DKIM/DMARC alignment'},
    {n:'3',t:'Search email gateway for messages from this sender'},
    {n:'4',t:'Quarantine any matching emails'},
    {n:'5',t:'Check if target users clicked any links'},
    {n:'6',t:'Block sender address + domain in mail gateway'},
  ]},
  cve: {title:'CVE Playbook', steps:[
    {n:'1',t:'Look up CVE on NVD: <a href="https://nvd.nist.gov/vuln/search" target="_blank">nvd.nist.gov</a>'},
    {n:'2',t:'Check CVSS score — ≥9.0 = critical, patch ASAP'},
    {n:'3',t:'Check ExploitDB / Metasploit for public exploit'},
    {n:'4',t:'Identify affected systems in asset inventory'},
    {n:'5',t:'Enable IDS signatures for exploitation attempts'},
    {n:'6',t:'Track patch deployment timeline'},
  ]},
  registry: {title:'Registry Key Playbook', steps:[
    {n:'1',t:'Identify persistence mechanism: Run/RunOnce/Services/Tasks'},
    {n:'2',t:'Enable Windows Event ID 12/13/14 if not active'},
    {n:'3',t:'Search SIEM: <code>TargetObject=&lt;key&gt;</code>'},
    {n:'4',t:'Check Sysinternals Autoruns for active entries'},
    {n:'5',t:'Alert on creation via Sysmon or EDR rule'},
    {n:'6',t:'Document baseline value for comparison'},
  ]},
  hostname: {title:'Hostname Playbook', steps:[
    {n:'1',t:'Resolve hostname to IP and check IP reputation'},
    {n:'2',t:'Check if it exists in internal asset inventory'},
    {n:'3',t:'If external: search for C2 infrastructure patterns'},
    {n:'4',t:'Search DNS logs for resolution attempts'},
    {n:'5',t:'Pivot to other IOCs associated with same infrastructure'},
  ]},
};

let activeNavKey = null;
let navMode = 'type';
let typeSubFilter = 'all'; // 'all' | 'feed' | 'hunt'

function setNavMode(mode){
  navMode = mode;
  // Solid accent fill for "selected", matching the convention every other
  // selected/active pill in the app uses (hunt-preset, type filters,
  // .hc-toggle.active) — this one used to be dark-bg+green-text instead,
  // which read as far less visible/clear than everywhere else.
  const BTN_ACTIVE   = {background:'var(--accent)', color:'var(--bg)', fontWeight:'700'};
  const BTN_INACTIVE = {background:'var(--bg2)', color:'var(--text2)',  fontWeight:''};
  ['Hunt','Type','Source'].forEach(n => {
    const btn = document.getElementById('navBtn'+n);
    if(!btn) return;
    const s = (n.toLowerCase() === mode) ? BTN_ACTIVE : BTN_INACTIVE;
    Object.assign(btn.style, s);
  });
  document.getElementById('iocNavHunt').style.display   = mode==='hunt'   ? '' : 'none';
  document.getElementById('iocNavType').style.display   = mode==='type'   ? '' : 'none';
  document.getElementById('iocNavSource').style.display = mode==='source' ? '' : 'none';
  document.getElementById('typeNavSubPills').style.display = mode==='type' ? '' : 'none';
  if(mode==='source') loadSourceNav();
  if(mode==='type')   loadTypeNav();
  if(mode==='hunt')   loadHuntNav();
}

function setTypeSubFilter(f){
  typeSubFilter = f;
  ['all','feed','hunt'].forEach(id => {
    const btn = document.getElementById('typePill'+id.charAt(0).toUpperCase()+id.slice(1));
    if(!btn) return;
    const active = id === f;
    btn.style.background   = active ? 'var(--accent)' : '';
    btn.style.color        = active ? 'var(--bg)'     : '';
    btn.style.borderColor  = active ? 'var(--accent)' : '';
  });
  loadTypeNav();
}

function loadHuntNav(){
  const nav = document.getElementById('iocNavHunt');
  if(!nav) return;
  if(!huntIOCs.length){
    nav.innerHTML='<div style="padding:12px;color:var(--text2);font-size:11px;">No IOCs in current hunt.</div>';
    return;
  }
  const TYPE_ORDER = ['ip','ipv6','domain','url','sha256','sha1','md5','email','cve','filename','registry_key','hostname'];
  const groups = {};
  for(const ioc of huntIOCs){ if(!groups[ioc.type]) groups[ioc.type]=[]; groups[ioc.type].push(ioc.value); }
  const sortedTypes = [...TYPE_ORDER.filter(t=>groups[t]), ...Object.keys(groups).filter(t=>!TYPE_ORDER.includes(t))];
  nav.innerHTML = sortedTypes.map(type => \`
    <div style="margin-bottom:6px;padding:6px 10px;border-bottom:1px solid var(--border);">
      <div style="font-size:10px;color:var(--purple);font-weight:700;text-transform:uppercase;margin-bottom:3px;">\${TYPE_ICONS[type]||'•'} \${type} (\${groups[type].length})</div>
      \${groups[type].map(val => \`
        <div style="display:flex;align-items:center;gap:5px;padding:2px 4px;border-radius:3px;background:var(--bg3);margin-bottom:2px;font-size:11px;">
          <span style="font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(val)}">\${escHtml(val)}</span>
          <span style="color:var(--red);cursor:pointer;padding:0 4px;font-weight:700;font-size:13px;" onclick="huntRemoveIOC(\${escHtml(JSON.stringify(val))})">×</span>
        </div>
      \`).join('')}
    </div>
  \`).join('');
}

const SRC_ICONS = {scraper:'📡', manual:'🖊', file:'📂', feed:'📥'};
let _srcNavData = [];

// Active source filter — undefined=off, string=filter by sourceUrl, ''=null sourceUrl (manual/file)
let activeSourceUrl = undefined;

async function loadSourceNav(){
  const sources = await api('/api/stats/by-source');
  _srcNavData = sources;
  const nav = document.getElementById('iocNavSource');
  if(!sources.length){nav.innerHTML='<div style="padding:12px;color:var(--text2);font-size:11px;">No data</div>';return;}
  nav.innerHTML = sources.map((s, idx) => {
    const icon = SRC_ICONS[s.source] || '•';
    const typePills = Object.entries(s.byType).map(([t,n])=>
      \`<span class="feed-type-pill" style="cursor:pointer;" onclick="event.stopPropagation();srcTypeFilter(\${idx},'\${t}')">\${TYPE_ICONS[t]||'•'} \${t} <strong style="color:var(--text);">\${n}</strong></span>\`
    ).join('');
    return \`
      <div class="nav-section">
        <div class="nav-section-header" onclick="srcNavFilter(\${idx})">
          <span class="nav-icon">\${icon}</span>
          <span class="nav-label" style="font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(s.label)}">\${escHtml(s.label)}</span>
          <span class="nav-count">\${s.count.toLocaleString()}</span>
          <span id="srcchev-\${idx}" style="font-size:9px;color:var(--accent);padding:0 5px;cursor:pointer;flex-shrink:0;" onclick="event.stopPropagation();toggleSourceSection(\${idx})">▶</span>
        </div>
        <div id="srcbody-\${idx}" style="display:none;padding:3px 10px 8px 38px;">
          <div style="display:flex;flex-wrap:wrap;gap:3px;margin-bottom:5px;">\${typePills}</div>
        </div>
      </div>\`;
  }).join('');

  // Populate feed URL filter dropdown too
  const sel = document.getElementById('feedUrlFilter');
  if(sel){
    const opts = sources.filter(s=>s.sourceUrl).map(s=>
      \`<option value="\${escHtml(s.sourceUrl)}">\${escHtml(s.sourceUrl.replace(/^https?:\\/\\//,'').slice(0,55))}</option>\`
    ).join('');
    sel.innerHTML = '<option value="">All Feeds</option>' + opts;
  }
}

function srcNavFilter(idx){
  const s = _srcNavData[idx];
  if(!s) return;
  activeSourceUrl = s.sourceUrl ?? '';
  document.getElementById('typeFilter').value = '';
  document.getElementById('classFilter').value = '';
  document.getElementById('searchInput').value = '';
  currentPage = 0; showTab('iocs'); loadIOCs();
}

function srcTypeFilter(idx, type){
  const s = _srcNavData[idx];
  if(!s) return;
  activeSourceUrl = s.sourceUrl ?? '';
  document.getElementById('typeFilter').value = type;
  document.getElementById('classFilter').value = '';
  document.getElementById('searchInput').value = '';
  currentPage = 0; showTab('iocs'); loadIOCs();
}

async function toggleSourceSection(idx){
  const body = document.getElementById('srcbody-'+idx);
  const chev = document.getElementById('srcchev-'+idx);
  if(!body || !chev) return;
  const open = body.style.display === 'none';
  body.style.display = open ? '' : 'none';
  chev.textContent = open ? '▼' : '▶';
  if(!open || body.dataset.loaded) return;

  // type pills already in body from render — append loading indicator below them
  const pillsDiv = body.querySelector('div');
  const loadEl = document.createElement('div');
  loadEl.style.cssText = 'color:var(--text2);font-size:10px;padding:3px 0;';
  loadEl.textContent = 'Loading…';
  body.appendChild(loadEl);

  const s = _srcNavData[idx];
  const qs = new URLSearchParams();
  qs.set('sourceUrl', s.sourceUrl ?? '');
  qs.set('limit','30');
  const data = await api('/api/iocs?'+qs);
  body.removeChild(loadEl);

  const iocs = data.iocs || [];
  if(!iocs.length){ body.dataset.loaded='1'; return; }

  const rows = iocs.map(ioc => {
    const cls = ioc.classification;
    const clsColor = cls==='malicious'?'var(--red)':cls==='suspicious'?'var(--yellow)':'var(--text2)';
    return \`<div style="padding:2px 0;display:flex;align-items:center;gap:5px;font-size:10px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.03);" onclick="srcTypeFilter(\${idx},\${escHtml(JSON.stringify(ioc.type))})">
      <span style="color:var(--purple);font-size:8px;font-weight:700;min-width:44px;text-transform:uppercase;">\${escHtml(ioc.type)}</span>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;color:var(--text);">\${escHtml(ioc.value)}</span>
      <span style="color:\${clsColor};font-size:8px;font-weight:700;">\${cls.slice(0,3).toUpperCase()}</span>
    </div>\`;
  }).join('');
  const more = data.total > 30
    ? \`<div style="font-size:10px;color:var(--accent);cursor:pointer;padding:4px 0;margin-top:2px;" onclick="srcNavFilter(\${idx})">→ View all \${data.total.toLocaleString()}</div>\`
    : '';
  const iocDiv = document.createElement('div');
  iocDiv.innerHTML = rows + more;
  body.appendChild(iocDiv);
  body.dataset.loaded = '1';
}

function applyFeedFilter(){
  const val = document.getElementById('feedUrlFilter').value;
  activeSourceUrl = val === '' ? undefined : val;
  currentPage = 0; loadIOCs();
}

async function loadTypeNav(){
  const nav = document.getElementById('iocNavType');
  if(!nav) return;

  // Hunt sub-filter: client-side counts from huntIOCs
  if(typeSubFilter === 'hunt'){
    const byType = {};
    for(const ioc of huntIOCs){ byType[ioc.type]=(byType[ioc.type]||0)+1; }
    nav.innerHTML = NAV_SECTIONS.map(s => {
      const total = s.types.reduce((acc,t)=>acc+(byType[t]||0),0);
      if(!total) return '';
      return \`
        <div class="nav-section" onclick="setNavMode('hunt')" title="Click to view Hunt tab">
          <div class="nav-section-header">
            <span class="nav-icon">\${s.icon}</span>
            <span class="nav-label">\${s.label}</span>
            <span class="nav-count">\${total}</span>
          </div>
        </div>\`;
    }).join('') || '<div style="padding:12px;color:var(--text2);font-size:11px;">No IOCs in current hunt.</div>';
    return;
  }

  const qs = typeSubFilter==='feed' ? '?source=scraper' : '';
  const bt = await api('/api/stats/by-type'+qs);
  nav.innerHTML = NAV_SECTIONS.map(s => {
    const counts = s.types.reduce((acc, t) => {
      const d = bt[t] ?? {total:0,malicious:0,suspicious:0};
      acc.total += d.total; acc.malicious += d.malicious; acc.suspicious += d.suspicious;
      return acc;
    }, {total:0,malicious:0,suspicious:0});

    const mal = counts.malicious > 0 ? \`<span class="pill m" onclick="navFilter('\${s.key}','malicious',event)">\${counts.malicious} mal</span>\` : '';
    const sus = counts.suspicious > 0 ? \`<span class="pill s" onclick="navFilter('\${s.key}','suspicious',event)">\${counts.suspicious} sus</span>\` : '';
    const pills = (mal || sus) ? \`<div class="nav-threat">\${mal}\${sus}</div>\` : '';

    return \`
      <div class="nav-section\${activeNavKey===s.key?' active':''}" onclick="navFilter('\${s.key}','',null)">
        <div class="nav-section-header">
          <span class="nav-icon">\${s.icon}</span>
          <span class="nav-label">\${s.label}</span>
          <span class="nav-count">\${counts.total.toLocaleString()}</span>
        </div>
        \${pills}
      </div>\`;
  }).join('');
}

function navFilter(key, cls, event){
  if(event) event.stopPropagation();
  activeNavKey = key;
  activeSourceUrl = undefined;
  const section = NAV_SECTIONS.find(s=>s.key===key);
  if(!section) return;

  // Show playbook
  const pb = PLAYBOOKS[key] ?? PLAYBOOKS[section.types[0]];
  if(pb){
    document.getElementById('playbook').style.display='';
    document.getElementById('playbookTitle').textContent = pb.title;
    document.getElementById('playbookSteps').innerHTML = pb.steps.map(step=>
      \`<div class="playbook-step"><span class="num">\${step.n}</span><span class="txt">\${step.t}</span></div>\`
    ).join('');
  }

  // Apply source filter when Feed pill active
  const srcEl = document.getElementById('sourceTypeFilter');
  if(srcEl) srcEl.value = typeSubFilter==='feed' ? 'scraper' : '';

  // Set type filter & navigate to IOC list
  document.getElementById('typeFilter').value = section.types.join(',');
  document.getElementById('classFilter').value = cls;
  currentPage = 0;
  showTab('iocs');
  loadIOCs();
  loadTypeNav();
}

// ══════════════════ IOC LIST ══════════════════
let _iocListCache = null; // last-loaded {iocs, total} — mutated in place by
                           // ignoreOne/enrichOne so a just-acted-on row can
                           // stay visible and show its new state, instead of
                           // a full reload re-applying filters (ignored=0,
                           // a classification filter, etc.) and yanking the
                           // row out of view right after you acted on it.

async function loadIOCs(){
  const search = document.getElementById('searchInput').value;
  const type   = document.getElementById('typeFilter').value;
  const cls    = document.getElementById('classFilter').value;
  const srcType = document.getElementById('sourceTypeFilter')?.value ?? '';
  const qs = new URLSearchParams();
  if(search)   qs.set('search',search);
  if(type)     qs.set('type',type);
  if(cls)      qs.set('classification',cls);
  if(srcType)  qs.set('source',srcType);
  if(activeSourceUrl !== undefined) qs.set('sourceUrl', activeSourceUrl);
  const showIgnored = document.getElementById('showIgnored')?.checked;
  if(showIgnored) qs.set('includeIgnored','1');
  document.getElementById('restoreAllBtn').style.display = showIgnored ? '' : 'none';
  qs.set('limit',PAGE_SIZE);
  qs.set('offset',currentPage*PAGE_SIZE);

  let data;
  try { data = await api('/api/iocs?'+qs); } catch(e) { data = {error:String(e)}; }
  const tbody = document.getElementById('iocTable');

  if(data.error){
    tbody.innerHTML=\`<tr><td colspan="9" class="loading" style="color:var(--red);">Failed to load IOCs. <button class="hc-toggle" style="font-size:10px;padding:1px 6px;margin-left:6px;" onclick="loadIOCs()"><span>↻ Retry</span></button></td></tr>\`;
    document.getElementById('paginationBar').innerHTML='';
    return;
  }
  _iocListCache = data;
  renderIOCTable();
}

function renderIOCTable(){
  const data = _iocListCache;
  const tbody = document.getElementById('iocTable');
  if(!data || !data.iocs?.length){
    tbody.innerHTML='<tr><td colspan="9" class="loading">No IOCs found.</td></tr>';
    document.getElementById('paginationBar').innerHTML='';
    return;
  }

  const totalPages = Math.ceil(data.total/PAGE_SIZE);
  document.getElementById('paginationBar').innerHTML=\`
    <button class="hc-toggle" onclick="currentPage=Math.max(0,currentPage-1);loadIOCs()" \${currentPage===0?'disabled':''}><span>← Prev</span></button>
    <span>Page \${currentPage+1} / \${totalPages} &nbsp;·&nbsp; \${data.total.toLocaleString()} total</span>
    <button class="hc-toggle" onclick="currentPage=Math.min(\${totalPages-1},currentPage+1);loadIOCs()" \${currentPage>=totalPages-1?'disabled':''}><span>Next →</span></button>
  \`;

  tbody.innerHTML = data.iocs.map(ioc => {
    const chk = selectedIOCIds.has(ioc.id) ? 'checked' : '';
    const score = ioc.enrichment?.reputationScore;
    const scoreHtml = score!=null ? scoreBar(score) : '—';
    const srcLink = ioc.sourceUrl
      ? \` <a href="\${escHtml(ioc.sourceUrl)}" target="_blank" style="color:var(--accent);font-size:9px">↗</a>\` : '';
    const isIgnored = ioc.ignored === true;
    const scraperStyle = ioc.source === 'scraper' ? 'background:rgba(120,40,200,0.18);border-left:3px solid #7c3aed;' : '';
    const ignoredStyle = isIgnored ? 'opacity:0.45;' : '';
    const rowStyle = scraperStyle + ignoredStyle;
    return \`<tr style="\${rowStyle}">
      <td><input type="checkbox" \${chk} onchange="toggleSelect('\${ioc.id}',this)"></td>
      <td class="val" title="\${escHtml(ioc.value)}">\${isIgnored?'<s>':''}\${escHtml(ioc.value)}\${isIgnored?'</s>':''}</td>
      <td><span class="badge type">\${escHtml(ioc.type)}</span></td>
      <td><span class="badge \${ioc.classification}">\${ioc.classification}</span></td>
      <td style="font-size:11px">\${escHtml(ioc.enrichment?.country??'—')}</td>
      <td style="font-size:11px">\${scoreHtml}</td>
      <td style="font-size:10px;color:\${ioc.source==='scraper'?'#a78bfa':'var(--text2)'}">\${ioc.source}\${srcLink}</td>
      <td style="font-size:10px;color:var(--text2)">\${ioc.extractedAt.split('T')[0]}</td>
      <td style="white-space:nowrap;">
        <button class="hc-toggle" style="font-size:10px;padding:2px 6px;" onclick="enrichOne('\${ioc.id}')"><span>Enrich</span></button>
        \${isIgnored
          ? \`<button class="hc-toggle" style="font-size:10px;padding:2px 6px;margin-left:3px;color:var(--green);border-color:var(--green);" onclick="ignoreOne('\${ioc.id}',false)"><span>↺</span></button>\`
          : \`<button class="hc-toggle" style="font-size:10px;padding:2px 6px;margin-left:3px;color:var(--yellow);border-color:var(--yellow);" onclick="ignoreOne('\${ioc.id}',true)"><span>Ignore</span></button>\`
        }
        \${huntFoundCheckbox(ioc.id, ioc.huntStatus)}
      </td>
    </tr>\`;
  }).join('');
  updateSelBar();
}

// Tri-state "found in environment" toggle: unset (○ Found?) -> found (✓ Found,
// green) -> not_found (✗ Not Found, red) -> back to unset. Click cycles state.
// Simple checkbox: checked = found, unchecked = not found. Always refreshes
// BOTH the IOC List and Enrichment tables regardless of which one is visible
// (whichever tab isn't showing just updates its hidden DOM harmlessly) —
// without this, toggling on one tab left the other's checkbox state stale
// until you switched tabs, which made repeated clicks look like they were
// "spreading" found-status to other rows (each stale click still persisted).
function huntFoundCheckbox(id, status){
  const checked = status === 'found' ? 'checked' : '';
  return \`<label style="display:inline-flex;align-items:center;gap:3px;font-size:11px;cursor:pointer;white-space:nowrap;" title="Mark whether this IOC was found in your environment">
    <input type="checkbox" \${checked} onchange="setFoundStatus('\${id}', this.checked)"> Found
  </label>\`;
}

async function setFoundStatus(id, isFound){
  await api('/api/iocs/annotate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,huntStatus:isFound?'found':'not_found'})});
  loadIOCs();
  loadEnrichmentTab();
  // Invalidate the IOC Description tab's cached report data — otherwise it
  // keeps showing whatever was true at page-load time (500ms prefetch) until
  // someone happens to click "↻ Reload" there.
  window._descBaseLines = null;
}

// ══════════════════ ENRICHMENT TAB ══════════════════
// Per-IOC analyst tracking: found/not-found (shared with the IOC List tab's
// button via the same annotateIOC API), a ticket/event reference (auto-linked
// when it looks like a URL), and an affected host.

function looksLikeUrl(s){ return /^https?:\\/\\//i.test(s||''); }

let _enrichIOCs = []; // cache of the last-loaded Enrichment tab rows, keyed by id below

async function loadEnrichmentTab(){
  const cls = document.getElementById('enrichClassFilter').value;
  const qs = new URLSearchParams({ limit: '1000' });
  if(cls) qs.set('classification', cls);
  let data;
  try { data = await api('/api/iocs?'+qs); } catch(e) { data = {error:String(e)}; }
  const tbody = document.getElementById('enrichmentTable');
  if(data.error){ tbody.innerHTML = '<tr><td colspan="4" class="loading" style="color:var(--red);">Failed to load IOCs.</td></tr>'; return; }
  if(!data.iocs?.length){ tbody.innerHTML = '<tr><td colspan="4" class="loading">No IOCs found.</td></tr>'; return; }

  _enrichIOCs = data.iocs;
  tbody.innerHTML = data.iocs.map(ioc => \`<tr>
      <td class="val" title="\${escHtml(ioc.value)}">\${escHtml(ioc.value)}</td>
      <td><span class="badge type">\${escHtml(ioc.type)}</span></td>
      <td>\${huntFoundCheckbox(ioc.id, ioc.huntStatus)}</td>
      <td><div id="tix-\${ioc.id}">\${renderTicketEntriesInner(ioc)}</div></td>
    </tr>\`).join('');
}

// Renders the ticket/host entry rows + "+ Add" button for one IOC. Always at
// least one (possibly blank) row so there's always something to type into.
function renderTicketEntriesInner(ioc){
  const entries = ioc.ticketEntries?.length ? ioc.ticketEntries : [{ticket:'',host:'',environment:''}];
  const rows = entries.map((e,idx) => {
    const linkIcon = looksLikeUrl(e.ticket)
      ? \` <a href="\${escHtml(e.ticket)}" target="_blank" title="Open ticket/event link" style="color:var(--accent);">↗</a>\`
      : '';
    const removeBtn = entries.length>1
      ? \`<span style="color:var(--red);cursor:pointer;padding:0 3px;font-weight:700;" onclick="removeTicketEntry('\${ioc.id}',\${idx})">×</span>\`
      : '';
    const envVal = escHtml(e.environment||'');
    return \`<div style="display:flex;gap:4px;align-items:center;margin-bottom:3px;">
      <input type="text" value="\${envVal}" placeholder="Environment" list="envNameOptions" style="width:120px;font-size:11px;" onchange="saveTicketEntries('\${ioc.id}')">
      <input type="text" value="\${escHtml(e.ticket)}" placeholder="TICKET-123 or URL" style="width:150px;font-size:11px;" onchange="saveTicketEntries('\${ioc.id}')">\${linkIcon}
      <input type="text" value="\${escHtml(e.host)}" placeholder="host / asset" style="width:130px;font-size:11px;" onchange="saveTicketEntries('\${ioc.id}')">
      \${removeBtn}
    </div>\`;
  }).join('');
  return rows + \`<button class="hc-toggle" style="font-size:10px;padding:1px 6px;" onclick="addTicketEntry('\${ioc.id}')"><span>+ Add ticket/host</span></button>\`;
}

function _findEnrichIOC(id){ return _enrichIOCs.find(i=>i.id===id); }

function addTicketEntry(id){
  const ioc = _findEnrichIOC(id);
  if(!ioc) return;
  if(!ioc.ticketEntries) ioc.ticketEntries = [];
  ioc.ticketEntries.push({ticket:'',host:'',environment:''});
  document.getElementById('tix-'+id).innerHTML = renderTicketEntriesInner(ioc);
}

async function removeTicketEntry(id, idx){
  const ioc = _findEnrichIOC(id);
  if(!ioc?.ticketEntries) return;
  ioc.ticketEntries.splice(idx,1);
  document.getElementById('tix-'+id).innerHTML = renderTicketEntriesInner(ioc);
  await api('/api/iocs/annotate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,ticketEntries:ioc.ticketEntries})});
  window._descBaseLines = null;
}

// Reads the current input values straight from the DOM (not the cache) so
// in-progress typing in other rows/entries isn't lost, and saves the whole
// entry list for this IOC in one call.
async function saveTicketEntries(id){
  const container = document.getElementById('tix-'+id);
  const rows = [...container.querySelectorAll(':scope > div')];
  const ticketEntries = rows.map(row => {
    const inputs = row.querySelectorAll('input');
    return {
      environment: inputs[0]?.value.trim() || '',
      ticket: inputs[1]?.value.trim() || '',
      host: inputs[2]?.value.trim() || '',
    };
  }).filter(e => e.ticket || e.host || e.environment);
  const ioc = _findEnrichIOC(id);
  if(ioc) ioc.ticketEntries = ticketEntries;
  await api('/api/iocs/annotate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,ticketEntries})});
  window._descBaseLines = null;
}

function scoreBar(s){
  const c = s>=70?'#f85149':s>=30?'#e3b341':'#3fb950';
  return \`<span style="color:\${c};font-weight:700">\${s}</span><span style="color:var(--text2);font-size:10px">/100</span>\`;
}

function toggleSelect(id, el){
  if(el.checked) selectedIOCIds.add(id); else selectedIOCIds.delete(id);
  updateSelBar();
}
function toggleSelectAll(){
  const checked = document.getElementById('selectAll').checked;
  document.querySelectorAll('#iocTable input[type=checkbox]').forEach(cb=>{
    const id = cb.closest('tr')?.querySelector('input[type=checkbox]');
    if(cb !== document.getElementById('selectAll')){
      cb.checked = checked;
      const row = cb.closest('tr');
      const rowId = row?.dataset?.id;
      // get ID from onclick
      const enBtn = row?.querySelector('button.secondary');
      if(enBtn){
        const m = enBtn.getAttribute('onclick')?.match(/'([^']+)'/);
        if(m) checked ? selectedIOCIds.add(m[1]) : selectedIOCIds.delete(m[1]);
      }
    }
  });
  updateSelBar();
}
function clearSelection(){
  selectedIOCIds.clear();
  document.querySelectorAll('#iocTable input[type=checkbox]').forEach(cb=>cb.checked=false);
  document.getElementById('selectAll').checked=false;
  updateSelBar();
}
function updateSelBar(){
  const bar = document.getElementById('selectionBar');
  const n = selectedIOCIds.size;
  if(n>0){
    bar.style.display='flex';
    document.getElementById('selCount').textContent=n+' IOC(s) selected';
  } else {
    bar.style.display='none';
  }
}
function huntSelected(){
  huntOverrideTypes = null;
  showTab('hunt');
  document.getElementById('huntResults').innerHTML='<div class="loading">Building queries for '+selectedIOCIds.size+' selected IOCs…</div>';
  buildHuntQueries(true);
}

async function huntAddAll(){
  const search = document.getElementById('searchInput').value;
  const type   = document.getElementById('typeFilter').value;
  const cls    = document.getElementById('classFilter').value;
  const srcType = document.getElementById('sourceTypeFilter')?.value ?? '';
  const qs = new URLSearchParams();
  if(search)   qs.set('search',search);
  if(type)     qs.set('type',type);
  if(cls)      qs.set('classification',cls);
  if(srcType)  qs.set('source',srcType);
  if(activeSourceUrl !== undefined) qs.set('sourceUrl', activeSourceUrl);
  qs.set('limit','2000');
  const data = await api('/api/iocs?'+qs);
  const iocs = data.iocs ?? [];
  if(!iocs.length){ showAlert('error','No IOCs to add'); return; }
  let added = 0;
  for(const ioc of iocs){
    if(huntIOCs.find(i=>i.value===ioc.value)) continue;
    huntIOCs.push({value:ioc.value, type:ioc.type});
    added++;
  }
  updateHuntBlocks();
  showAlert('success', \`Added \${added} IOC(s) to Hunt Builder (\${iocs.length - added} already present)\`);
  showTab('hunt');
}

async function enrichOne(id){
  showAlert('info','Enriching…');
  const vtKey=localStorage.getItem('lth_vt_key')||undefined;
  const abuseKey=localStorage.getItem('lth_abuse_key')||undefined;
  const d=await api('/api/enrich',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,vtKey,abuseKey})});
  if(d.error){showAlert('error',d.error);return;}
  showAlert('success','Enriched!');
  // Patch the row in place instead of reloading — a reload re-applies the
  // active classification filter, and enrichment can change classification
  // (e.g. unknown -> malicious), which would silently drop the row you just
  // acted on out of view.
  const cached = _iocListCache?.iocs?.find(i=>i.id===id);
  if(cached && d.ioc) Object.assign(cached, d.ioc);
  renderIOCTable();
  loadStats();
}
async function deleteOne(id){
  await api('/api/iocs',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  loadIOCs(); loadStats(); loadTypeNav();
}

async function ignoreOne(id, ignored){
  await api('/api/iocs/ignore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,ignored})});
  // Patch in place — a reload would re-apply the "hide ignored" filter
  // (default when "Show Ignored" isn't checked) and the row you just
  // ignored/restored would vanish immediately instead of showing its new
  // (dimmed / restored) state.
  const cached = _iocListCache?.iocs?.find(i=>i.id===id);
  if(cached) cached.ignored = ignored;
  renderIOCTable();
  loadStats(); loadTypeNav();
}

async function restoreAll(){
  const d = await api('/api/iocs/restore-all',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  showAlert('success',\`Restored \${d.restored} IOC(s)\`);
  loadIOCs(); loadStats(); loadTypeNav();
}

// ══════════════════ INGEST ══════════════════
function toggleIngest(){
  const body=document.getElementById('ingestBody');
  const chev=document.getElementById('ingestChevron');
  const show=body.style.display==='none';
  body.style.display=show?'':'none';
  chev.textContent=show?'▲':'▼';
}

async function ingestText(){
  const text=document.getElementById('pasteInput').value.trim();
  if(!text) return;
  const autoAdd=document.getElementById('autoAddHunt')?.checked;
  showAlert('info','Extracting…');
  // Extract-only — never saves to DB from Custom Hunt paste
  const d=await api('/api/extract/text',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
  if(d.error){showAlert('error',d.error);return;}
  showAlert('success',\`Found \${d.total} IOC(s)\${autoAdd?' — added to Hunt Builder':''}\`);
  if(d.iocs?.length) addToHuntFromIngest(d.iocs);
  // No refresh() — nothing was saved to DB
}
async function ingestURL(){
  const raw=document.getElementById('urlInput').value.trim();
  if(!raw) return;
  const autoAdd=document.getElementById('autoAddHunt')?.checked;
  const urls=raw.split(/\\n+/).map(u=>u.trim()).filter(u=>/^https?:\\/\\//i.test(u));
  if(!urls.length){showAlert('error','No valid URLs — must start with http(s)://');return;}
  showAlert('info',\`Scraping \${urls.length} URL(s)…\`);
  let total=0, inserted=0, failed=0;
  const allIOCs=[];
  for(const url of urls){
    const d=await api('/api/ingest/url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url,returnIOCs:autoAdd})});
    if(d.error) failed++;
    else { total+=d.total||0; inserted+=d.inserted||0; if(autoAdd&&d.iocs) allIOCs.push(...d.iocs); }
  }
  const failMsg=failed?\` (\${failed} failed)\`:'';
  showAlert(failed?'error':'success',\`Scraped \${urls.length-failed} URL(s)\${failMsg} — \${total} IOC(s), \${inserted} new\`);
  if(autoAdd&&allIOCs.length) addToHuntFromIngest(allIOCs);
  refresh();
}

async function addToHuntFromIngest(iocs){
  const newOnes=[];
  for(const {value,type} of iocs){
    if(!value||!type) continue;
    if(huntIOCs.find(i=>i.value===value)) continue;
    huntIOCs.push({value,type});
    newOnes.push({value,type});
  }
  updateHuntBlocks();
  if(newOnes.length){
    showAlert('success',\`Added \${newOnes.length} IOC(s) to Hunt Builder\`);
    // This path (sidebar "Auto-add to Hunt Builder") previously only ever
    // touched the in-memory huntIOCs array — it never reached the IOC DB,
    // so these never showed up in IOC List/Enrichment. Persist them too.
    try { await api('/api/iocs/add-manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iocs:newOnes})}); }
    catch(e) { console.error('Failed to persist hunt IOCs', e); }
    refreshIOCData();
  }
}
async function ingestFile(){
  const file=document.getElementById('fileInput').files[0];
  if(!file) return;
  showAlert('info','Parsing '+file.name+'…');
  const fd=new FormData(); fd.append('file',file);
  const d=await api('/api/ingest/file',{method:'POST',body:fd});
  if(d.error){showAlert('error',d.error);return;}
  showAlert('success',\`Parsed \${file.name} — \${d.total} IOC(s), \${d.inserted} new\`);
  refresh();
}

function showAlert(type, msg){
  const el = document.getElementById('ingestAlert');
  const colors={info:'var(--accent)',success:'var(--green)',error:'var(--red)'};
  el.style.color=colors[type]||'var(--text)';
  el.textContent=msg;
  clearTimeout(el._t);
  el._t=setTimeout(()=>el.textContent='',5000);
}

// ══════════════════ FEEDS ══════════════════
let feedsPanelOpen = true;

function toggleFeedsPanel(){
  feedsPanelOpen = !feedsPanelOpen;
  document.getElementById('feedsBody').style.display = feedsPanelOpen ? '' : 'none';
  document.getElementById('feedsPanelChev').textContent = feedsPanelOpen ? '▼' : '▶';
}

function toggleAddFeed(){
  const form = document.getElementById('feedAddForm');
  const isHidden = form.style.display==='none' || form.style.display==='';
  form.style.display = isHidden ? 'flex' : 'none';
  if(isHidden) document.getElementById('feedAddUrl').focus();
}

function getFeedDisabled(){
  try{ return new Set(JSON.parse(localStorage.getItem('feedDisabled')||'[]')); }
  catch{ return new Set(); }
}
function setFeedDisabledState(url, disabled){
  const s=getFeedDisabled();
  if(disabled) s.add(url); else s.delete(url);
  localStorage.setItem('feedDisabled',JSON.stringify([...s]));
}
// Feed subscriptions — per-device localStorage list
function getFeedSubs(){ try{ return JSON.parse(localStorage.getItem('lth_feeds_v1')||'[]'); } catch{ return []; } }
function saveFeedSubs(list){ localStorage.setItem('lth_feeds_v1', JSON.stringify(list)); }
function addFeedSub(url){ const s=getFeedSubs(); if(!s.includes(url)){ s.push(url); saveFeedSubs(s); } }
function removeFeedSub(url){ saveFeedSubs(getFeedSubs().filter(u=>u!==url)); }

const TYPE_ICONS = {ip:'🌐',ipv6:'🌐',domain:'🔗',url:'🌍',sha256:'#',sha1:'#',md5:'#',email:'✉',cve:'⚠',filename:'📄',registry_key:'🗝',hostname:'💻'};
const PLATFORM_VENDOR = {splunk:'Splunk',elastic:'Elastic',kql:'Microsoft Sentinel / Defender',cql:'CrowdStrike Falcon SIEM',s1ql:'SentinelOne Deep Visibility',wazuh:'Wazuh',tql:'Trellix ePO',sigma:'Sigma',yara:'YARA'};

async function addFeed(){
  const inp = document.getElementById('feedAddUrl');
  const status = document.getElementById('feedAddStatus');
  const url = inp.value.trim();
  if(!url) return;
  status.style.color='var(--text2)'; status.textContent='Importing…';
  const d = await api('/api/feeds/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  if(d.error){status.style.color='var(--red)';status.textContent=d.error;return;}
  addFeedSub(url); // save to this device's subscription list
  status.style.color='var(--green)'; status.textContent=\`✓ +\${d.inserted} new IOCs\`;
  inp.value='';
  setTimeout(()=>{status.textContent='';toggleAddFeed();},2000);
  refresh(); loadFeeds();
}

async function loadFeeds(){
  const subs = new Set(getFeedSubs());
  const allFeeds = await api('/api/feeds/iocs');
  // Only show feeds this device has subscribed to
  const feeds = Array.isArray(allFeeds) ? allFeeds.filter(f=>subs.has(f.url)) : [];
  const body = document.getElementById('feedsBody');
  const badge = document.getElementById('feedsTotalBadge');
  badge.textContent = feeds.length ? \`(\${feeds.length})\` : '';
  if(!feeds.length){
    body.innerHTML='<div style="padding:6px 14px;font-size:11px;color:var(--text2);">No feeds yet — click + Add Feed</div>';
    return;
  }
  const disabled = getFeedDisabled();
  body.innerHTML = feeds.map((f, idx) => {
    const short = f.url.replace(/^https?:\\/\\//, '').slice(0, 60);
    const age = f.lastSeen ? f.lastSeen.slice(0,10) : '?';
    const isPaused = disabled.has(f.url);
    const typePills = Object.entries(f.byType||{}).map(([t,n])=>
      \`<span class="feed-type-pill">\${TYPE_ICONS[t]||'•'} \${t} <strong style="color:var(--text);">\${n}</strong></span>\`
    ).join('');
    // Store URL in data attr to avoid JSON double-quote breaking onclick attributes
    const safeUrl = escHtml(f.url);
    return \`
      <div class="feed-section" id="fsec-\${idx}">
        <div class="feed-section-hdr\${isPaused?' disabled':''}" onclick="toggleFeedSection(\${idx})">
          <span id="fchev-\${idx}" style="font-size:10px;color:var(--text2);min-width:12px;">▶</span>
          <span style="color:\${isPaused?'var(--text2)':'var(--accent)'};flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${safeUrl}">\${escHtml(short)}</span>
          <span style="color:var(--text2);white-space:nowrap;">\${f.count.toLocaleString()} · \${age}</span>
          \${isPaused?'<span style="font-size:9px;color:var(--yellow);font-weight:700;padding:0 4px;">PAUSED</span>':''}
          <button class="hc-toggle" style="font-size:9px;padding:1px 5px;" title="\${isPaused?'Resume':'Pause'} feed"
            data-furl="\${safeUrl}" data-fidx="\${idx}"
            onclick="event.stopPropagation();toggleFeedPause(this.dataset.furl,parseInt(this.dataset.fidx),this)"><span>\${isPaused?'▶':'⏸'}</span></button>
          <button class="hc-toggle" style="font-size:9px;padding:1px 5px;"
            data-furl="\${safeUrl}"
            onclick="event.stopPropagation();updateFeed(this.dataset.furl,this)"><span>↻</span></button>
          <button class="hc-toggle" style="font-size:9px;padding:1px 5px;--hc-primary:var(--red);"
            data-furl="\${safeUrl}"
            onclick="event.stopPropagation();deleteFeed(this.dataset.furl,this)"><span>✕</span></button>
        </div>
        <div id="fbody-\${idx}" class="feed-ioc-body" style="display:none;">\${typePills||'<span style="color:var(--text2);font-size:10px;">No IOCs</span>'}</div>
      </div>\`;
  }).join('');
}

function toggleFeedSection(idx){
  const body = document.getElementById('fbody-'+idx);
  const chev = document.getElementById('fchev-'+idx);
  const open = body.style.display === 'none';
  body.style.display = open ? '' : 'none';
  chev.textContent = open ? '▼' : '▶';
}

function toggleFeedPause(url, idx, btn){
  const disabled = getFeedDisabled();
  const wasPaused = disabled.has(url);
  setFeedDisabledState(url, !wasPaused);
  // Re-render feeds
  loadFeeds();
}

async function updateFeed(url, btn){
  const disabled = getFeedDisabled();
  if(disabled.has(url)){showAlert('error','Feed is paused — resume it first');return;}
  btn.textContent='…'; btn.disabled=true;
  const d = await api('/api/feeds/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  btn.textContent='↻'; btn.disabled=false;
  showAlert('success',\`Feed updated: +\${d.inserted} new IOCs\`);
  refresh(); loadFeeds();
}

async function deleteFeed(url, btn){
  if(!confirm('Remove this feed and its IOCs?')) return;
  btn.disabled=true;
  await api('/api/feeds/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  removeFeedSub(url);
  setFeedDisabledState(url, false);
  showAlert('success','Feed removed');
  refresh(); loadFeeds();
}

// ══════════════════ IOC BLOCK HELPERS ══════════════════
function detectIOCType(val){
  val = val.trim();
  if(!val) return null;
  if(/^CVE-\\d{4}-\\d{4,}/i.test(val)) return 'cve';
  if(/^HKEY_/i.test(val)) return 'registry_key';
  if(/^[a-f0-9]{64}$/i.test(val)) return 'sha256';
  if(/^[a-f0-9]{40}$/i.test(val)) return 'sha1';
  if(/^[a-f0-9]{32}$/i.test(val)) return 'md5';
  if(/^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$/.test(val)) return 'email';
  if(/^https?:\\/\\//i.test(val)) return 'url';
  if(/^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$/.test(val)) return 'ip';
  if(/^(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}/.test(val)) return 'ipv6';
  if(/\\.(exe|dll|bat|ps1|vbs|js|jar|sh|py|php|hta|cmd|scr|msi|lnk|doc|docx|pdf|zip|rar)$/i.test(val)) return 'filename';
  if(/^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+$/.test(val)) return 'domain';
  return null;
}

function renderBlock(val, type, containerId, storeName){
  const safe = escHtml(val);
  const id = 'blk_' + Math.random().toString(36).slice(2);
  const el = document.createElement('span');
  el.className = 'ioc-block';
  el.id = id;
  el.innerHTML = \`<span class="ioc-type">\${type}</span><span class="ioc-val" title="\${safe}">\${safe}</span><span class="ioc-rm" onclick="removeBlock('\${id}','\${storeName}',\${escHtml(JSON.stringify(val))})">×</span>\`;
  return el;
}

function removeBlock(blockId, storeName, val){
  document.getElementById(blockId)?.remove();
  window[storeName] = window[storeName].filter(i=>i.value!==val);
  updateBlockUI(storeName);
}

function updateBlockUI(storeName){
  if(storeName==='huntIOCs') updateHuntBlocks();
  if(storeName==='analystIOCs') updateAnalystBlocks();
}

// ══════════════════ HUNT BUILDER ══════════════════
let huntMode = 'custom';
let huntIOCs = []; // {value, type}

// Repopulate the Hunt Builder working list from persisted manual-source
// IOCs on page load — huntIOCs is otherwise just an in-memory array that
// starts empty every time the script runs, so even though additions are
// saved to the database (add-manual), the "Current Hunt" box would still
// show empty on every reload without this.
async function rehydrateHuntFromDB(){
  let data;
  try { data = await api('/api/iocs?source=manual&limit=500'); } catch(e) { return; }
  if(!data?.iocs?.length) return;
  for(const ioc of data.iocs){
    if(!huntIOCs.find(h=>h.value===ioc.value)) huntIOCs.push({value:ioc.value, type:ioc.type});
  }
  updateHuntBlocks();
}

function setHuntMode(mode){
  huntMode = mode;
  const isCustom = mode==='custom';
  document.getElementById('huntModeCustom').style.borderColor = isCustom ? 'var(--accent)' : 'var(--border)';
  document.getElementById('huntModeCustom').style.color       = isCustom ? 'var(--accent)' : 'var(--text2)';
  document.getElementById('huntModeDB').style.borderColor     = !isCustom ? 'var(--accent)' : 'var(--border)';
  document.getElementById('huntModeDB').style.color           = !isCustom ? 'var(--accent)' : 'var(--text2)';
  document.getElementById('huntCustomControls').style.display = isCustom ? '' : 'none';
  document.getElementById('huntDbControls').style.display     = !isCustom ? '' : 'none';
}

function toggleHuntType(cb){
  cb.closest('label').classList.toggle('on',cb.checked);
}

async function huntAddOne(){
  const inp = document.getElementById('huntAddVal');
  const typeEl = document.getElementById('huntAddType');
  const val = inp.value.trim();
  if(!val) return;
  const type = typeEl.value==='auto' ? (detectIOCType(val)||'hostname') : typeEl.value;
  if(huntIOCs.find(i=>i.value===val)) { inp.value=''; return; }
  huntIOCs.push({value:val, type});
  inp.value='';
  updateHuntBlocks();
  // Persist to the IOC DB too, so it also shows up in IOC List / Enrichment.
  try { await api('/api/iocs/add-manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iocs:[{value:val,type}]})}); }
  catch(e) { console.error('Failed to persist hunt IOC', e); }
  refreshIOCData();
}

function updateHuntBlocks(){
  const container = document.getElementById('huntBlocks');
  const sidebar = document.getElementById('huntBlocksSidebar');
  const countEl = document.getElementById('huntBlockCount');
  const sidebarCount = document.getElementById('huntBlocksSidebarCount');
  if(!huntIOCs.length){
    const empty = '<span style="color:var(--text2);font-size:11px;">No IOCs added yet</span>';
    if(container) container.innerHTML=empty;
    if(sidebar) sidebar.innerHTML=empty;
    if(countEl) countEl.textContent='';
    if(sidebarCount) sidebarCount.textContent='';
    return;
  }
  const TYPE_ORDER = ['ip','ipv6','domain','url','sha256','sha1','md5','email','cve','filename','registry_key','hostname'];
  const groups = {};
  for(const ioc of huntIOCs){ if(!groups[ioc.type]) groups[ioc.type]=[]; groups[ioc.type].push(ioc.value); }
  const sortedTypes = [...TYPE_ORDER.filter(t=>groups[t]), ...Object.keys(groups).filter(t=>!TYPE_ORDER.includes(t))];
  const renderGroup = (type, bgColor) => \`
    <div style="margin-bottom:7px;">
      <div style="font-size:10px;color:var(--purple);font-weight:700;text-transform:uppercase;margin-bottom:3px;">\${TYPE_ICONS[type]||'•'} \${type} (\${groups[type].length})</div>
      \${groups[type].map(val => \`
        <div style="display:flex;align-items:center;gap:5px;padding:2px 6px;border-radius:3px;background:\${bgColor};margin-bottom:2px;font-size:11px;">
          <span style="font-family:monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(val)}">\${escHtml(val)}</span>
          <span style="color:var(--red);cursor:pointer;padding:0 4px;font-weight:700;font-size:13px;" onclick="huntRemoveIOC(\${escHtml(JSON.stringify(val))})">×</span>
        </div>
      \`).join('')}
    </div>
  \`;
  if(container) container.innerHTML = sortedTypes.map(t=>renderGroup(t,'var(--bg2)')).join('');
  if(sidebar) sidebar.innerHTML = sortedTypes.map(t=>renderGroup(t,'var(--bg2)')).join('');
  const byType = {};
  for(const i of huntIOCs) byType[i.type]=(byType[i.type]||0)+1;
  const summary = Object.entries(byType).map(([t,n])=>\`\${n} \${t}\`).join(', ');
  const countText = \`\${huntIOCs.length} IOC(s): \${summary}\`;
  if(countEl) countEl.textContent=countText;
  if(sidebarCount) sidebarCount.textContent=countText;
  // Keep Hunt nav tab and Hunt sub-pill in sync
  if(navMode==='hunt') loadHuntNav();
  if(navMode==='type' && typeSubFilter==='hunt') loadTypeNav();
}

function huntRemoveIOC(val){
  huntIOCs = huntIOCs.filter(i=>i.value!==val);
  updateHuntBlocks();
}

function huntClearBlocks(){
  huntIOCs=[];
  updateHuntBlocks();
}

function huntPastePreview(){
  const raw=document.getElementById('huntPasteInput').value;
  const lines=raw.split(/[\\n,;]+/).map(l=>l.trim()).filter(Boolean);
  let ok=0, skip=0;
  for(const l of lines){ detectIOCType(l)?ok++:skip++; }
  document.getElementById('huntPasteInfo').innerHTML =
    ok ? \`<span style="color:var(--green)">✓ \${ok} recognized</span>\${skip?'<span style="color:var(--yellow)"> · '+skip+' unrecognized</span>':''}\` : '';
}

async function huntPasteAdd(){
  const raw=document.getElementById('huntPasteInput').value;
  const lines=raw.split(/[\\n,;]+/).map(l=>l.trim()).filter(Boolean);
  const added=[];
  for(const l of lines){
    if(huntIOCs.find(i=>i.value===l)) continue;
    let type=detectIOCType(l);
    if(!type){
      const answer=prompt(\`Cannot auto-detect type for:\\n\${l}\\n\\nEnter type (ip, domain, url, sha256, sha1, md5, email, cve, filename, registry_key, hostname) or leave blank to skip:\`);
      if(!answer?.trim()) continue;
      type=answer.trim().toLowerCase();
    }
    huntIOCs.push({value:l,type});
    added.push({value:l,type});
  }
  document.getElementById('huntPasteInput').value='';
  document.getElementById('huntPasteInfo').innerHTML='';
  updateHuntBlocks();
  // Persist to the IOC DB too, so these also show up in IOC List / Enrichment.
  if(added.length){
    try { await api('/api/iocs/add-manual',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({iocs:added})}); }
    catch(e) { console.error('Failed to persist hunt IOCs', e); }
    refreshIOCData();
  }
}

async function buildHuntQueries(selectedOnly=false){
  // Environments checkboxes (top of page) are the only platform selector now —
  // always generate for all platforms server-side, then filter down to
  // whatever's checked in _filterQueriesByEnv (empty selection = show all).
  const platform = 'all';
  const div = document.getElementById('huntResults');
  div.innerHTML='<div class="loading">Building queries…</div>';

  if(huntMode === 'custom'){
    const rawIOCs = selectedOnly && selectedIOCIds.size>0
      ? huntIOCs.filter(i=>selectedIOCIds.has(i.value))
      : huntIOCs;
    if(!rawIOCs.length){
      div.innerHTML='<div class="loading">No IOCs in hunt list. Add some above.</div>';
      return;
    }
    const timeRange = getHuntTimeRange();
    const huntData = await api('/api/hunt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform,rawIOCs,timeRange})});
    if(!huntData.queries?.length){div.innerHTML='<div class="loading">No queries generated.</div>';return;}
    const filteredQ = _filterQueriesByEnv(huntData.queries);
    div.innerHTML = renderQueries(rawIOCs.length, filteredQ);
    return;
  }

  // DB mode
  const clsVal=document.getElementById('huntClassFilter').value;
  const cls=clsVal==='all'?[]:clsVal.split(',');
  const checkedTypes=[...document.querySelectorAll('#huntTypeGrid input:checked')].map(i=>i.value);
  if(!checkedTypes.length){div.innerHTML='<div class="loading">Select at least one type.</div>';return;}
  const qs=new URLSearchParams();
  qs.set('type',checkedTypes.join(','));
  if(cls.length) qs.set('classification',cls.join(','));
  qs.set('limit','2000');
  const data=await api('/api/iocs?'+qs);
  let iocs=data.iocs??[];
  if(selectedOnly && selectedIOCIds.size>0) iocs=iocs.filter(i=>selectedIOCIds.has(i.id));
  if(!iocs.length){div.innerHTML='<div class="loading">No matching IOCs in DB.</div>';return;}
  const timeRange = getHuntTimeRange();
  const huntData=await api('/api/hunt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform,iocIds:iocs.map(i=>i.id),overrideTypes:checkedTypes,timeRange})});
  if(!huntData.queries?.length){div.innerHTML='<div class="loading">No queries generated.</div>';return;}
  const filteredQ2 = _filterQueriesByEnv(huntData.queries);
  div.innerHTML=renderQueries(iocs.length,filteredQ2);
}

// ── Time range state ──────────────────────────────────────────────────
let huntTimePreset = '7d'; // '1d'|'7d'|'14d'|'30d'|'90d'|'custom'

function setHuntTimePreset(preset){
  huntTimePreset = preset;
  document.querySelectorAll('.hunt-preset').forEach(btn => {
    const active = btn.dataset.preset === preset;
    btn.style.background   = active ? 'var(--accent)' : '';
    btn.style.color        = active ? 'var(--bg)'     : '';
    btn.style.borderColor  = active ? 'var(--accent)' : '';
  });
  const cr = document.getElementById('huntCustomRange');
  if(cr) cr.style.display = preset === 'custom' ? 'flex' : 'none';
}

function validateHuntRange(){
  const s = document.getElementById('huntRangeStart')?.value;
  const e = document.getElementById('huntRangeEnd')?.value;
  const err = document.getElementById('huntRangeErr');
  if(s && e && s > e){ if(err) err.textContent = 'Start must be before end'; return false; }
  if(err) err.textContent = '';
  return true;
}

function getHuntTimeRange(){
  if(huntTimePreset !== 'custom'){
    return {type:'relative', relative:huntTimePreset};
  }
  const s = document.getElementById('huntRangeStart')?.value;
  const e = document.getElementById('huntRangeEnd')?.value;
  if(!s || !e || !validateHuntRange()) return null;
  return {type:'absolute', start:s+'T00:00:00', end:e+'T23:59:59'};
}

// ── Platform acknowledgment (searched) state ──────────────────────────
let _platformAcked = {}; // platform -> bool
let _huntEnvs = new Set(); // platforms checked in hunt env selector

function togglePlatformAck(platform, checked){
  _platformAcked[platform] = checked;
  document.querySelectorAll('.qblock[data-platform]').forEach(el => {
    const show = _platformAcked[el.dataset.platform] !== false;
    el.style.display = show ? '' : 'none';
  });
}

function toggleHuntEnv(platform, checked){
  if(checked) _huntEnvs.add(platform);
  else _huntEnvs.delete(platform);
  // Sync global env bar checkbox
  const cb = document.getElementById('genv-'+platform);
  if(cb) cb.checked = checked;
}

// Filter queries to whatever's checked in the Environments bar — the sole
// platform selector for Hunt Builder now. No selection = show every platform.
function _filterQueriesByEnv(queries){
  if(_huntEnvs.size > 0){
    return queries.filter(q => _huntEnvs.has(q.platform));
  }
  return queries;
}

let _queryCache = [];

function renderQueries(iocCount, queries){
  _queryCache = queries;
  // Ack state: if user selected specific envs, only those start checked
  const platforms = [...new Set(queries.map(q=>q.platform))];
  _platformAcked = {};
  platforms.forEach(p => _platformAcked[p] = _huntEnvs.size === 0 || _huntEnvs.has(p));

  const copyAllBtn = \`<button class="hc-toggle" style="font-size:11px;padding:3px 10px;" onclick="copyAllQueries()"><span>⧉ Copy All</span></button>\`;

  // Platform acknowledgment header
  const ackRow = platforms.length ? \`
    <div style="margin-bottom:12px;padding:8px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;">
      <div style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;margin-bottom:6px;">Platforms Searched (check to show queries)</div>
      <div style="display:flex;flex-wrap:wrap;gap:10px;">\${platforms.map(p=>\`
        <label style="display:flex;align-items:center;gap:5px;font-size:12px;cursor:pointer;">
          <input type="checkbox" checked onchange="togglePlatformAck('\${p}',this.checked)" style="cursor:pointer;">
          <span style="font-weight:600;color:var(--accent);">\${p.toUpperCase()}</span>
          <span style="color:var(--text2);font-size:11px;">\${PLATFORM_VENDOR[p]||''}</span>
        </label>\`).join('')}
      </div>
    </div>\` : '';

  return \`<div style="font-size:11px;color:var(--text2);margin-bottom:10px;display:flex;align-items:center;gap:10px;">\${iocCount} IOC(s) · \${queries.length} queries generated \${copyAllBtn}</div>\` +
    ackRow +
    queries.map((q, idx) => \`
      <div class="qblock" data-platform="\${q.platform}">
        <div class="qplat">
          [\${q.platform.toUpperCase()}] \${q.iocType} · \${q.iocValues.length} value(s) &nbsp;<span style="color:var(--text2);font-weight:400;">\${PLATFORM_VENDOR[q.platform]||''}</span>
          <button class="hc-toggle" style="font-size:10px;padding:2px 7px;" data-qidx="\${idx}" onclick="copyQuery(parseInt(this.dataset.qidx),this)"><span>Copy</span></button>
        </div>
        <div class="qdesc">\${escHtml(q.description)}</div>
        <pre>\${escHtml(q.query)}</pre>
      </div>
    \`).join('');
}

function copyQuery(idx, btn){
  const q = _queryCache[idx];
  if(!q) return;
  copy(q.query);
  if(btn){ btn.textContent='✓ Copied'; setTimeout(()=>btn.textContent='Copy',1500); }
}

function copyAllQueries(){
  const all = _queryCache.map(q => \`// [\${q.platform.toUpperCase()}] \${q.iocType}\\n\${q.query}\`).join('\\n\\n');
  copy(all);
  showAlert('success', \`Copied \${_queryCache.length} queries\`);
}

// ══════════════════ ANALYST MANUAL ENTRY ══════════════════
let analystIOCs = []; // {value, type}

function analystAddManual(){
  const inp=document.getElementById('analystManualVal');
  const val=inp.value.trim();
  if(!val) return;
  const type=detectIOCType(val)||'hostname';
  if(analystIOCs.find(i=>i.value===val)){inp.value='';return;}
  analystIOCs.push({value:val,type});
  const c=document.getElementById('analystManualBlocks');
  c.appendChild(renderBlock(val,type,'analystManualBlocks','analystIOCs'));
  inp.value='';
  updateAnalystBlocks();
}

function updateAnalystBlocks(){
  const byType={};
  for(const i of analystIOCs) byType[i.type]=(byType[i.type]||0)+1;
  const summary=Object.entries(byType).map(([t,n])=>\`\${n} \${t}\`).join(', ');
  document.getElementById('analystManualCount').textContent=analystIOCs.length?\`\${analystIOCs.length} IOC(s): \${summary}\`:'';
}

function analystClearManual(){
  analystIOCs=[];
  document.getElementById('analystManualBlocks').innerHTML='';
  updateAnalystBlocks();
}

function analystAddFromHunt(){
  if(!huntIOCs.length){alert('No IOCs in current hunt session.');return;}
  const c=document.getElementById('analystManualBlocks');
  let added=0;
  for(const h of huntIOCs){
    if(analystIOCs.find(i=>i.value===h.value)) continue;
    analystIOCs.push({value:h.value,type:h.type});
    c.appendChild(renderBlock(h.value,h.type,'analystManualBlocks','analystIOCs'));
    added++;
  }
  updateAnalystBlocks();
  if(!added) alert('All hunt IOCs already in analyst list.');
}

function analystPasteOpen(){
  document.getElementById('analystPasteArea').style.display='';
  document.getElementById('analystPasteInput').focus();
}

function analystPastePreview(){
  const raw=document.getElementById('analystPasteInput').value;
  const lines=raw.split(/[\\n,;]+/).map(l=>l.trim()).filter(Boolean);
  let ok=0,skip=0;
  for(const l of lines){ detectIOCType(l)?ok++:skip++; }
  document.getElementById('analystPasteInfo').innerHTML=
    ok?\`<span style="color:var(--green)">✓ \${ok} recognized</span>\${skip?'<span style="color:var(--yellow)"> · '+skip+' unrecognized</span>':''}\`:'';
}

function analystPasteAdd(){
  const raw=document.getElementById('analystPasteInput').value;
  const lines=raw.split(/[\\n,;]+/).map(l=>l.trim()).filter(Boolean);
  const c=document.getElementById('analystManualBlocks');
  for(const l of lines){
    const type=detectIOCType(l);
    if(!type||analystIOCs.find(i=>i.value===l)) continue;
    analystIOCs.push({value:l,type});
    c.appendChild(renderBlock(l,type,'analystManualBlocks','analystIOCs'));
  }
  document.getElementById('analystPasteInput').value='';
  document.getElementById('analystPasteArea').style.display='none';
  updateAnalystBlocks();
}

// ══════════════════ HUNT REPORT (email-ready) ══════════════════
let _huntReportText = '';
async function generateHuntReport(btn){
  if(btn) btn.disabled = true;
  const r = await api('/api/report/analyst');
  if(btn) btn.disabled = false;
  if(r && r.error){ showAlert('error', 'Report failed: '+r.error); return; }
  _huntReportText = r.text || '';
  document.getElementById('huntReportText').textContent = _huntReportText;
  document.getElementById('huntReportBody').style.display = '';
  document.getElementById('copyReportBtn').style.display = '';
}
function copyHuntReport(btn){
  if(!_huntReportText) return;
  copy(_huntReportText);
  const orig = btn.textContent;
  btn.textContent = '✓ Copied';
  setTimeout(()=>{ btn.textContent = orig; }, 1500);
}

// ══════════════════ ANALYST VIEW ══════════════════
async function loadAnalystView(useManual=false){
  const div  = document.getElementById('analystResults');
  div.innerHTML='<div class="loading">Loading…</div>';

  let iocs;
  if(useManual){
    if(!analystIOCs.length){div.innerHTML='<div class="loading">No IOCs added above.</div>';return;}
    // Build synthetic IOC objects for buildLinks / rendering
    iocs = analystIOCs.map((r,i)=>({id:'manual-'+i,value:r.value,type:r.type,classification:'unknown',source:'manual',extractedAt:new Date().toISOString(),tags:[]}));
  } else {
    const type = document.getElementById('analystTypeFilter').value;
    const cls  = document.getElementById('analystClassFilter').value;
    const qs = new URLSearchParams();
    if(type) qs.set('type',type);
    if(cls)  qs.set('classification',cls);
    qs.set('limit','500');
    const data = await api('/api/iocs?'+qs);
    iocs = data.iocs ?? [];
  }

  if(!iocs.length){div.innerHTML='<div class="loading">No IOCs match filter.</div>';return;}

  // Build link cache for Copy All / Open All
  _analystLinkCache = [];
  for(const ioc of iocs){
    const ev = encodeURIComponent(ioc.value);
    const t = ioc.type;
    const entry = { value: ioc.value, vt:'', abuse:'', otx:'' };
    if(t==='ip'||t==='ipv6'){
      entry.vt=\`https://www.virustotal.com/gui/ip-address/\${ev}\`;
      entry.abuse=\`https://www.abuseipdb.com/check/\${ioc.value}\`;
      entry.otx=\`https://otx.alienvault.com/indicator/ip/\${ioc.value}\`;
    } else if(t==='domain'||t==='hostname'){
      entry.vt=\`https://www.virustotal.com/gui/domain/\${ev}\`;
      entry.abuse=\`https://www.abuseipdb.com/check/\${ev}\`;
      entry.otx=\`https://otx.alienvault.com/indicator/domain/\${ioc.value}\`;
    } else if(t==='url'){
      entry.vt=\`https://www.virustotal.com/gui/url/\${btoa(ioc.value).replace(/=/g,'')}\`;
    } else if(t==='sha256'||t==='sha1'||t==='md5'){
      entry.vt=\`https://www.virustotal.com/gui/file/\${ioc.value}\`;
      entry.otx=\`https://otx.alienvault.com/indicator/file/\${ioc.value}\`;
    } else if(t==='email'){
      const d=ioc.value.split('@')[1]||'';
      entry.vt=\`https://www.virustotal.com/gui/domain/\${encodeURIComponent(d)}\`;
    }
    if(entry.vt||entry.abuse||entry.otx) _analystLinkCache.push(entry);
  }

  // Group by type
  const groups = {};
  for(const ioc of iocs){
    if(!groups[ioc.type]) groups[ioc.type]=[];
    groups[ioc.type].push(ioc);
  }

  const sections = Object.entries(groups).map(([t, list])=>{
    const rows = list.map(ioc => {
      const links = buildLinks(ioc);
      const score = ioc.enrichment?.reputationScore;
      return \`<tr>
        <td class="val" title="\${escHtml(ioc.value)}">\${escHtml(ioc.value)}</td>
        <td><span class="badge \${ioc.classification}">\${ioc.classification}</span></td>
        <td>\${score!=null?scoreBar(score):'—'}</td>
        <td>\${escHtml(ioc.enrichment?.country??'—')}</td>
        <td>\${escHtml(ioc.enrichment?.asnOrg??'—')}</td>
        <td>\${links}</td>
        <td id="abuse_\${ioc.id}" style="font-size:11px;color:var(--text2);">
          <button class="hc-toggle" style="font-size:10px;padding:1px 6px;" onclick="tiAnalyzeIOC(\${escHtml(JSON.stringify(ioc.value))},\${escHtml(JSON.stringify(ioc.type))})"><span>🎯 Intel</span></button>
          \${(ioc.type==='ip'||ioc.type==='ipv6') ? \`<button class="hc-toggle" style="font-size:10px;padding:1px 6px;" data-iid="\${ioc.id}" data-ip="\${escHtml(ioc.value)}" onclick="checkLive(this.dataset.iid,this.dataset.ip)"><span>Live Check</span></button>\` : ''}
        </td>
      </tr>\`;
    }).join('');

    return \`<div class="exec-section" style="margin-bottom:10px;">
      <h3 style="margin-bottom:8px;">\${typeIcon(t)} \${t.toUpperCase()} (\${list.length})</h3>
      <div style="overflow-x:auto;">
        <table>
          <thead><tr>
            <th>Value</th><th>Class</th><th>Score</th>
            <th>Country</th><th>ASN/Org</th><th>Links</th><th>Live Check</th>
          </tr></thead>
          <tbody>\${rows}</tbody>
        </table>
      </div>
    </div>\`;
  }).join('');

  const actionBar = \`<div style="display:flex;gap:7px;align-items:center;margin-bottom:11px;flex-wrap:wrap;">
    <span style="font-size:11px;color:var(--text2);">\${iocs.length} IOC(s)</span>
    <button class="hc-toggle" style="font-size:11px;padding:3px 9px;" onclick="copyAllAnalystLinks()"><span>⧉ Copy All Links</span></button>
    <button class="hc-toggle" style="font-size:11px;padding:3px 9px;" onclick="openAllAnalystLinks()"><span>↗ Open VT/Abuse/OTX</span></button>
  </div>\`;

  div.innerHTML = actionBar + sections;

  // Auto-run Ticket Intelligence for the analyzed IOCs
  const intelTypes = ['ip','ipv6','domain','hostname','url','sha256','sha1','md5','email'];
  const intelIOCs = iocs.filter(i => intelTypes.includes(i.type));
  _analystLastBatch = intelIOCs.map(i=>({value:i.value,type:i.type}));

  if(useManual && intelIOCs.length){
    const body = document.getElementById('ticketIntelBody');
    const icon = document.getElementById('tiCollapseIcon');
    if(body) body.style.display = '';
    if(icon) icon.textContent = '▼';
    _tiCollapsed = false;
    runTicketIntelBatch(_analystLastBatch);
  }
}

function buildLinks(ioc){
  const v = encodeURIComponent(ioc.value);
  const parts = [];
  const t = ioc.type;

  if(t==='ip'||t==='ipv6'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/ip-address/\${v}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://www.abuseipdb.com/check/\${v}" target="_blank">AbuseIPDB</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/ip/\${v}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.shodan.io/host/\${v}" target="_blank">Shodan</a>\`);
  } else if(t==='domain'||t==='hostname'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/domain/\${v}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://www.abuseipdb.com/check/\${v}" target="_blank">AbuseIPDB</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/domain/\${v}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist:\${v}" target="_blank">MXBl</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://viewdns.info/iphistory/?domain=\${v}" target="_blank">ViewDNS</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.whois.com/whois/\${v}" target="_blank">WHOIS</a>\`);
  } else if(t==='url'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/url/\${encodeURIComponent(btoa(ioc.value).replace(/=/g,''))}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://urlscan.io/search/#\${v}" target="_blank">URLScan</a>\`);
  } else if(t==='sha256'||t==='sha1'||t==='md5'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/file/\${v}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.hybrid-analysis.com/search?query=\${v}" target="_blank">Hybrid</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/file/\${v}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://bazaar.abuse.ch/sample/\${v}/" target="_blank">MalBazaar</a>\`);
  } else if(t==='email'){
    const domain = ioc.value.split('@')[1]||'';
    const domEnc = encodeURIComponent(domain);
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/domain/\${domEnc}" target="_blank">VT Domain</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://hunter.io/email-verifier/\${v}" target="_blank">Hunter</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=mx:\${domEnc}" target="_blank">MX Lookup</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist:\${domEnc}" target="_blank">MXBl</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://viewdns.info/whois/?domain=\${domEnc}" target="_blank">ViewDNS</a>\`);
  } else if(t==='cve'){
    parts.push(\`<a class="link-btn vt" href="https://nvd.nist.gov/vuln/detail/\${v}" target="_blank">NVD</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.exploit-db.com/search?cve=\${encodeURIComponent(ioc.value.replace(/^CVE-/i,''))}" target="_blank">ExploitDB</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://www.cvedetails.com/cve/\${v}/" target="_blank">Details</a>\`);
  } else if(t==='filename'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/search/\${v}" target="_blank">VT Search</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://bazaar.abuse.ch/browse.php?search=\${v}" target="_blank">MalBazaar</a>\`);
  }

  // Always add copy button. HTML-escaping alone is NOT enough here: escHtml
  // turns a ' into &#x27;, but the browser HTML-decodes attribute values
  // BEFORE handing them to the inline-handler JS parser, so a raw ' comes
  // right back and breaks out of the single-quoted copy('...') call. Use
  // JSON.stringify for JS-string safety, then escHtml so the resulting
  // double-quoted JSON string survives sitting inside the "..." attribute.
  parts.push(\`<button class="hc-toggle" style="font-size:10px;padding:1px 6px;" onclick="copy(\${escHtml(JSON.stringify(ioc.value))});this.textContent='✓';setTimeout(()=>this.textContent='Copy',1200)"><span>Copy</span></button>\`);

  return parts.join(' ');
}

let _analystLinkCache = [];
let _analystLastBatch = []; // {value, type} — for rescan with keys

function copyAllAnalystLinks(){
  const lines = _analystLinkCache.map(d => {
    const parts = ['Links', 'IOC: '+d.value];
    if(d.vt) parts.push('VT: '+d.vt);
    if(d.abuse) parts.push('Abuse: '+d.abuse);
    if(d.otx) parts.push('OTX: '+d.otx);
    return parts.join('\\n');
  }).join('\\n\\n');
  copy(lines);
  showAlert('success', \`Copied links for \${_analystLinkCache.length} IOCs\`);
}

function openAllAnalystLinks(){
  const links = [];
  for(const d of _analystLinkCache){
    if(d.vt) links.push({label:'VT: '+d.value, url:d.vt});
    if(d.abuse) links.push({label:'Abuse: '+d.value, url:d.abuse});
    if(d.otx) links.push({label:'OTX: '+d.value, url:d.otx});
  }
  if(!links.length){showAlert('warning','No links available');return;}
  let existing = document.getElementById('_linkModal');
  if(existing) existing.remove();
  const modal = document.createElement('div');
  modal.id = '_linkModal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = \`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:20px;max-width:520px;width:90%;max-height:70vh;overflow-y:auto;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <span style="font-weight:600;font-size:14px;">Open Links</span>
      <button class="hc-toggle" onclick="document.getElementById('_linkModal').remove()" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:16px;"><span>✕</span></button>
    </div>
    \${links.map(l=>\`<div style="margin:4px 0;"><a href="\${escHtml(l.url)}" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:none;font-size:12px;">\${escHtml(l.label)}</a></div>\`).join('')}
  </div>\`;
  modal.addEventListener('click', e => { if(e.target===modal) modal.remove(); });
  document.body.appendChild(modal);
}

async function checkLive(id, ip){
  const el = document.getElementById('abuse_'+id);
  el.innerHTML='<span style="color:var(--text2)">Checking…</span>';
  const d = await api('/api/check/live/'+encodeURIComponent(ip));
  if(d.error){el.innerHTML='<span style="color:var(--red)">'+escHtml(d.error)+'</span>';return;}

  el.innerHTML = \`
    <div class="enrich-card" style="min-width:240px;">
      \${d.org?'<div class="enrich-row"><span class="enrich-label">Org/ISP</span><span class="enrich-value">'+escHtml(d.org)+'</span></div>':''}
      \${d.country?'<div class="enrich-row"><span class="enrich-label">Country</span><span class="enrich-value">'+escHtml(d.country)+'</span></div>':''}
      \${d.city?'<div class="enrich-row"><span class="enrich-label">City</span><span class="enrich-value">'+escHtml(d.city)+'</span></div>':''}
      \${d.rdns?'<div class="enrich-row"><span class="enrich-label">rDNS</span><span class="enrich-value" style="font-family:monospace;font-size:10px;">'+escHtml(d.rdns)+'</span></div>':''}
      \${d.proxy?'<div class="enrich-row"><span class="enrich-label">Proxy/VPN</span><span class="enrich-value" style="color:var(--yellow);font-weight:700;">⚠ Detected</span></div>':''}
      \${d.hosting?'<div class="enrich-row"><span class="enrich-label">Hosting</span><span class="enrich-value" style="color:var(--text2);">Yes (datacenter)</span></div>':''}
      \${!d.source?'<div class="enrich-row" style="color:var(--text2);font-size:10px;">No geo data returned</div>':''}
      <div class="enrich-row" style="margin-top:5px;flex-wrap:wrap;gap:4px;">
        <a class="link-btn vt" href="\${escHtml(d.vtLink)}" target="_blank">VT</a>
        <a class="link-btn abuse" href="\${escHtml(d.abuseLink)}" target="_blank">AbuseIPDB</a>
        <a class="link-btn otx" href="\${escHtml(d.otxLink)}" target="_blank">OTX</a>
        <a class="link-btn hybrid" href="\${escHtml(d.shodanLink)}" target="_blank">Shodan</a>
      </div>
      \${d.source?'<div style="font-size:10px;color:var(--text2);margin-top:4px;">Source: '+escHtml(d.source)+'</div>':''}
    </div>
  \`;
}

function typeIcon(t){
  const m={ip:'🌐',ipv6:'🌐',domain:'🔗',url:'🌍',sha256:'#',sha1:'#',md5:'#',email:'✉',cve:'⚠',filename:'📄',registry_key:'🗝',hostname:'💻'};
  return m[t]||'•';
}


// ══════════════════ TABS / UTIL ══════════════════
const TAB_ORDER = ['hypothesis','ttp','hunt','iocs','enrichment','cheatsheet','detect','analyst','description','hypreport','frameworks'];
function showTab(name){
  TAB_ORDER.forEach(t=>{
    document.getElementById('tab-'+t).style.display=t===name?'':'none';
  });
  document.querySelectorAll('.tab').forEach((el,i)=>{
    el.classList.toggle('active',TAB_ORDER[i]===name);
  });
  if(name==='hypothesis') renderHypothesesList();
  if(name==='hypreport') renderHypothesisReport();
  if(name==='ttp') loadTTPLibrary();
  if(name==='iocs') refreshIOCData();
  if(name==='enrichment') loadEnrichmentTab();
  if(name==='description') loadDescriptionTab();
  if(name==='analyst') loadAnalystView();
  if(name==='cheatsheet') loadCheatSheet();
  if(name==='detect') updateDetectHuntCount();
  if(name==='frameworks') loadFrameworks();
}

function exportCSV(){
  api('/api/iocs?limit=9999').then(data=>{
    const rows=[['Value','Type','Classification','Source','Country','Score','Extracted']];
    for(const i of data.iocs) rows.push([i.value,i.type,i.classification,i.source,i.enrichment?.country??'',i.enrichment?.reputationScore??'',i.extractedAt]);
    // Prefix cells that a spreadsheet would treat as a formula (CSV injection)
    const cell=c=>{let s=String(c);if(/^[=+\\-@\\t\\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};
    const csv=rows.map(r=>r.map(cell).join(',')).join('\\n');
    const a=document.createElement('a');
    a.href='data:text/csv,'+encodeURIComponent(csv);
    a.download='iocs-'+new Date().toISOString().split('T')[0]+'.csv';
    a.click();
  });
}

// ══════════════════ IOC DESCRIPTION TAB ══════════════════
const BLOCKLIST_PATTERNS = ['ipsum','stamparm','blocklist','feodo','abuse.ch/feeds','cinsscore','binarydefense','emergingthreats','spamhaus','dshield','firehol'];

function isBlocklistSource(ioc){
  if(!ioc.sourceUrl) return false;
  const lower = ioc.sourceUrl.toLowerCase();
  return BLOCKLIST_PATTERNS.some(p=>lower.includes(p));
}

let _descText = '';

// ── Recommendations state ─────────────────────────────────────────────────
const REC_POOL = [
  {id:'block_ip',    text:'Block malicious IPs at perimeter firewall and/or NGFW',                types:['ip','ipv6']},
  {id:'fw_rule',     text:'Create blocking rules in NDR/IDS for confirmed malicious indicators',   types:['ip','ipv6','domain','url']},
  {id:'dns_block',   text:'Add malicious domains/URLs to DNS sinkhole and web proxy blocklist',    types:['domain','url']},
  {id:'edr_hash',    text:'Add malicious hashes to EDR custom IOC block list',                     types:['sha256','sha1','md5']},
  {id:'file_edr',    text:'Add filename-based detection rules to EDR',                             types:['filename']},
  {id:'reg_monitor', text:'Add registry key monitoring alerts to EDR/SIEM',                        types:['registry_key']},
  {id:'cve_review',  text:'Review CVEs against asset inventory — prioritize CVSS ≥ 9.0',           types:['cve']},
  {id:'email_block', text:'Block sender addresses and domains in mail gateway',                     types:['email']},
  {id:'hunt_siem',   text:'Generate and run SIEM hunt queries (use Hunt Builder tab)',              types:null},
  {id:'enrich',      text:'Enrich remaining unknown IOCs (use Analyst View tab)',                   types:null},
  {id:'ir_notify',   text:'Create incident ticket and notify security management',                  types:null},
  {id:'tlp_share',   text:'Share IOC package with threat intelligence partners (TLP:AMBER)',        types:null},
];
let _recommendations = new Set(); // text strings of checked recs
let _customRecs = [];             // user-added custom recommendation strings
let _descGroups = {};             // stored IOC groups for context-aware checklist
let _descSources = [];            // feed URLs from loaded IOCs

function _rebuildDescText(){
  const base = window._descBaseLines;
  if(!base) return;
  // Replace __HUNT_NAME__ sentinel with current value or placeholder
  const nameEl = document.getElementById('huntName');
  const huntName = nameEl ? nameEl.value.trim() : '';
  const displayName = huntName || '[INSERT THREAT HUNT NAME]';
  const lines = base.slice().map(l => l.replace(/__HUNT_NAME__/g, displayName));
  // Per-IOC ticket/host status for anything marked Found on the Enrichment tab
  lines.push('');
  lines.push(getTicketHostText());
  // Recommended actions
  lines.push('');
  lines.push('RECOMMENDED ACTIONS');
  lines.push('-'.repeat(30));
  if(_recommendations.size > 0){
    for(const r of _recommendations) lines.push(\`• \${r}\`);
  } else {
    lines.push('[INSERT RECOMMENDATIONS HERE]');
  }
  // Sources (feeds)
  if(_descSources.length){
    lines.push('');
    lines.push('SOURCES');
    lines.push('-'.repeat(30));
    for(const url of _descSources) lines.push(\`  • \${url}\`);
  }
  _descText = lines.join('\\n');
  const pre = document.getElementById('descPre');
  if(pre) pre.textContent = _descText;
}

// Per-IOC ticket/host status for the ticket-ready description — every IOC
// marked Found on the Enrichment tab gets a line; anything missing a ticket
// ref or affected host gets the [ADD TICKET AND HOST] reminder placeholder
// instead of silently omitting it.
function getTicketHostText(){
  const allIOCs = Object.values(_descGroups).flat();
  const found = allIOCs.filter(i => i.huntStatus === 'found');
  const out = ['TICKET / HOST STATUS', '-'.repeat(30)];
  if(!found.length){
    out.push('  No IOCs marked Found yet — use the Enrichment tab.');
    return out.join('\\n');
  }
  for(const ioc of found){
    const complete = (ioc.ticketEntries||[]).filter(e=>e.ticket && e.host);
    if(!complete.length){
      out.push(\`  \${ioc.value} — [ADD TICKET AND HOST]\`);
    } else {
      for(const e of complete){
        const envPart = e.environment ? \`Environment: \${e.environment} | \` : '';
        out.push(\`  \${ioc.value} — \${envPart}Ticket: \${e.ticket} | Host: \${e.host}\`);
      }
    }
  }
  return out.join('\\n');
}

function renderRecommendationsPanel(innerOnly=false){
  const available = REC_POOL.filter(r => !r.types || r.types.some(t => _descGroups[t]));
  const checkboxRows = available.map(r => {
    const checked = _recommendations.has(r.text) ? 'checked' : '';
    return \`<label style="display:flex;align-items:flex-start;gap:7px;cursor:pointer;padding:3px 0;font-size:12px;">
      <input type="checkbox" \${checked} data-text="\${escHtml(r.text)}" onchange="toggleRec(this.dataset.text,this.checked)" style="margin-top:2px;cursor:pointer;">
      <span>\${escHtml(r.text)}</span>
    </label>\`;
  }).join('');
  const customRows = _customRecs.map((txt,i) => {
    const checked = _recommendations.has(txt) ? 'checked' : '';
    return \`<label style="display:flex;align-items:flex-start;gap:7px;cursor:pointer;padding:3px 0;font-size:12px;">
      <input type="checkbox" \${checked} data-text="\${escHtml(txt)}" onchange="toggleRec(this.dataset.text,this.checked)" style="margin-top:2px;cursor:pointer;">
      <span style="flex:1;">\${escHtml(txt)}</span>
      <span onclick="removeCustomRec(\${i})" style="color:var(--red);cursor:pointer;font-size:13px;font-weight:bold;padding:0 5px;" title="Remove">×</span>
    </label>\`;
  }).join('');
  const hint = available.length===0 && _customRecs.length===0
    ? \`<div style="font-size:11px;color:var(--text2);padding:6px 0;">Reload the tab after adding IOCs to see context-aware suggestions.</div>\`
    : '';
  const inner = \`
    <div class="panel-header">✅ Recommended Actions</div>
    <div class="panel-body">
      <div style="font-size:11px;color:var(--text2);margin-bottom:8px;">Check items to include in the ticket description. Unchecked = <em>[INSERT RECOMMENDATIONS HERE]</em> placeholder.</div>
      \${hint}\${checkboxRows}\${customRows}
      <div style="margin-top:8px;display:flex;gap:6px;align-items:center;">
        <input type="text" id="recCustomInput" placeholder="Add custom recommendation…" style="flex:1;font-size:11px;" onkeydown="if(event.key==='Enter')addCustomRec()">
        <button class="hc-toggle" style="font-size:11px;padding:3px 9px;" onclick="addCustomRec()"><span>+ Add</span></button>
      </div>
    </div>\`;
  if(innerOnly) return inner;
  return \`<div class="panel" id="recommendationsPanel">\${inner}</div>\`;
}

function toggleRec(text, checked){
  if(checked) _recommendations.add(text);
  else _recommendations.delete(text);
  _rebuildDescText();
}

function addCustomRec(){
  const el = document.getElementById('recCustomInput');
  const txt = (el?.value||'').trim();
  if(!txt) return;
  if(!_customRecs.includes(txt)) _customRecs.push(txt);
  _recommendations.add(txt);
  if(el) el.value='';
  _rerenderRecsPanel();
}

function removeCustomRec(idx){
  const txt = _customRecs[idx];
  if(txt){ _customRecs.splice(idx,1); _recommendations.delete(txt); }
  _rerenderRecsPanel();
}

function _rerenderRecsPanel(){
  const host = document.getElementById('recommendationsPanel');
  if(host) host.innerHTML = renderRecommendationsPanel(true);
  _rebuildDescText();
}

// Silently pre-fetch IOC list so description tab is instant on first click
async function _prefetchDescriptionData(){
  if(window._descBaseLines) return; // already loaded
  try {
    const data = await api('/api/iocs?limit=2000');
    if(data.error || !data.iocs) return;
    // Only stash if user hasn't opened description tab yet
    if(window._descBaseLines) return;
    const dbIOCs = (data.iocs||[]).filter(ioc=>!isBlocklistSource(ioc));
    const dbVals = new Set(dbIOCs.map(i=>i.value));
    const huntEntries = huntIOCs
      .filter(h=>!dbVals.has(h.value))
      .map((h,i)=>({id:'hunt-'+i,value:h.value,type:h.type,classification:'unknown',source:'manual',extractedAt:new Date().toISOString(),tags:[]}));
    const iocs = [...dbIOCs, ...huntEntries];
    const now = new Date().toISOString().split('T')[0];
    const groups = {};
    for(const ioc of iocs){ if(!groups[ioc.type]) groups[ioc.type]=[]; groups[ioc.type].push(ioc); }
    const mal = iocs.filter(i=>i.classification==='malicious');
    const sus = iocs.filter(i=>i.classification==='suspicious');
    const lines = [];
    lines.push(\`THREAT INTELLIGENCE REPORT — __HUNT_NAME__ — \${now}\`);
    lines.push('='.repeat(50));
    lines.push(\`Threat Hunt: __HUNT_NAME__\`);
    lines.push(\`Total IOCs: \${iocs.length}\`);
    if(mal.length) lines.push(\`Malicious: \${mal.length}\`);
    if(sus.length) lines.push(\`Suspicious: \${sus.length}\`);
    lines.push('');
    lines.push('INDICATORS BY TYPE');
    lines.push('-'.repeat(30));
    for(const [type, list] of Object.entries(groups)){
      lines.push('');
      lines.push(\`\${type.toUpperCase()} (\${list.length})\`);
      const sources = [...new Set(list.map(i=>i.sourceUrl ? i.sourceUrl.replace(/^https?:\\/\\//,'').split('/')[0] : i.source))].slice(0,3);
      lines.push(\`  Origin: \${sources.join(', ')}\`);
      const malList = list.filter(i=>i.classification==='malicious');
      const susList = list.filter(i=>i.classification==='suspicious');
      const unkList = list.filter(i=>i.classification!=='malicious'&&i.classification!=='suspicious');
      if(malList.length){ lines.push('  Malicious:'); for(const ioc of malList) lines.push(\`    \${ioc.value}\`); }
      if(susList.length){ lines.push('  Suspicious:'); for(const ioc of susList) lines.push(\`    \${ioc.value}\`); }
      if(unkList.length){
        lines.push('  Unknown/External:');
        for(const ioc of unkList.slice(0,15)) lines.push(\`    \${ioc.value}\`);
        if(unkList.length>15) lines.push(\`    ... and \${unkList.length-15} more\`);
      }
    }
    _descGroups = groups;
    _descSources = [...new Set(iocs.filter(i=>i.sourceUrl).map(i=>i.sourceUrl))];
    window._descBaseLines = lines.slice();
    window._descDate = now;
  } catch { /* silent prefetch — failure is fine */ }
}

async function loadDescriptionTab(){
  // Fast path: data already loaded — skip API round-trip, just refresh text
  if(window._descBaseLines && document.getElementById('descPre')){
    _rebuildDescText();
    return;
  }
  const div = document.getElementById('tab-description');
  div.innerHTML='<div class="loading">Loading…</div>';

  let data;
  try { data = await api('/api/iocs?limit=2000'); } catch(e) { data = {error:String(e)}; }
  if(data.error){
    div.innerHTML=\`<div style="padding:20px;color:var(--red);font-size:12px;">Failed to load IOC data. <button class="hc-toggle" style="font-size:11px;padding:2px 8px;margin-left:8px;" onclick="loadDescriptionTab()"><span>↻ Click to retry</span></button></div>\`;
    return;
  }
  const dbIOCs = (data.iocs??[]).filter(ioc=>!isBlocklistSource(ioc));

  // Merge in Custom Hunt IOCs (huntIOCs global) — deduplicated by value
  const dbVals = new Set(dbIOCs.map(i=>i.value));
  const huntEntries = huntIOCs
    .filter(h=>!dbVals.has(h.value))
    .map((h,i)=>({id:'hunt-'+i,value:h.value,type:h.type,classification:'unknown',source:'manual',extractedAt:new Date().toISOString(),tags:[]}));

  const iocs = [...dbIOCs, ...huntEntries];

  if(!iocs.length){
    div.innerHTML='<div style="padding:20px;color:var(--text2);font-size:12px;">No IOCs from non-blocklist sources.</div>';
    return;
  }

  const now = new Date().toISOString().split('T')[0];
  window._descDate = now;
  const groups = {};
  for(const ioc of iocs){ if(!groups[ioc.type]) groups[ioc.type]=[]; groups[ioc.type].push(ioc); }

  const mal = iocs.filter(i=>i.classification==='malicious');
  const sus = iocs.filter(i=>i.classification==='suspicious');

  const lines = [];
  lines.push(\`THREAT INTELLIGENCE REPORT — __HUNT_NAME__ — \${now}\`);
  lines.push('='.repeat(50));
  lines.push(\`Threat Hunt: __HUNT_NAME__\`);
  lines.push(\`Total IOCs: \${iocs.length}\`);
  if(mal.length) lines.push(\`Malicious: \${mal.length}\`);
  if(sus.length) lines.push(\`Suspicious: \${sus.length}\`);
  lines.push('');
  lines.push('INDICATORS BY TYPE');
  lines.push('-'.repeat(30));

  for(const [type, list] of Object.entries(groups)){
    lines.push('');
    lines.push(\`\${type.toUpperCase()} (\${list.length})\`);
    const sources = [...new Set(list.map(i=>i.sourceUrl ? i.sourceUrl.replace(/^https?:\\/\\//,'').split('/')[0] : i.source))].slice(0,3);
    lines.push(\`  Origin: \${sources.join(', ')}\`);

    const malList = list.filter(i=>i.classification==='malicious');
    const susList = list.filter(i=>i.classification==='suspicious');
    const unkList = list.filter(i=>i.classification!=='malicious'&&i.classification!=='suspicious');

    if(malList.length){ lines.push('  Malicious:'); for(const ioc of malList) lines.push(\`    \${ioc.value}\`); }
    if(susList.length){ lines.push('  Suspicious:'); for(const ioc of susList) lines.push(\`    \${ioc.value}\`); }
    if(unkList.length){
      lines.push('  Unknown/External:');
      for(const ioc of unkList.slice(0,15)) lines.push(\`    \${ioc.value}\`);
      if(unkList.length>15) lines.push(\`    ... and \${unkList.length-15} more\`);
    }
  }

  // Stash IOC groups and feed sources for dynamic rebuild
  _descGroups = groups;
  _descSources = [...new Set(iocs.filter(i=>i.sourceUrl).map(i=>i.sourceUrl))];

  // Stash base lines (IOC listing only — recs/sources/env appended dynamically by _rebuildDescText)
  window._descBaseLines = lines.slice();

  // Build initial _descText via _rebuildDescText (reads sentinel + appends dynamic sections)
  _rebuildDescText();

  div.innerHTML = \`
    <div style="display:flex;gap:7px;align-items:center;margin-bottom:11px;flex-wrap:wrap;">
      <span style="font-size:11px;color:var(--text2);">\${iocs.length} IOCs\${huntEntries.length?' · '+huntEntries.length+' from Hunt Builder':''} · blocklist/manual excluded</span>
      <button class="hc-toggle" style="font-size:11px;padding:3px 9px;" onclick="copyDescription()"><span>⧉ Copy All</span></button>
      <button class="hc-toggle" style="font-size:11px;padding:3px 9px;" onclick="window._descBaseLines=null;loadDescriptionTab()"><span>↻ Reload</span></button>
    </div>
    <div class="panel">
      <div class="panel-header">📋 Ticket-Ready Description</div>
      <div class="panel-body">
        <pre id="descPre" style="white-space:pre-wrap;max-height:620px;overflow-y:auto;font-size:12px;">\${escHtml(_descText)}</pre>
      </div>
    </div>
    \${renderRecommendationsPanel(false)}
  \`;
}

function copyDescription(){
  copy(_descText);
  showAlert('success','Description copied to clipboard');
}

// ── Ticket Intelligence ─────────────────────────────────────────────────────

let _tiCollapsed = false;
const _tiSources = new Set(['virustotal','abuseipdb','ipinfo','arin','urlscan','crtsh','talos']);
const _tiManualData = {}; // keyed by cardKey_source -> {score, verdict}
const _tiSessionCache = {}; // in-memory only: key = ioc|type -> TicketIntelResult

// Reference-only sources — shown as links, not in scored TI panels
const TI_REF_SOURCES = new Set(['crtsh','talos']);
// Context-only providers — show evidence text only, no score/verdict/override
const TI_CONTEXT_ONLY = new Set(['ipinfo','arin']);

function toggleTiSource(source, checked){
  if(checked) _tiSources.add(source); else _tiSources.delete(source);
}

function tiToggleKeys(){
  const b = document.getElementById('tiKeyBody');
  const icon = document.getElementById('tiKeyIcon');
  if(!b || !icon) return;
  const open = b.style.display === 'none';
  b.style.display = open ? '' : 'none';
  icon.textContent = open ? '▼' : '▶';
}

function tiGetKeys(){
  const vtInp = document.getElementById('tiVtKey');
  const abInp = document.getElementById('tiAbuseKey');
  return {
    vtKey: (vtInp && vtInp.value) || '',
    abuseKey: (abInp && abInp.value) || '',
  };
}

function tiLoadKeys(){
  const inp = document.getElementById('tiVtKey');
  const inpA = document.getElementById('tiAbuseKey');
  const k = tiGetKeys();
  if(inp) inp.value = k.vtKey;
  if(inpA) inpA.value = k.abuseKey;
  // Show indicator if keys set
  const panel = document.querySelector('#tiKeyPanel .panel-header span:nth-child(2)');
  if(panel) panel.textContent = [k.vtKey?'VT ✓':'VT —', k.abuseKey?'AbuseIPDB ✓':'AbuseIPDB —'].join(' · ');
}

function _tiGetSessionCache(ioc, type){
  const k = ioc + '|' + type;
  return _tiSessionCache[k] || null;
}

function _allNoKey(result){
  if(!result || !result.providers) return false;
  const vals = Object.values(result.providers);
  if(!vals.length) return false;
  return vals.every(p => p && p.status === 'no_key');
}

function _tiSetSessionCache(ioc, type, result){
  if(_allNoKey(result)) return;
  const k = ioc + '|' + type;
  _tiSessionCache[k] = result;
}

function toggleTicketIntel(){
  _tiCollapsed = !_tiCollapsed;
  const body = document.getElementById('ticketIntelBody');
  const icon = document.getElementById('tiCollapseIcon');
  if(body) body.style.display = _tiCollapsed ? 'none' : '';
  if(icon) icon.textContent = _tiCollapsed ? '▶' : '▼';
}

function tiClear(){
  const res = document.getElementById('tiResults');
  if(res) res.innerHTML = '';
}

function tiAnalyzeIOC(value, type){
  const body = document.getElementById('ticketIntelBody');
  const icon = document.getElementById('tiCollapseIcon');
  if(body) body.style.display = '';
  if(icon) icon.textContent = '▼';
  _tiCollapsed = false;
  const sect = document.getElementById('ticketIntelSection');
  if(sect) sect.scrollIntoView({behavior:'smooth', block:'nearest'});
  runTicketIntelSingle(value, type, false);
}

function _tiClearCache(ioc, type){
  const k = ioc + '|' + type;
  delete _tiSessionCache[k];
}

async function runTicketIntelSingle(ioc, type, force){
  ioc = (ioc||'').trim();
  if(!ioc){ showAlert('error','No IOC value'); return; }
  if(force) _tiClearCache(ioc, type);
  const div = document.getElementById('tiResults');
  const cached = _tiGetSessionCache(ioc, type);
  if(cached){ div.innerHTML = renderTicketIntel(cached, true); return; }
  div.innerHTML = \`<div style="padding:16px;text-align:center;">
    <div style="font-size:13px;color:var(--accent);margin-bottom:8px;">⏳ Analyzing \${escHtml(ioc)}…</div>
    <div style="font-size:11px;color:var(--text2);">Running VT · AbuseIPDB · ARIN · ipinfo · urlscan…</div>
  </div>\`;
  try {
    const keys = tiGetKeys();
    const data = await api('/api/intel/analyze', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ioc, type, vtKey: keys.vtKey||undefined, abuseKey: keys.abuseKey||undefined}),
      timeoutMs: 25000
    });
    if(data.error){ div.innerHTML = \`<div class="loading" style="color:var(--red);">Error: \${escHtml(data.error)}</div>\`; return; }
    _tiSetSessionCache(ioc, type, data.result);
    div.innerHTML = renderTicketIntel(data.result, false);
  } catch(e){
    div.innerHTML = \`<div class="loading" style="color:var(--red);">Request failed: \${escHtml(String(e))}</div>\`;
  }
}

function rescanWithKeys(){
  if(!_analystLastBatch.length){ showAlert('error','No analyst batch to rescan. Run Analyze first.'); return; }
  for(const ioc of _analystLastBatch) _tiClearCache(ioc.value, ioc.type);
  const body = document.getElementById('ticketIntelBody');
  const icon = document.getElementById('tiCollapseIcon');
  if(body) body.style.display = '';
  if(icon) icon.textContent = '▼';
  _tiCollapsed = false;
  runTicketIntelBatch(_analystLastBatch);
}

// Batch analysis — runs all IOCs concurrently, renders live per-card updates
async function runTicketIntelBatch(iocList){
  if(!iocList.length) return;
  const div = document.getElementById('tiResults');
  // Seed placeholder cards immediately so user sees progress
  div.innerHTML = iocList.map((ioc,i) => \`
    <div id="ti-card-\${i}" style="margin-bottom:10px;border:1px solid var(--border);border-radius:6px;overflow:hidden;">
      <div style="display:flex;align-items:center;gap:8px;padding:7px 10px;background:var(--bg3);cursor:pointer;" onclick="tiToggleCard(\${i})">
        <span id="ti-card-icon-\${i}" style="font-size:10px;color:var(--text2);">▼</span>
        <span style="font-family:monospace;font-size:12px;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">\${escHtml(ioc.value)}</span>
        <span style="font-size:10px;color:var(--text2);">\${escHtml(ioc.type)}</span>
        <span id="ti-badge-\${i}" style="font-size:10px;padding:2px 7px;background:var(--bg3);border:1px solid var(--border);border-radius:2px;color:var(--text2);font-family:monospace;">⏳</span>
      </div>
      <div id="ti-body-\${i}" style="padding:10px;">
        <div style="font-size:11px;color:var(--text2);">Analyzing…</div>
      </div>
    </div>
  \`).join('');

  const keys = tiGetKeys();
  // Run all concurrently, update each card as it resolves
  await Promise.all(iocList.map(async (ioc, i) => {
    try {
      const cached = _tiGetSessionCache(ioc.value, ioc.type);
      const data = cached
        ? { result: cached, cached: true, error: null }
        : await api('/api/intel/analyze', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ioc:ioc.value, type:ioc.type, vtKey: keys.vtKey||undefined, abuseKey: keys.abuseKey||undefined}),
            timeoutMs: 25000
          });
      if(!cached && !data.error) _tiSetSessionCache(ioc.value, ioc.type, data.result);
      const badge = document.getElementById('ti-badge-'+i);
      const body  = document.getElementById('ti-body-'+i);
      if(!badge || !body) return;
      if(data.error){
        badge.textContent = 'ERR';
        badge.style.color = 'var(--red)';
        body.innerHTML = \`<div style="font-size:11px;color:var(--red);">\${escHtml(data.error)}</div>\`;
        return;
      }
      const r = data.result;
      const vColor = _tiVerdictColor(r.verdict);
      badge.textContent = r.verdict;
      badge.style.color = vColor;
      badge.style.borderColor = vColor;
      // Collapse by default when batch; user can expand
      body.innerHTML = renderTicketIntel(r, data.cached);
      document.getElementById('ti-body-'+i).style.display = 'none';
      document.getElementById('ti-card-icon-'+i).textContent = '▶';
    } catch(e){
      const body = document.getElementById('ti-body-'+i);
      if(body) body.innerHTML = \`<div style="font-size:11px;color:var(--red);">Failed: \${escHtml(String(e))}</div>\`;
    }
  }));
  buildTicketInfoSection(iocList);
}

function buildTicketInfoSection(iocList){
  const div = document.getElementById('ticketInfoSection');
  if(!div) return;
  if(!iocList || !iocList.length){ div.innerHTML=''; return; }
  const lines = [];
  lines.push('TICKET INFORMATION');
  lines.push('==================');
  lines.push('');
  lines.push('IOC COUNT: '+iocList.length);
  lines.push('GENERATED: '+new Date().toISOString());
  lines.push('');
  let malCount=0, susCount=0, cleanCount=0, unkCount=0;
  iocList.forEach((ioc, idx)=>{
    const r = _tiGetSessionCache(ioc.value, ioc.type);
    lines.push('--- IOC '+(idx+1)+': '+ioc.value+' ('+ioc.type+') ---');
    if(!r){
      lines.push('  STATUS: not analyzed');
      lines.push('');
      unkCount++;
      return;
    }
    const v = (r.verdict||'unknown').toUpperCase();
    if(v.includes('MALICIOUS')||v.includes('CRITICAL')) malCount++;
    else if(v.includes('SUSPICIOUS')) susCount++;
    else if(v.includes('CLEAN')||v.includes('LOW')) cleanCount++;
    else unkCount++;
    lines.push('  VERDICT:   '+v);
    lines.push('  SCORE:     '+(r.score||0)+'/100');
    lines.push('  SEVERITY:  '+(r.severity||'').toUpperCase());
    lines.push('  CONSENSUS: '+(r.consensus||'').toUpperCase()+' ('+(r.confidence||0)+'/100)');
    if(r.country||r.org||r.asn){
      const parts=[];
      if(r.country) parts.push(r.country);
      if(r.org) parts.push(r.org);
      if(r.asn) parts.push('AS'+r.asn);
      lines.push('  CONTEXT:   '+parts.join(' · '));
    }
    const prov = r.providers||{};
    ['virustotal','abuseipdb'].forEach(src=>{
      const p = prov[src];
      if(!p) return;
      if(p.status==='no_key'||p.verdict==='no_key'){
        lines.push('  '+src.toUpperCase()+': [MANUALLY UPDATE]');
        return;
      }
      let ratio='';
      if(src==='virustotal' && p.maliciousCount!=null){
        const tot=(p.maliciousCount||0)+(p.suspiciousCount||0)+(p.harmlessCount||0);
        ratio=p.maliciousCount+'/'+(tot||'?')+' engines';
      } else if(src==='abuseipdb' && p.abuseScore!=null){
        ratio=p.abuseScore+'/100';
      } else if(p.confidence!=null){
        ratio=Math.round(p.confidence)+'/100';
      }
      lines.push('  '+src.toUpperCase()+': ('+(ratio||'?')+') • '+(p.verdict||'?').toUpperCase());
    });
    ['ipinfo','arin','urlscan'].forEach(src=>{
      const p = prov[src];
      if(!p) return;
      const ev=(p.evidence||[]).join(' · ')||p.error||'';
      lines.push('  '+src.toUpperCase()+': '+(p.verdict||'?').toUpperCase()+(ev?' — '+ev:''));
    });
    const _enc=encodeURIComponent(ioc.value);
    const _t=ioc.type;
    lines.push('  REFERENCES:');
    if(_t==='ip'||_t==='ipv6'){
      lines.push('    VT:        https://www.virustotal.com/gui/ip-address/'+_enc);
      lines.push('    AbuseIPDB: https://www.abuseipdb.com/check/'+_enc);
      lines.push('    Shodan:    https://www.shodan.io/host/'+_enc);
      lines.push('    IPInfo:    https://ipinfo.io/'+_enc);
      lines.push('    URLScan:   https://urlscan.io/ip/'+_enc);
      lines.push('    Talos:     https://talosintelligence.com/reputation_center/lookup?search='+_enc);
    } else if(_t==='domain'||_t==='hostname'){
      lines.push('    VT:        https://www.virustotal.com/gui/domain/'+_enc);
      lines.push('    crt.sh:    https://crt.sh/?q='+_enc);
      lines.push('    URLScan:   https://urlscan.io/search/#domain:'+ioc.value);
      lines.push('    AbuseIPDB: https://www.abuseipdb.com/check/'+_enc);
      lines.push('    Talos:     https://talosintelligence.com/reputation_center/lookup?search='+_enc);
    } else if(_t==='sha256'||_t==='sha1'||_t==='md5'){
      lines.push('    VT:            https://www.virustotal.com/gui/file/'+_enc);
      lines.push('    MalwareBazaar: https://bazaar.abuse.ch/browse.php?search=sha256%3A'+_enc);
      lines.push('    Any.run:       https://app.any.run/hash/'+_enc);
      lines.push('    Hybrid:        https://www.hybrid-analysis.com/search?query='+_enc);
    } else if(_t==='url'){
      lines.push('    URLScan: https://urlscan.io/search/#page.url:'+_enc);
      lines.push('    VT:      https://www.virustotal.com/gui/search/'+_enc);
    } else if(_t==='email'){
      const _dom=encodeURIComponent(ioc.value.split('@')[1]||'');
      lines.push('    VT:     https://www.virustotal.com/gui/domain/'+_dom);
      lines.push('    Hunter: https://hunter.io/email-verifier/'+_enc);
    } else {
      lines.push('    VT: https://www.virustotal.com/gui/search/'+_enc);
    }
    lines.push('');
  });
  lines.unshift('');
  lines.unshift('SUMMARY:   '+malCount+' malicious · '+susCount+' suspicious · '+cleanCount+' clean · '+unkCount+' unknown');
  lines.unshift('==================');
  lines.unshift('TICKET INFORMATION');
  const text = lines.join('\\n');

  // Build per-IOC reference link rows shown below the stats pre
  const linkStyle = 'font-size:10px;color:var(--accent);padding:1px 6px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;text-decoration:none;white-space:nowrap;';
  const lnk = (label, url) => \`<a href="\${escHtml(url)}" target="_blank" rel="noopener" style="\${linkStyle}">\${escHtml(label)} ↗</a>\`;
  const linkRows = iocList.map((ioc) => {
    const enc = encodeURIComponent(ioc.value);
    const t = ioc.type;
    const r = _tiGetSessionCache(ioc.value, ioc.type);
    // Provider links from live result take priority
    const provLinks = [];
    if (r && r.providers) {
      const srcLabels = {virustotal:'VT',abuseipdb:'AbuseIPDB',ipinfo:'IPInfo',arin:'ARIN',urlscan:'URLScan',crtsh:'crt.sh',talos:'Talos'};
      Object.entries(r.providers).forEach(([src, p]) => {
        if (p && p.link && p.verdict !== 'n/a') provLinks.push(lnk(srcLabels[src]||src, p.link));
      });
    }
    // Fall back to type-based standard links
    let typeLinks = [];
    if (t === 'ip' || t === 'ipv6') {
      typeLinks = [
        lnk('VT', 'https://www.virustotal.com/gui/ip-address/' + enc),
        lnk('AbuseIPDB', 'https://www.abuseipdb.com/check/' + enc),
        lnk('Shodan', 'https://www.shodan.io/host/' + enc),
        lnk('IPInfo', 'https://ipinfo.io/' + enc),
        lnk('URLScan', 'https://urlscan.io/ip/' + enc),
        lnk('Talos', 'https://talosintelligence.com/reputation_center/lookup?search=' + enc),
      ];
    } else if (t === 'domain' || t === 'hostname') {
      typeLinks = [
        lnk('VT', 'https://www.virustotal.com/gui/domain/' + enc),
        lnk('crt.sh', 'https://crt.sh/?q=' + enc),
        lnk('URLScan', 'https://urlscan.io/search/#domain:' + ioc.value),
        lnk('AbuseIPDB', 'https://www.abuseipdb.com/check/' + enc),
        lnk('Talos', 'https://talosintelligence.com/reputation_center/lookup?search=' + enc),
      ];
    } else if (t === 'sha256' || t === 'sha1' || t === 'md5') {
      typeLinks = [
        lnk('VT', 'https://www.virustotal.com/gui/file/' + enc),
        lnk('MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search=sha256%3A' + enc),
        lnk('Any.run', 'https://app.any.run/hash/' + enc),
        lnk('Hybrid', 'https://www.hybrid-analysis.com/search?query=' + enc),
      ];
    } else if (t === 'url') {
      typeLinks = [
        lnk('URLScan', 'https://urlscan.io/search/#page.url:' + enc),
        lnk('VT', 'https://www.virustotal.com/gui/search/' + enc),
      ];
    } else if (t === 'email') {
      const dom = encodeURIComponent(ioc.value.split('@')[1]||'');
      typeLinks = [
        lnk('VT', 'https://www.virustotal.com/gui/domain/' + dom),
        lnk('Hunter', 'https://hunter.io/email-verifier/' + enc),
        lnk('MXToolbox', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a' + dom),
      ];
    } else {
      typeLinks = [lnk('VT', 'https://www.virustotal.com/gui/search/' + enc)];
    }
    const links = (provLinks.length ? provLinks : typeLinks).join(' ');
    const shortVal = ioc.value.length > 32 ? ioc.value.substring(0,30) + '…' : ioc.value;
    return \`<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;">
      <span style="font-size:10px;font-family:monospace;color:var(--text2);min-width:130px;max-width:180px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(ioc.value)}">\${escHtml(shortVal)} <span style="color:var(--accent);opacity:.6;font-size:9px;">\${escHtml(t)}</span></span>
      <div style="display:flex;flex-wrap:wrap;gap:4px;">\${links}</div>
    </div>\`;
  }).join('');

  div.innerHTML = \`
    <div class="panel">
      <div class="panel-header" style="display:flex;align-items:center;gap:8px;">
        📋 Ticket Information
        <span style="font-size:10px;color:var(--text2);font-weight:400;">— combined intel for all analyzed IOCs</span>
        <button class="hc-toggle" style="font-size:10px;padding:2px 7px;margin-left:auto;"
          onclick="copy(document.getElementById('ticketInfoPre').textContent);showAlert('success','Copied ticket info')"><span>⧉ Copy</span></button>
      </div>
      <div class="panel-body">
        <pre id="ticketInfoPre" style="white-space:pre-wrap;max-height:500px;overflow-y:auto;font-size:11px;">\${escHtml(text)}</pre>
        \${linkRows ? \`<div style="margin-top:12px;border-top:1px solid var(--border);padding-top:10px;">
          <div style="font-size:10px;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px;">Reference Links</div>
          \${linkRows}
        </div>\` : ''}
      </div>
    </div>
  \`;
}

function tiToggleCard(i){
  const body = document.getElementById('ti-body-'+i);
  const icon = document.getElementById('ti-card-icon-'+i);
  if(!body||!icon) return;
  const open = body.style.display === 'none';
  body.style.display = open ? '' : 'none';
  icon.textContent = open ? '▼' : '▶';
}

function _tiVerdictColor(v){
  return v==='CLEAN'?'var(--green)':v==='LOW RISK'?'#7ec8e3':v==='SUSPICIOUS'?'var(--yellow)':v==='MALICIOUS'?'#f97316':'var(--red)';
}

function _tiProviderBadge(v){
  v = v || 'unknown';
  const cfg = {malicious:['var(--red)','#2a0000'],suspicious:['var(--yellow)','#2a1e00'],clean:['var(--green)','#002a00'],unknown:['var(--text2)','var(--bg3)'],no_key:['var(--accent)','var(--bg3)'],manual_check:['#7ec8e3','var(--bg3)'],error:['var(--red)','#2a0000'],'n/a':['var(--text2)','var(--bg3)']};
  const [color,bg] = cfg[v]||cfg.unknown;
  const label = v==='no_key'?'NO KEY':v==='manual_check'?'CHECK':v.toUpperCase();
  return \`<span style="font-size:10px;padding:2px 7px;background:\${bg};border:1px solid \${color};border-radius:2px;color:\${color};font-family:monospace;">\${escHtml(label)}</span>\`;
}

function _tiScoreBar(score){
  const color = score>=70?'var(--red)':score>=50?'var(--yellow)':score>=21?'#7ec8e3':'var(--green)';
  return \`<div style="display:inline-flex;align-items:center;gap:5px;">
    <div style="width:70px;height:6px;background:var(--bg3);border-radius:3px;overflow:hidden;"><div style="width:\${score}%;height:100%;background:\${color};border-radius:3px;"></div></div>
    <span style="font-size:11px;font-weight:700;color:\${color};">\${score}</span>
  </div>\`;
}

function _tiCardKey(r){ return 'ti_' + btoa(r.ioc + '|' + r.iocType).replace(/[^a-zA-Z0-9]/g,'').slice(0,16); }

function _tiManualKey(cardKey, source){ return cardKey + '_' + source; }

function _tiGetManual(cardKey, source){
  return _tiManualData[_tiManualKey(cardKey, source)] || {score:'', verdict:''};
}

function _tiSetManual(cardKey, source, field, val){
  const k = _tiManualKey(cardKey, source);
  if(!_tiManualData[k]) _tiManualData[k] = {score:'', verdict:''};
  _tiManualData[k][field] = val;
  _tiRebuildTicketText(cardKey);
}

function _tiRebuildTicketText(cardKey){
  const pre = document.getElementById('tirpt_' + cardKey);
  if(!pre) return;
  const ioc = pre.dataset.ioc, iocType = pre.dataset.type, analyzedAt = pre.dataset.analyzed;
  const apiSection = document.getElementById('ti_api_' + cardKey);
  const pubSection = document.getElementById('ti_pub_' + cardKey);
  const lines = ['THREAT INTELLIGENCE REPORT','==========================','',
    'IOC:      ' + ioc, 'TYPE:     ' + (iocType||'').toUpperCase(), 'ANALYZED: ' + analyzedAt, ''];
  lines.push('--- API SOURCES ---');
  if(apiSection){
    apiSection.querySelectorAll('[data-ti-src]').forEach(function(row){
      const src = row.dataset.tiSrc;
      const mk = _tiManualKey(cardKey, src);
      const m = _tiManualData[mk] || {score:'',verdict:''};
      const ratio = row.dataset.ratio || row.dataset.autoScore || '?';
      const autoVerdict = row.dataset.autoVerdict || '[VERDICT]';
      const ratioDisp = ratio ? '(' + ratio + ')' : '(?/100)';
      const vDisp = (m.verdict && m.verdict !== '[VERDICT]') ? m.verdict : autoVerdict;
      lines.push('  ' + src.toUpperCase() + ': ' + ratioDisp + ' • ' + vDisp);
    });
  }
  lines.push('');
  lines.push('--- PUBLIC SOURCES ---');
  if(pubSection){
    pubSection.querySelectorAll('[data-ti-src]').forEach(function(row){
      const src = row.dataset.tiSrc;
      const ev = row.dataset.evidence || '';
      if(TI_CONTEXT_ONLY.has(src)){
        lines.push('  ' + src.toUpperCase() + ': ' + ev);
      } else {
        const mk = _tiManualKey(cardKey, src);
        const m = _tiManualData[mk] || {score:'',verdict:''};
        const autoScore = row.dataset.autoScore || '?';
        const autoVerdict = row.dataset.autoVerdict || '?';
        const scoreDisp = m.score !== '' ? m.score + '/100' : autoScore + '/100';
        const vDisp = m.verdict || autoVerdict;
        lines.push('  ' + src.toUpperCase() + ': (' + scoreDisp + ') • ' + vDisp + (ev ? ' — ' + ev : ''));
      }
    });
  }
  pre.textContent = lines.join('\\n');
}

function _tiCopyApi(cardKey){
  const section = document.getElementById('ti_api_' + cardKey);
  if(!section){ showAlert('error','No API section found'); return; }
  const lines = [];
  section.querySelectorAll('[data-ti-src]').forEach(function(row){
    const src = row.dataset.tiSrc;
    const verdictSelect = row.querySelector('select');
    const ratio = row.dataset.ratio || row.dataset.autoScore || '?';
    const autoVerdict = row.dataset.autoVerdict || '[VERDICT]';
    const verdict = verdictSelect ? verdictSelect.value : autoVerdict;
    lines.push(src.toUpperCase() + ': (' + ratio + ') • ' + verdict);
  });
  copy(lines.join('\\n'));
  showAlert('success','Copied API section');
}

function _tiCopyPub(cardKey){
  const section = document.getElementById('ti_pub_' + cardKey);
  if(!section){ showAlert('error','No public section found'); return; }
  const lines = [];
  section.querySelectorAll('[data-ti-src]').forEach(function(row){
    const src = row.dataset.tiSrc;
    const ev = row.dataset.evidence || '';
    if(TI_CONTEXT_ONLY.has(src)){
      lines.push(src.toUpperCase() + ': ' + ev);
    } else {
      const scoreInput = row.querySelector('input[type="number"]');
      const autoScore = row.dataset.autoScore || '?';
      const autoVerdict = (row.dataset.autoVerdict || '?').toUpperCase();
      const score = scoreInput && scoreInput.value ? scoreInput.value : autoScore;
      lines.push(src.toUpperCase() + ': (' + score + '/100) • ' + autoVerdict + (ev ? ' — ' + ev : ''));
    }
  });
  copy(lines.join('\\n'));
  showAlert('success','Copied public section');
}

function renderTicketIntel(r, cached){
  const vColor = _tiVerdictColor(r.verdict);
  const cColor = {weak:'var(--text2)',moderate:'var(--yellow)',strong:'#f97316',unanimous:'var(--red)'}[r.consensus]||'var(--text2)';
  const sColor = {info:'var(--text2)',low:'var(--green)',medium:'var(--yellow)',high:'#f97316',critical:'var(--red)'}[r.severity]||'var(--text2)';
  const cardKey = _tiCardKey(r);

  const API_PROVIDERS = ['virustotal','abuseipdb'];
  const PUB_PROVIDERS = ['ipinfo','arin','urlscan']; // scored providers only
  const REF_PROVIDERS = ['crtsh','talos']; // reference links, no scoring
  const verdictOpts = ['[VERDICT]','CLEAN','LOW RISK','SUSPICIOUS','MALICIOUS','CRITICAL'].map(v=>
    \`<option value="\${v}">\${v}</option>\`).join('');

  // ── API Sources section ──────────────────────────────────────────────────
  const _tiVerdictMap = {clean:'CLEAN',suspicious:'SUSPICIOUS',malicious:'MALICIOUS',critical:'CRITICAL',low_risk:'LOW RISK'};
  const _tiSkipAuto = new Set(['no_key','manual_check','n/a','unknown','error','']);
  const apiRows = API_PROVIDERS.filter(src => _tiSources.has(src)).map(src => {
    const p = (r.providers||{})[src] || {};
    const link = p.link ? \`<a href="\${escHtml(p.link)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:11px;">↗</a>\` : '';
    const noKey = p.verdict === 'no_key';
    const mk = _tiGetManual(cardKey, src);
    const hasReal = p.verdict && !_tiSkipAuto.has(p.verdict);
    const autoScore = (hasReal && p.confidence != null) ? String(Math.round(p.confidence)) : '';
    const autoVerdict = hasReal ? (_tiVerdictMap[p.verdict] || p.verdict.toUpperCase()) : '';
    const dispScore = mk.score !== '' ? mk.score : autoScore;
    const dispVerdict = (mk.verdict && mk.verdict !== '[VERDICT]') ? mk.verdict : autoVerdict;
    // Raw ratio labels: VT shows malicious/total, AbuseIPDB shows abuseScore/100
    let ratioLabel = '';
    if(src === 'virustotal' && hasReal && p.maliciousCount != null){
      const total = (p.maliciousCount||0) + (p.suspiciousCount||0) + (p.harmlessCount||0);
      ratioLabel = \`<span style="font-size:10px;color:var(--text2);font-family:monospace;margin-left:6px;">\${p.maliciousCount}/\${total||'?'} engines</span>\`;
    } else if(src === 'abuseipdb' && hasReal && p.abuseScore != null){
      ratioLabel = \`<span style="font-size:10px;color:var(--text2);font-family:monospace;margin-left:6px;">\${p.abuseScore}/100</span>\`;
    }
    return \`<div data-ti-src="\${src}" data-auto-score="\${autoScore}" data-auto-verdict="\${autoVerdict||'[VERDICT]'}" data-ratio="\${src==='virustotal'&&p.maliciousCount!=null?(p.maliciousCount+'/'+(((p.maliciousCount||0)+(p.suspiciousCount||0)+(p.harmlessCount||0))||'?')+' engines'):(src==='abuseipdb'&&p.abuseScore!=null?p.abuseScore+'/100':'')}" style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);">
      <div style="min-width:90px;font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text);">\${src}\${link}</div>
      <div style="flex:1;font-size:11px;color:var(--text2);">\${noKey?'<span style="color:var(--yellow);font-size:11px;font-weight:700;">[MANUALLY UPDATE]</span>':_tiProviderBadge(p.verdict||'unknown')}\${ratioLabel}</div>
      <select style="font-size:11px;padding:2px 4px;" onchange="_tiSetManual('\${cardKey}','\${src}','verdict',this.value)">
        \${['[VERDICT]','CLEAN','LOW RISK','SUSPICIOUS','MALICIOUS','CRITICAL'].map(v=>\`<option value="\${v}"\${dispVerdict===v?' selected':''}>\${v}</option>\`).join('')}
      </select>
    </div>\`;
  }).join('');


  // ── Public Sources section ───────────────────────────────────────────────
  const pubRows = PUB_PROVIDERS.filter(src => _tiSources.has(src)).map(src => {
    const p = (r.providers||{})[src] || {};
    const link = p.link ? \`<a href="\${escHtml(p.link)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:11px;">↗</a>\` : '';
    const evRaw = ((p.evidence||[]).join(' · ') || p.error || '—');
    const ev = src === 'abuseipdb' ? evRaw.replace(/(\d+)%/g, '$1/100') : evRaw;
    const mk = _tiGetManual(cardKey, src);
    const isCtx = TI_CONTEXT_ONLY.has(src);
    if(isCtx){
      return \`<div data-ti-src="\${src}" data-auto-score="0" data-auto-verdict="unknown" data-evidence="\${escHtml(ev)}"
        style="display:flex;align-items:center;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);">
        <div style="min-width:90px;font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text);">\${src}\${link}</div>
        <div style="flex:1;font-size:11px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(ev)}">\${escHtml(ev)}</div>
      </div>\`;
    }
    return \`<div data-ti-src="\${src}" data-auto-score="\${p.confidence||0}" data-auto-verdict="\${p.verdict||'unknown'}" data-evidence="\${escHtml(ev)}"
      style="display:flex;align-items:flex-start;gap:8px;padding:7px 0;border-bottom:1px solid var(--border);">
      <div style="min-width:90px;font-size:11px;font-weight:700;text-transform:uppercase;color:var(--text);">\${src}\${link}</div>
      <div style="flex:1;min-width:0;">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">\${_tiProviderBadge(p.verdict||'unknown')}\${_tiScoreBar(p.confidence||0)}</div>
        <div style="font-size:10px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="\${escHtml(ev)}">\${escHtml(ev)}</div>
      </div>
      <input type="number" min="0" max="100" placeholder="override" value="\${mk.score}"
        style="width:64px;font-family:monospace;font-size:11px;text-align:center;"
        oninput="_tiSetManual('\${cardKey}','\${src}','score',this.value)"
        title="Override score">
    </div>\`;
  }).join('');


  const tags = (r.tags||[]).map(t=>\`<span style="font-size:10px;padding:2px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:10px;color:var(--accent);">\${escHtml(t)}</span>\`).join('');

  // Initial report text (rebuilt live as user enters manual data)
  const initLines = ['THREAT INTELLIGENCE REPORT','==========================','',
    \`IOC:      \${r.ioc}\`, \`TYPE:     \${(r.iocType||'').toUpperCase()}\`, \`ANALYZED: \${r.analyzedAt}\`,'',
    '--- API SOURCES ---', ...API_PROVIDERS.filter(src=>_tiSources.has(src)).map(src=>{
      const p=(r.providers||{})[src]||{};
      if(p.status==='no_key'||p.verdict==='no_key') return src.toUpperCase()+': [MANUALLY UPDATE]';
      const mk=_tiGetManual(cardKey,src);
      const hasR=p.verdict&&!_tiSkipAuto.has(p.verdict);
      const aVerdict=hasR?(_tiVerdictMap[p.verdict]||p.verdict.toUpperCase()):'';
      const vStr=(mk.verdict&&mk.verdict!=='[VERDICT]')?mk.verdict:(aVerdict||'[VERDICT]');
      let ratioStr='?';
      if(src==='virustotal'&&hasR&&p.maliciousCount!=null){
        const tot=(p.maliciousCount||0)+(p.suspiciousCount||0)+(p.harmlessCount||0);
        ratioStr=p.maliciousCount+'/'+(tot||'?')+' engines';
      } else if(src==='abuseipdb'&&hasR&&p.abuseScore!=null){
        ratioStr=p.abuseScore+'/100';
      } else if(hasR&&p.confidence!=null){
        ratioStr=Math.round(p.confidence)+'/100';
      }
      return src.toUpperCase()+': ('+ratioStr+') • '+vStr;
    }),'',
    '--- PUBLIC SOURCES ---', ...PUB_PROVIDERS.filter(src=>_tiSources.has(src)).map(src=>{
      const p=(r.providers||{})[src]||{};
      const ev=(p.evidence||[]).join(' · ')||p.error||'';
      if(TI_CONTEXT_ONLY.has(src)) return src.toUpperCase()+': '+ev;
      return src.toUpperCase()+': ('+(p.confidence||'?')+'/100) • '+(p.verdict||'?').toUpperCase()+(ev?' — '+ev:'');
    })
  ];
  const initReport = initLines.join('\\n');

  return \`
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:12px;">
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;">
      <div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;">Final Verdict</div>
      <div style="font-size:15px;font-weight:700;color:\${vColor};">\${escHtml(r.verdict)}</div>
      <div style="margin-top:6px;">\${_tiScoreBar(r.score)}</div>
      <div style="font-size:10px;color:var(--text2);margin-top:3px;">Score \${r.score}/100</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;">
      <div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;">Consensus</div>
      <div style="font-size:15px;font-weight:700;color:\${cColor};text-transform:uppercase;">\${escHtml(r.consensus||'')}</div>
      <div style="font-size:10px;color:var(--text2);margin-top:3px;">Confidence \${r.confidence}/100</div>
    </div>
    <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;">
      <div style="font-size:10px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;">Severity</div>
      <div style="font-size:15px;font-weight:700;color:\${sColor};text-transform:uppercase;">\${escHtml(r.severity||'')}</div>
      \${r.country||r.org?\`<div style="font-size:10px;color:var(--text2);margin-top:3px;">\${escHtml(r.country||'')}\${r.country&&r.org?' · ':''}\${escHtml(r.org||'')}</div>\`:''}
    </div>
  </div>
  \${tags?\`<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:12px;">\${tags}</div>\`:''}
  \${(r.org||r.asn||r.country||r.network||r.created)?\`
  <div style="background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:9px 12px;margin-bottom:12px;display:flex;flex-wrap:wrap;gap:16px;">
    \${r.org?\`<div><div style="font-size:9px;color:var(--text2);text-transform:uppercase;">Org</div><div style="font-size:12px;font-family:monospace;">\${escHtml(r.org)}</div></div>\`:''}
    \${r.asn?\`<div><div style="font-size:9px;color:var(--text2);text-transform:uppercase;">ASN</div><div style="font-size:12px;font-family:monospace;">\${escHtml(r.asn)}</div></div>\`:''}
    \${r.country?\`<div><div style="font-size:9px;color:var(--text2);text-transform:uppercase;">Country</div><div style="font-size:12px;font-family:monospace;">\${escHtml(r.country)}</div></div>\`:''}
    \${r.network?\`<div><div style="font-size:9px;color:var(--text2);text-transform:uppercase;">Network</div><div style="font-size:12px;font-family:monospace;">\${escHtml(r.network)}</div></div>\`:''}
    \${r.created?\`<div><div style="font-size:9px;color:var(--text2);text-transform:uppercase;">First Seen</div><div style="font-size:12px;font-family:monospace;">\${escHtml(r.created.substring(0,10))}</div></div>\`:''}
  </div>\`:''}

  <!-- API Sources -->
  \${API_PROVIDERS.some(s=>_tiSources.has(s))?\`
  <div class="panel" style="margin-bottom:10px;">
    <div class="panel-header" style="display:flex;align-items:center;gap:8px;">
      🔑 API Sources
      <span style="font-size:10px;color:var(--text2);font-weight:400;">— enter scores manually until key configured</span>
      <button class="hc-toggle" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="_tiCopyApi('\${cardKey}')"><span>⧉ Copy</span></button>
    </div>
    <div class="panel-body" id="ti_api_\${cardKey}">\${apiRows||'<div style="font-size:11px;color:var(--text2);">No API sources selected</div>'}</div>
  </div>\`:''}

  <!-- Public Sources -->
  \${PUB_PROVIDERS.some(s=>_tiSources.has(s))?\`
  <div class="panel" style="margin-bottom:10px;">
    <div class="panel-header" style="display:flex;align-items:center;gap:8px;">
      🌐 Public Sources
      <span style="font-size:10px;color:var(--text2);font-weight:400;">— live data, optional score override</span>
      <button class="hc-toggle" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="_tiCopyPub('\${cardKey}')"><span>⧉ Copy</span></button>
    </div>
    <div class="panel-body" id="ti_pub_\${cardKey}">\${pubRows||'<div style="font-size:11px;color:var(--text2);">No public sources selected</div>'}</div>
  </div>\`:''}

  <!-- Reference Links (crt.sh, Talos — no score) -->
  \${REF_PROVIDERS.some(s=>_tiSources.has(s))?\`
  <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;align-items:center;">
    <span style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;">References:</span>
    \${_tiSources.has('crtsh')&&(r.providers||{}).crtsh?\`<a href="\${escHtml((r.providers.crtsh.link)||'https://crt.sh/?q='+encodeURIComponent(r.ioc))}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent);padding:2px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;">crt.sh ↗</a>\`:''}
    \${_tiSources.has('talos')&&(r.providers||{}).talos?\`<a href="\${escHtml((r.providers.talos.link)||'https://talosintelligence.com/reputation_center/lookup?search='+encodeURIComponent(r.ioc))}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent);padding:2px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;">Talos ↗</a>\`:''}
    \${_tiSources.has('crtsh')&&!(r.providers||{}).crtsh?\`<a href="https://crt.sh/?q=\${encodeURIComponent(r.ioc)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent);padding:2px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;">crt.sh ↗</a>\`:''}
    \${_tiSources.has('talos')&&!(r.providers||{}).talos?\`<a href="https://talosintelligence.com/reputation_center/lookup?search=\${encodeURIComponent(r.ioc)}" target="_blank" rel="noopener" style="font-size:11px;color:var(--accent);padding:2px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;">Talos ↗</a>\`:''}
  </div>\`:''}

  <!-- Full Ticket Report + Direct Sources combined -->
  <div class="panel">
    <div class="panel-header" style="display:flex;align-items:center;gap:8px;">
      📄 Ticket Report
      \${cached?'<span style="font-size:10px;color:var(--text2);font-weight:400;">· session cache</span>':''}
      <button class="hc-toggle" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="copy(document.getElementById('tirpt_\${cardKey}').textContent);showAlert('success','Copied')"><span>⧉ Copy</span></button>
    </div>
    <div class="panel-body">
      <pre id="tirpt_\${cardKey}" data-ioc="\${escHtml(r.ioc)}" data-type="\${escHtml(r.iocType)}" data-analyzed="\${escHtml(r.analyzedAt)}"
        style="white-space:pre-wrap;max-height:340px;overflow-y:auto;font-size:11px;">\${escHtml(initReport)}</pre>
      <div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:6px;">
      \${(()=>{
        const enc=encodeURIComponent(r.ioc);
        const t=r.iocType||'';
        const lnk=(label,url)=>\`<a href="\${escHtml(url)}" target="_blank" rel="noopener"
          style="font-size:11px;color:var(--accent);padding:3px 9px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;white-space:nowrap;text-decoration:none;">\${label} ↗</a>\`;
        let links=[];
        if(t==='ip'||t==='ipv6'){
          links=[
            lnk('VirusTotal','https://www.virustotal.com/gui/ip-address/'+enc),
            lnk('AbuseIPDB','https://www.abuseipdb.com/check/'+enc),
            lnk('IPInfo','https://ipinfo.io/'+enc),
            lnk('URLScan','https://urlscan.io/ip/'+enc),
            lnk('Talos','https://talosintelligence.com/reputation_center/lookup?search='+enc),
            lnk('Shodan','https://www.shodan.io/host/'+enc),
            lnk('ARIN','https://search.arin.net/rest/nets;q='+enc+'?showDetails=true'),
          ];
        } else if(t==='domain'||t==='hostname'||t==='fqdn'){
          links=[
            lnk('VirusTotal','https://www.virustotal.com/gui/domain/'+enc),
            lnk('URLScan','https://urlscan.io/search/#domain:'+r.ioc),
            lnk('AbuseIPDB','https://www.abuseipdb.com/check/'+enc),
            lnk('crt.sh','https://crt.sh/?q='+enc),
            lnk('Talos','https://talosintelligence.com/reputation_center/lookup?search='+enc),
            lnk('DNSDumpster','https://dnsdumpster.com/'),
            lnk('MXToolbox','https://mxtoolbox.com/SuperTool.aspx?action=dns%3a'+enc+'&run=toolpage'),
          ];
        } else if(t==='sha256'||t==='sha1'||t==='md5'){
          links=[
            lnk('VirusTotal','https://www.virustotal.com/gui/file/'+enc),
            lnk('MalwareBazaar','https://bazaar.abuse.ch/browse.php?search=sha256%3A'+enc),
            lnk('Any.run','https://app.any.run/hash/'+enc),
            lnk('Hybrid Analysis','https://www.hybrid-analysis.com/search?query='+enc),
          ];
        } else if(t==='email'){
          const domain=(r.ioc.split('@')[1]||'');
          const denc=encodeURIComponent(domain);
          links=[
            lnk('VirusTotal','https://www.virustotal.com/gui/domain/'+denc),
            lnk('Hunter.io','https://hunter.io/email-verifier/'+enc),
            lnk('MXToolbox','https://mxtoolbox.com/SuperTool.aspx?action=mx%3a'+denc+'&run=toolpage'),
            lnk('ViewDNS','https://viewdns.info/whois/?domain='+denc),
          ];
        } else if(t==='url'){
          links=[
            lnk('URLScan','https://urlscan.io/search/#page.url:'+enc),
            lnk('VirusTotal','https://www.virustotal.com/gui/search/'+enc),
          ];
        } else {
          links=[lnk('VirusTotal','https://www.virustotal.com/gui/search/'+enc)];
        }
        return links.join('');
      })()}
      </div>
    </div>
  </div>\`;
}

// Render UI from whatever is already stored — no more auto-wipe-on-load.
// This used to POST /api/session/init here, which calls clearAllIOCs() and
// wiped the entire database on every single page load — fine for a public
// no-auth demo where each visitor should get a clean slate, actively wrong
// for real ongoing use, where anything you add (Hunt Builder, IOC List,
// Enrichment) is expected to still be there next time you open the page.
loadStats(); loadIOCs();
rehydrateHuntFromDB();
setTimeout(()=>_prefetchDescriptionData(), 500);
loadTypeNav();
loadFeeds();
tiLoadKeys();
// Tabs and mode-bar buttons both drive a glitch-text hover effect off
// content: attr(data-text) — fill data-text from each element's own label
// once so it works for every tab/button without hardcoding each string.
document.querySelectorAll('.tab, .hc-toggle, .hw-text').forEach(el=>{ if(!el.dataset.text) el.dataset.text = el.textContent.trim(); });

</script>
// ═══ DETECTION ENGINEERING ═══
<script src="/cheatsheet.js"></script>
<script src="/detection.js"></script>
<script src="/ttp-library.js"></script>
<script src="/frameworks.js"></script>
<script>
// Runs after ttp-library.js has loaded (THREAT_ACTORS/TTP_TECHNIQUES must
// exist before a saved-mode reload can call showTab('hypothesis') ->
// renderHypothesesList(), which reads them — see the TAB_ORDER/TDZ bug this
// session already hit once for the same class of ordering mistake).
initMode();
</script>
</body></html>`;
}

const _cachedHTML = getHTML();
let _cachedHTMLGzip: Uint8Array | null = null;
(async () => {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  await writer.write(new TextEncoder().encode(_cachedHTML));
  await writer.close();
  _cachedHTMLGzip = new Uint8Array(await new Response(cs.readable).arrayBuffer());
})();
