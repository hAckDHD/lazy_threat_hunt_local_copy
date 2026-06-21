import { scrapeURL } from '../ingestion/scraper.js';
import { parseBulkText } from '../ingestion/manual.js';
import { parseBuffer } from '../ingestion/file-parser.js';
import { upsertIOC, bulkUpsertIOCs, bulkLinkSourceUrl, listIOCs, countIOCs, getStats, deleteIOC, getIOC, ignoreIOC, restoreAllIgnored, getStatsByType, getFeeds, getFeedsWithTypes, getStatsBySource, deleteBySourceUrl, clearAllIOCs } from '../storage/db.js';
import { analyzeIOC, type AnalyzeOptions } from '../intel/providers.js';
import { enrichIOC } from '../enrichment/index.js';
import { classifyBatch } from '../classification/classifier.js';
import { generateHuntQueries } from '../hunting/index.js';
import { generateExecutiveReport } from '../reporting/executive.js';
import { generateAnalystReport } from '../reporting/analyst.js';
import type { IOCFilter, IOCType } from '../types/index.js';
import { lookup } from 'dns/promises';

const PORT = Number(process.env.IOC_PORT ?? 8847);
const AUTH_TOKEN = process.env.IOC_API_TOKEN ?? '';
const ALLOWED_ORIGIN = process.env.IOC_ALLOWED_ORIGIN ?? '';

// ── Auth ────────────────────────────────────────────────────────────────────
function checkAuth(req: Request, path: string): Response | null {
  if (!AUTH_TOKEN) return null;
  if (req.method === 'OPTIONS' || path === '/' || path === '/index.html') return null;
  const header = req.headers.get('Authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (token !== AUTH_TOKEN) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer' },
    });
  }
  return null;
}

// ── SSRF guard ───────────────────────────────────────────────────────────────
function ip2n(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
}
function isPrivateIPv4(ip: string): boolean {
  const n = ip2n(ip);
  return (
    (n >>> 24) === 0 ||
    (n >>> 24) === 127 ||
    (n >>> 16) === 0xa9fe ||
    (n >>> 24) === 10 ||
    ((n >>> 20) & 0xfff) === 0xac1 ||
    (n >>> 16) === 0xc0a8 ||
    ((n >>> 22) & 0x3ff) === 0x191 ||
    (n >>> 28) === 0xf
  );
}
function isPrivateIPv6(ip: string): boolean {
  const l = ip.toLowerCase();
  return l === '::1' || l.startsWith('::ffff:') || l.startsWith('fe80:') || l.startsWith('fc') || l.startsWith('fd') || l === '::';
}
async function validateSSRFUrl(urlStr: string): Promise<void> {
  let parsed: URL;
  try { parsed = new URL(urlStr); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`Protocol not allowed: ${parsed.protocol}`);
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    if (isPrivateIPv4(hostname)) throw new Error('Private/internal IP not allowed');
    return;
  }
  if (hostname.includes(':')) {
    if (isPrivateIPv6(hostname)) throw new Error('Private IPv6 not allowed');
    return;
  }
  const addrs = await lookup(hostname, { all: true });
  for (const { address, family } of addrs) {
    if (family === 4 && isPrivateIPv4(address)) throw new Error(`Resolves to private IP: ${address}`);
    if (family === 6 && isPrivateIPv6(address)) throw new Error(`Resolves to private IPv6: ${address}`);
  }
}
function isValidIP(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-fA-F:]+$/.test(s);
}

export async function handleRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === 'TRACE') return new Response(null, { status: 405 });

  const cors: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  if (ALLOWED_ORIGIN) cors['Access-Control-Allow-Origin'] = ALLOWED_ORIGIN;

  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  const authErr = checkAuth(req, path);
  if (authErr) return authErr;

  // Lazy seed for cold starts — runs once per process instance, no-ops if DB has data
  seedDefaultFeeds().catch(() => {});

  try {
        // === API Routes ===

        if (path === '/api/iocs' && req.method === 'GET') {
          const filter = parseFilter(url);
          const iocs = await listIOCs(filter);
          const countFilter = { ...filter, limit: undefined, offset: undefined };
          const total = await countIOCs(countFilter);
          return json({ iocs, total, page: filter.offset ?? 0, limit: filter.limit ?? 100 }, cors);
        }

        if (path === '/api/stats' && req.method === 'GET') {
          return json(await getStats(), cors);
        }

        if (path === '/api/feeds' && req.method === 'GET') {
          return json(await getFeeds(), cors);
        }

        if (path === '/api/feeds/iocs' && req.method === 'GET') {
          return json(await getFeedsWithTypes(), cors);
        }

        if (path === '/api/stats/by-source' && req.method === 'GET') {
          return json(await getStatsBySource(), cors);
        }

        if (path === '/api/feeds/update' && req.method === 'POST') {
          const { url } = await req.json() as { url: string };
          await validateSSRFUrl(url);
          const result = await scrapeURL(url);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified);
          const { updated } = await bulkLinkSourceUrl(classified, url);
          return json({ ok: true, inserted, updated, total: result.stats.total }, cors);
        }

        if (path === '/api/feeds/delete' && req.method === 'POST') {
          const { url } = await req.json() as { url: string };
          await deleteBySourceUrl(url);
          return json({ ok: true }, cors);
        }

        if (path === '/api/iocs' && req.method === 'DELETE') {
          const body = await req.json() as { id: string };
          await deleteIOC(body.id);
          return json({ ok: true }, cors);
        }

        // Extract-only — parses text, returns IOCs, does NOT save to DB
        if (path === '/api/extract/text' && req.method === 'POST') {
          const { text } = await req.json() as { text: string };
          const result = parseBulkText(text);
          const classified = classifyBatch(result.iocs);
          return json({ ...result.stats, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
        }

        if (path === '/api/ingest/text' && req.method === 'POST') {
          const { text, returnIOCs } = await req.json() as { text: string; returnIOCs?: boolean };
          const result = parseBulkText(text);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified);
          const base = { ...result.stats, inserted };
          if (returnIOCs) return json({ ...base, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
          return json(base, cors);
        }

        if (path === '/api/ingest/url' && req.method === 'POST') {
          const { url: targetUrl, returnIOCs } = await req.json() as { url: string; returnIOCs?: boolean };
          await validateSSRFUrl(targetUrl);
          const result = await scrapeURL(targetUrl);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified);
          const base = { ...result.stats, inserted, sourceUrl: targetUrl };
          if (returnIOCs) return json({ ...base, iocs: classified.map(i => ({ value: i.value, type: i.type })) }, cors);
          return json(base, cors);
        }

        if (path === '/api/ingest/file' && req.method === 'POST') {
          const formData = await req.formData();
          const file = formData.get('file') as File | null;
          if (!file) return json({ error: 'No file provided' }, cors, 400);

          const buf = Buffer.from(await file.arrayBuffer());
          if (buf.length > 5 * 1024 * 1024) return json({ error: 'File too large (max 5 MB)' }, cors, 413);
          const result = await parseBuffer(buf, file.type, file.name);
          const classified = classifyBatch(result.iocs);
          const { inserted } = await bulkUpsertIOCs(classified);
          return json({ ...result.stats, inserted, filename: file.name }, cors);
        }

        if (path === '/api/enrich' && req.method === 'POST') {
          const body = await req.json() as { id: string; vtKey?: string; abuseKey?: string };
          const ioc = await getIOC(body.id);
          if (!ioc) return json({ error: 'IOC not found' }, cors, 404);
          const cfg = {
            virusTotal: body.vtKey || process.env.VT_API_KEY,
            abuseIpDb: body.abuseKey || process.env.ABUSEIPDB_API_KEY,
            shodan: process.env.SHODAN_API_KEY,
          };
          if (!cfg.virusTotal && !cfg.abuseIpDb && !cfg.shodan) {
            return json({ error: 'No API keys configured. Add VT or AbuseIPDB keys in Settings.' }, cors, 400);
          }
          const enriched = await enrichIOC(ioc, cfg);
          return json({ ioc: enriched }, cors);
        }

        // AbuseIPDB check — uses real API if key configured, otherwise returns curl commands
        if (path.startsWith('/api/check/abuse/') && req.method === 'GET') {
          const ip = decodeURIComponent(path.replace('/api/check/abuse/', ''));
          if (!ip || !isValidIP(ip)) return json({ error: 'Invalid IP address' }, cors, 400);

          const apiKey = process.env.ABUSEIPDB_API_KEY;

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

        // Live IP check — no API key required (ipinfo.io + ip-api.com + Google DoH)
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

          // Fallback: ip-api.com (free, 1000 req/15min, HTTP only)
          if (!source) {
            try {
              const r = await fetch(
                `http://ip-api.com/json/${ip}?fields=status,org,isp,country,countryCode,city,proxy,hosting,reverse`,
                { signal: liveCtrl(4000) }
              );
              if (r.ok) {
                const d = await r.json() as Record<string, unknown>;
                if (d.status === 'success') {
                  org = String(d.org ?? d.isp ?? '') || null;
                  country = (d.countryCode as string) ?? null;
                  city = (d.city as string) ?? null;
                  rdns = (d.reverse as string) ?? null;
                  proxy = Boolean(d.proxy);
                  hosting = Boolean(d.hosting);
                  source = 'ip-api.com';
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
          return json(await getStatsByType(srcParam), cors);
        }

        if (path === '/api/iocs/ignore' && req.method === 'POST') {
          const { id, ignored } = await req.json() as { id: string; ignored: boolean };
          await ignoreIOC(id, ignored);
          return json({ ok: true }, cors);
        }

        if (path === '/api/iocs/restore-all' && req.method === 'POST') {
          const n = await restoreAllIgnored();
          return json({ ok: true, restored: n }, cors);
        }

        if (path === '/api/hunt' && req.method === 'POST') {
          const body = await req.json() as {
            platform?: string;
            iocIds?: string[];
            overrideTypes?: string[];
            rawIOCs?: Array<{ value: string; type: string }>;
            timeRange?: import('../types/index.js').HuntTimeRange;
          };
          const platform = (body.platform ?? 'all') as 'all' | 'splunk' | 'elastic' | 'kql' | 'cql' | 's1ql' | 'wazuh' | 'tql' | 'sigma' | 'yara';
          const huntOptions = body.timeRange ? { timeRange: body.timeRange } : undefined;

          let iocs: Awaited<ReturnType<typeof listIOCs>>;

          if (body.rawIOCs?.length) {
            // Custom list mode — build minimal IOC objects directly, skip DB
            iocs = body.rawIOCs.map((r, i) => ({
              id: `raw-${i}`,
              value: r.value,
              type: r.type as import('../types/index.js').IOCType,
              classification: 'unknown' as const,
              source: 'manual' as const,
              extractedAt: new Date().toISOString(),
              tags: [],
            }));
          } else {
            iocs = await listIOCs({ classification: ['malicious', 'suspicious'], limit: 5000 });

            if (body.iocIds?.length) {
              const idSet = new Set(body.iocIds);
              iocs = iocs.filter(i => idSet.has(i.id));
              if (iocs.length === 0) {
                const all = await listIOCs({ limit: 5000 });
                iocs = all.filter(i => idSet.has(i.id));
              }
            }

            if (body.overrideTypes?.length) {
              const typeSet = new Set(body.overrideTypes);
              iocs = iocs.filter(i => typeSet.has(i.type));
            }
          }

          const queries = generateHuntQueries(iocs, platform, huntOptions);
          return json({ queries }, cors);
        }

        if (path === '/api/report/executive' && req.method === 'GET') {
          const since = url.searchParams.get('since') ?? new Date(Date.now() - 7 * 86400000).toISOString();
          const iocs = await listIOCs({ since });
          const report = generateExecutiveReport(iocs, since, new Date().toISOString());
          return json({ report }, cors);
        }

        if (path === '/api/report/analyst' && req.method === 'GET') {
          const since = url.searchParams.get('since') ?? new Date(Date.now() - 7 * 86400000).toISOString();
          const iocs = await listIOCs({ since });
          const report = generateAnalystReport(iocs);
          return json({ report }, cors);
        }

        // New session init — wipe all stored IOCs so each page load starts fresh.
        if (path === '/api/session/init' && req.method === 'POST') {
          await clearAllIOCs();
          return json({ ok: true }, cors);
        }

        // Ticket Intelligence — multi-provider reputation analysis (no server-side cache).
        if (path === '/api/intel/analyze' && req.method === 'POST') {
          const body = await req.json() as { ioc?: string; type?: string; vtKey?: string; abuseKey?: string };
          const { ioc, type } = body;
          if (!ioc || !type) return json({ error: 'ioc and type required' }, cors, 400);
          const opts: AnalyzeOptions = { vtKey: body.vtKey || undefined, abuseKey: body.abuseKey || undefined };
          const result = await analyzeIOC(ioc, type, opts);
          return json({ result, cached: false }, cors);
        }

        // === UI ===
        
        // Static file serving for new tabs
        if (path === '/public/cheatsheet.html' && req.method === 'GET') {
          try { const fs = require('fs'); const p = require('path'); const fp = p.join(process.cwd(),'public','cheatsheet.html'); const body = fs.readFileSync(fp); return new Response(body, {headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'public, max-age=60'}}); } catch(e) { return json({error:'File not found'},{},404); }
        }
        if (path === '/public/detection.html' && req.method === 'GET') {
          try { const fs = require('fs'); const p = require('path'); const fp = p.join(process.cwd(),'public','detection.html'); const body = fs.readFileSync(fp); return new Response(body, {headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'public, max-age=60'}}); } catch(e) { return json({error:'File not found'},{},404); }
        }
        if (path === '/public' && req.method === 'GET') {
          return json({files:['cheatsheet.html','detection.html']});
        }
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

        return json({ error: 'Not found' }, cors, 404);
  } catch (err) {
    console.error('[server error]', err);
    const msg = err instanceof Error ? err.message : 'Internal server error';
    // Only expose message for validation errors (user-facing); mask internal details
    const safe = /protocol not allowed|invalid url|private.*ip|resolves to|dns resolution|invalid ip|file too large/i.test(msg) ? msg : 'Internal server error';
    return json({ error: safe }, cors, 500);
  }
}

const DEFAULT_FEEDS = [
  'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt',
];

let _seeded = false;

async function seedDefaultFeeds(): Promise<void> {
  if (_seeded) return;
  _seeded = true;
  const count = await countIOCs();
  if (count > 0) return;
  for (const feedUrl of DEFAULT_FEEDS) {
    try {
      console.log(`[seed] Loading ${feedUrl} ...`);
      const result = await scrapeURL(feedUrl);
      const classified = classifyBatch(result.iocs);
      let inserted = 0;
      for (const ioc of classified) {
        const r = await upsertIOC(ioc);
        if (r.inserted) inserted++;
      }
      console.log(`[seed] Inserted ${inserted} IOCs from ${feedUrl}`);
    } catch (err) {
      console.error(`[seed] Failed ${feedUrl}:`, err);
    }
  }
}

async function gzipBytes(data: string): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip');
  const writer = cs.writable.getWriter();
  await writer.write(new TextEncoder().encode(data));
  await writer.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}

async function withGzip(req: Request): Promise<Response> {
  const res = await handleRequest(req);
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
  Bun.serve({ port: PORT, fetch: withGzip });
  console.log(`IOC Tool running at http://localhost:${PORT}`);
  seedDefaultFeeds().catch(err => console.error('[seed error]', err));
}

function json(data: unknown, extraHeaders: Record<string, string> = {}, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function parseFilter(url: URL): IOCFilter {
  const filter: IOCFilter = {};
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
  <style>
    :root {
      --bg:#050505;--bg2:#0a0a0a;--bg3:#111111;--bg4:#020202;
      --border:#1a2a1a;--text:#d0d0d0;--text2:#606060;
      --accent:#00ff41;--accent2:#00cc33;
      --red:#f85149;--yellow:#e3b341;--green:#3fb950;--orange:#d29922;--purple:#bc8cff;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,monospace;font-size:13px;}
    header{background:var(--bg2);border-bottom:1px solid var(--border);padding:10px 18px;display:flex;align-items:center;gap:14px;}
    header h1{font-size:17px;color:var(--accent);font-weight:700;letter-spacing:.5px;}
    header .subtitle{color:var(--text2);font-size:11px;}
    .stats-bar{display:flex;gap:10px;padding:8px 18px;background:var(--bg4);border-bottom:1px solid var(--border);flex-wrap:wrap;align-items:center;}
    .stat{background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:5px 12px;text-align:center;min-width:75px;cursor:pointer;transition:border-color .15s;}
    .stat:hover{border-color:var(--accent);}
    .stat .n{font-size:19px;font-weight:700;color:var(--accent);}
    .stat .label{font-size:10px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;}
    .stat.red .n{color:var(--red);}
    .stat.yellow .n{color:var(--yellow);}
    .layout{display:grid;grid-template-columns:290px 1fr;height:calc(100vh - 96px);}
    .sidebar{background:var(--bg2);border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column;}
    .main{overflow-y:auto;padding:14px;}

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
    .ingest-toggle{display:flex;align-items:center;justify-content:space-between;cursor:pointer;color:var(--text2);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px;}
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
    .tabs{display:flex;gap:3px;margin-bottom:11px;}
    .tab{padding:5px 13px;border-radius:6px 6px 0 0;cursor:pointer;font-size:12px;border:1px solid transparent;border-bottom:none;}
    .tab.active{background:var(--bg2);border-color:var(--accent);color:var(--accent);border-bottom-color:var(--bg2);}
    .tab:not(.active){color:var(--text2);}
    .tab:not(.active):hover{color:var(--text);}
    .filter-row{display:flex;gap:7px;align-items:center;margin-bottom:10px;flex-wrap:wrap;}
    .filter-row select{width:auto;}
    pre{background:var(--bg);border:1px solid var(--border);border-radius:5px;padding:10px;overflow:auto;font-size:11px;max-height:360px;}
    .alert{padding:8px 12px;border-radius:5px;margin-bottom:9px;font-size:12px;}
    .alert.success{background:#0d2d0d;border:1px solid #1e5e1e;color:var(--green);}
    .alert.error{background:#3d1a1a;border:1px solid #6e211e;color:var(--red);}
    .alert.info{background:#001a00;border:1px solid #1a4a1a;color:var(--accent);}
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
    .type-toggle{display:flex;align-items:center;gap:5px;padding:5px 8px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;cursor:pointer;font-size:12px;}
    .type-toggle.on{border-color:var(--accent);background:#001a00;}
    .type-toggle input{accent-color:var(--accent);}
    .ioc-block{display:inline-flex;align-items:center;gap:5px;padding:3px 8px 3px 6px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;font-size:11px;font-family:monospace;}
    .ioc-block .ioc-type{color:var(--purple);font-size:9px;font-weight:700;text-transform:uppercase;background:var(--bg3);padding:1px 4px;border-radius:8px;}
    .ioc-block .ioc-val{color:var(--text);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .ioc-block .ioc-rm{color:var(--text2);cursor:pointer;font-size:13px;line-height:1;margin-left:2px;}
    .ioc-block .ioc-rm:hover{color:var(--red);}
    .feed-chip{display:inline-flex;align-items:center;gap:7px;background:var(--bg2);border:1px solid var(--border);border-radius:5px;padding:3px 8px;font-size:11px;}
    .feed-chip .feed-url{color:var(--accent);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
    .feed-chip .feed-count{color:var(--text2);}
    /* Footer */
    .footer{margin-top:20px;padding:10px 18px;border-top:1px solid var(--border);text-align:center;font-size:11px;color:var(--text2);}
    .footer a{color:var(--accent);text-decoration:none;}
    .footer a:hover{text-decoration:underline;}
  </style>
</head>
<body>

<header>
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#00ff41" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
  <div>
    <h1>Lazy Threat Hunt</h1>
    <div class="subtitle">Extraction · Classification · Enrichment · Hunt · Report</div>
  </div>
  <div style="margin-left:auto;display:flex;gap:7px;align-items:center;">
    <span id="ingestAlert" style="font-size:11px;"></span>
    <button class="secondary" onclick="refresh()">⟳ Refresh</button>
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
    <button onclick="addFeed()" style="font-size:10px;padding:2px 10px;">Import</button>
    <button class="secondary" onclick="toggleAddFeed()" style="font-size:10px;padding:2px 7px;">Cancel</button>
    <span id="feedAddStatus" style="font-size:11px;color:var(--text2);"></span>
  </div>
  <div id="feedsBody"></div>
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
        <button onclick="ingestText()" style="margin-top:6px;width:100%">Add IOCs</button>
      </div>
      <div class="ingest-section">
        <label>Scrape URLs (one per line)</label>
        <textarea id="urlInput" rows="3" placeholder="https://threat-report.example.com/apt29&#10;https://raw.githubusercontent.com/..."></textarea>
        <button onclick="ingestURL()" style="margin-top:6px;width:100%">Scrape & Extract</button>
      </div>
      <div class="ingest-section">
        <label>Upload File (.txt .csv .json .pdf .docx)</label>
        <input type="file" id="fileInput" accept=".txt,.csv,.json,.pdf,.docx,.md,.log" style="color:var(--text2);font-size:11px;">
        <button onclick="ingestFile()" style="margin-top:6px;width:100%">Parse & Extract</button>
      </div>

      <!-- Current Hunt (sidebar mirror) -->
      <div class="ingest-section" style="padding-bottom:6px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;">
          <label style="margin:0;">Current Hunt</label>
          <button class="secondary" style="font-size:10px;padding:1px 7px;" onclick="huntClearBlocks()">Clear</button>
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
    <button id="navBtnType" onclick="setNavMode('type')" style="flex:1;border-radius:0;background:var(--bg3);border:none;border-left:1px solid var(--border);border-right:1px solid var(--border);color:var(--accent);font-size:11px;padding:6px 0;cursor:pointer;font-weight:700;">By Type</button>
    <button id="navBtnSource" onclick="setNavMode('source')" style="flex:1;border-radius:0;background:var(--bg2);border:none;color:var(--text2);font-size:11px;padding:6px 0;cursor:pointer;">By Source</button>
  </div>
  <!-- By Type sub-pills -->
  <div id="typeNavSubPills" style="display:flex;gap:4px;padding:5px 8px;border-bottom:1px solid var(--border);">
    <button id="typePillAll"  class="secondary" style="font-size:10px;padding:2px 9px;background:var(--accent);color:var(--bg);border-color:var(--accent);" onclick="setTypeSubFilter('all')">All</button>
    <button id="typePillFeed" class="secondary" style="font-size:10px;padding:2px 9px;" onclick="setTypeSubFilter('feed')">Feed</button>
    <button id="typePillHunt" class="secondary" style="font-size:10px;padding:2px 9px;" onclick="setTypeSubFilter('hunt')">Hunt</button>
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
  <!-- Global Environment Selector -->
  <div id="globalEnvBar" style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;padding:7px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;margin-bottom:9px;">
    <span style="font-size:10px;color:var(--text2);text-transform:uppercase;font-weight:700;white-space:nowrap;">Environments</span>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-splunk" onchange="toggleHuntEnv('splunk',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Splunk</span><span style="color:var(--text2);font-size:10px;">SPL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-kql" onchange="toggleHuntEnv('kql',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Sentinel/Defender</span><span style="color:var(--text2);font-size:10px;">KQL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-cql" onchange="toggleHuntEnv('cql',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">CrowdStrike</span><span style="color:var(--text2);font-size:10px;">CQL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-s1ql" onchange="toggleHuntEnv('s1ql',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">SentinelOne</span><span style="color:var(--text2);font-size:10px;">S1QL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-wazuh" onchange="toggleHuntEnv('wazuh',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Wazuh</span><span style="color:var(--text2);font-size:10px;">WQL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-elastic" onchange="toggleHuntEnv('elastic',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Elastic</span><span style="color:var(--text2);font-size:10px;">DSL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-tql" onchange="toggleHuntEnv('tql',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Trellix</span><span style="color:var(--text2);font-size:10px;">TQL</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-sigma" onchange="toggleHuntEnv('sigma',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">Sigma</span></label>
    <label style="display:flex;align-items:center;gap:4px;font-size:12px;cursor:pointer;"><input type="checkbox" id="genv-yara" onchange="toggleHuntEnv('yara',this.checked)" style="cursor:pointer;"><span style="font-weight:600;">YARA</span></label>
  </div>
  <div class="tabs">
    <div class="tab active" onclick="showTab('iocs')">IOC List</div>
    <div class="tab" onclick="showTab('hunt')">Hunt Builder</div>
    <div class="tab" onclick="showTab('analyst')">Analyst View</div>
    <div class="tab" onclick="showTab('description')">IOC Description</div>
    <div class="tab" onclick="showTab('cheatsheet')">Cheat Sheet</div>
    <div class="tab" onclick="showTab('detection')">Detection Engineering</div>
  </div>

  <!-- ── IOC List ── -->
  <div id="tab-iocs">
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
      <button id="restoreAllBtn" class="secondary" style="display:none;font-size:11px;padding:3px 9px;color:var(--yellow);border-color:var(--yellow);" onclick="restoreAll()">↺ Restore All</button>
      <button class="secondary" onclick="exportCSV()">⬇ Export CSV</button>
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
      <button onclick="huntSelected()">Hunt Selected →</button>
      <button class="secondary" onclick="huntAddAll()">+ Add All to Hunt</button>
      <button class="secondary" onclick="clearSelection()">Clear</button>
    </div>
  </div>

  <!-- ── Hunt Builder ── -->
  <div id="tab-hunt" style="display:none;">

    <!-- Mode toggle -->
    <div style="display:flex;gap:6px;margin-bottom:14px;">
      <button id="huntModeCustom" class="secondary" style="font-size:11px;padding:4px 13px;border-color:var(--accent);color:var(--accent);" onclick="setHuntMode('custom')">⚡ Custom Hunt</button>
      <button id="huntModeDB" class="secondary" style="font-size:11px;padding:4px 13px;" onclick="setHuntMode('db')">📦 From Database</button>
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
        <button onclick="huntAddOne()">+ Add</button>
      </div>

      <!-- Paste area — always visible -->
      <div id="huntPasteArea" style="margin-bottom:8px;">
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Paste IOCs</div>
        <textarea id="huntPasteInput" rows="4" placeholder="Paste IOCs — one per line (auto-detected; unknown types will prompt)" style="font-family:monospace;font-size:12px;" oninput="huntPastePreview()"></textarea>
        <div style="display:flex;gap:6px;margin-top:5px;align-items:center;">
          <span id="huntPasteInfo" style="font-size:11px;color:var(--text2);flex:1;"></span>
          <button onclick="huntPasteAdd()">→ Add to Hunt</button>
        </div>
      </div>

      <!-- Current hunt — sorted by type -->
      <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Current Hunt</div>
      <div id="huntBlocks" style="min-height:38px;padding:8px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;margin-bottom:6px;">
        <span style="color:var(--text2);font-size:11px;">No IOCs added yet</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;">
        <span id="huntBlockCount" style="font-size:11px;color:var(--text2);flex:1;"></span>
        <button class="secondary" style="font-size:10px;padding:2px 8px;" onclick="huntClearBlocks()">Clear All</button>
      </div>
    </div>

    <!-- ── DB mode ── -->
    <div id="huntDbControls" style="display:none;">
      <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:10px;">
        <div>
          <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:6px;font-weight:700;">IOC Types</div>
          <div class="hunt-type-grid" id="huntTypeGrid">
            <label class="type-toggle on"><input type="checkbox" value="ip" checked onchange="toggleHuntType(this)"> 🌐 IPs</label>
            <label class="type-toggle on"><input type="checkbox" value="domain" checked onchange="toggleHuntType(this)"> 🔗 Domains</label>
            <label class="type-toggle on"><input type="checkbox" value="url" checked onchange="toggleHuntType(this)"> 🔗 URLs</label>
            <label class="type-toggle on"><input type="checkbox" value="sha256" checked onchange="toggleHuntType(this)"> # SHA256</label>
            <label class="type-toggle on"><input type="checkbox" value="md5" checked onchange="toggleHuntType(this)"> # MD5</label>
            <label class="type-toggle on"><input type="checkbox" value="sha1" checked onchange="toggleHuntType(this)"> # SHA1</label>
            <label class="type-toggle on"><input type="checkbox" value="email" checked onchange="toggleHuntType(this)"> ✉ Email</label>
            <label class="type-toggle on"><input type="checkbox" value="cve" checked onchange="toggleHuntType(this)"> ⚠ CVEs</label>
            <label class="type-toggle on"><input type="checkbox" value="registry_key" checked onchange="toggleHuntType(this)"> 🗝 Registry</label>
            <label class="type-toggle on"><input type="checkbox" value="filename" checked onchange="toggleHuntType(this)"> 📄 Files</label>
            <label class="type-toggle on"><input type="checkbox" value="hostname" checked onchange="toggleHuntType(this)"> 💻 Hosts</label>
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

    <!-- Platform + Build (shared) -->
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px;">
      <div>
        <div style="font-size:11px;color:var(--text2);text-transform:uppercase;margin-bottom:4px;font-weight:700;">Platform</div>
        <select id="huntPlatform" style="width:210px;">
          <option value="all">All Platforms</option>
          <option value="splunk">Splunk (SPL)</option>
          <option value="kql">Microsoft Sentinel / Defender (KQL)</option>
          <option value="cql">CrowdStrike Falcon SIEM (CQL)</option>
          <option value="s1ql">SentinelOne Deep Visibility (S1QL)</option>
          <option value="wazuh">Wazuh (WQL)</option>
          <option value="elastic">Elastic (DSL)</option>
          <option value="sigma">Sigma Rule</option>
          <option value="yara">YARA</option>
          <option value="tql">Trellix (TQL)</option>
        </select>
      </div>
      <div style="align-self:flex-end;">
        <button onclick="buildHuntQueries()">⚡ Build Queries</button>
      </div>
    </div>

    <!-- Date range picker -->
    <div style="margin-bottom:14px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:6px;">
      <div style="font-size:11px;color:var(--text2);text-transform:uppercase;font-weight:700;margin-bottom:7px;">Time Range</div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:6px;" id="huntTimePresets">
        <button data-preset="1d"  class="hunt-preset" onclick="setHuntTimePreset('1d')"  style="font-size:11px;padding:3px 10px;">24h</button>
        <button data-preset="7d"  class="hunt-preset active" onclick="setHuntTimePreset('7d')"  style="font-size:11px;padding:3px 10px;background:var(--accent);color:var(--bg);border-color:var(--accent);">7d</button>
        <button data-preset="14d" class="hunt-preset" onclick="setHuntTimePreset('14d')" style="font-size:11px;padding:3px 10px;">14d</button>
        <button data-preset="30d" class="hunt-preset" onclick="setHuntTimePreset('30d')" style="font-size:11px;padding:3px 10px;">30d</button>
        <button data-preset="90d" class="hunt-preset" onclick="setHuntTimePreset('90d')" style="font-size:11px;padding:3px 10px;">90d</button>
        <button data-preset="custom" class="hunt-preset" onclick="setHuntTimePreset('custom')" style="font-size:11px;padding:3px 10px;">Custom…</button>
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
        <button onclick="analystAddManual()">+ Add</button>
        <button class="secondary" style="font-size:11px;" onclick="analystPasteOpen()">⊞ Paste Many</button>
        <button class="secondary" style="font-size:11px;" onclick="analystAddFromHunt()">⚡ From Hunt</button>
      </div>
      <div id="analystPasteArea" style="display:none;margin-bottom:7px;">
        <textarea id="analystPasteInput" rows="4" placeholder="Paste IOCs — one per line" style="font-family:monospace;font-size:12px;" oninput="analystPastePreview()"></textarea>
        <div style="display:flex;gap:6px;margin-top:4px;align-items:center;">
          <span id="analystPasteInfo" style="font-size:11px;color:var(--text2);flex:1;"></span>
          <button onclick="analystPasteAdd()">Add All</button>
          <button class="secondary" onclick="document.getElementById('analystPasteArea').style.display='none'">Cancel</button>
        </div>
      </div>
      <div id="analystManualBlocks" style="display:flex;flex-wrap:wrap;gap:5px;min-height:28px;"></div>
      <div style="display:flex;gap:7px;margin-top:7px;align-items:center;">
        <span id="analystManualCount" style="font-size:11px;color:var(--text2);flex:1;"></span>
        <button class="secondary" style="font-size:10px;padding:2px 7px;" onclick="analystClearManual()">Clear</button>
        <button onclick="loadAnalystView(true)">Analyze</button>
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
      <button onclick="loadAnalystView(false)">Load from DB</button>
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
          <button onclick="rescanWithKeys()" style="background:var(--accent);color:#000;font-weight:700;white-space:nowrap;">🔑 Rescan with Keys</button>
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

</div><!-- /main -->
</div><!-- /layout -->

<script>
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

function refresh(){huntIOCs=[];analystIOCs=[];envFindings={};_descText='';updateHuntBlocks();updateAnalystBlocks();loadStats();loadTypeNav();if(navMode==='source')loadSourceNav();loadIOCs();loadFeeds();}

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
  const BTN_ACTIVE   = {background:'var(--bg3)', color:'var(--accent)', fontWeight:'700'};
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
          <span style="color:var(--red);cursor:pointer;padding:0 4px;font-weight:700;font-size:13px;" onclick="huntRemoveIOC(\${JSON.stringify(val)})">×</span>
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
    return \`<div style="padding:2px 0;display:flex;align-items:center;gap:5px;font-size:10px;cursor:pointer;border-bottom:1px solid rgba(255,255,255,.03);" onclick="srcTypeFilter(\${idx},'\${ioc.type}')">
      <span style="color:var(--purple);font-size:8px;font-weight:700;min-width:44px;text-transform:uppercase;">\${ioc.type}</span>
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
    tbody.innerHTML=\`<tr><td colspan="9" class="loading" style="color:var(--red);">Failed to load IOCs. <button class="secondary" style="font-size:10px;padding:1px 6px;margin-left:6px;" onclick="loadIOCs()">↻ Retry</button></td></tr>\`;
    document.getElementById('paginationBar').innerHTML='';
    return;
  }
  if(!data.iocs?.length){
    tbody.innerHTML='<tr><td colspan="9" class="loading">No IOCs found.</td></tr>';
    document.getElementById('paginationBar').innerHTML='';
    return;
  }

  const totalPages = Math.ceil(data.total/PAGE_SIZE);
  document.getElementById('paginationBar').innerHTML=\`
    <button class="secondary" onclick="currentPage=Math.max(0,currentPage-1);loadIOCs()" \${currentPage===0?'disabled':''}>← Prev</button>
    <span>Page \${currentPage+1} / \${totalPages} &nbsp;·&nbsp; \${data.total.toLocaleString()} total</span>
    <button class="secondary" onclick="currentPage=Math.min(\${totalPages-1},currentPage+1);loadIOCs()" \${currentPage>=totalPages-1?'disabled':''}>Next →</button>
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
      <td><span class="badge type">\${ioc.type}</span></td>
      <td><span class="badge \${ioc.classification}">\${ioc.classification}</span></td>
      <td style="font-size:11px">\${ioc.enrichment?.country??'—'}</td>
      <td style="font-size:11px">\${scoreHtml}</td>
      <td style="font-size:10px;color:\${ioc.source==='scraper'?'#a78bfa':'var(--text2)'}">\${ioc.source}\${srcLink}</td>
      <td style="font-size:10px;color:var(--text2)">\${ioc.extractedAt.split('T')[0]}</td>
      <td style="white-space:nowrap;">
        <button class="secondary" style="font-size:10px;padding:2px 6px;" onclick="enrichOne('\${ioc.id}')">Enrich</button>
        \${isIgnored
          ? \`<button class="secondary" style="font-size:10px;padding:2px 6px;margin-left:3px;color:var(--green);border-color:var(--green);" onclick="ignoreOne('\${ioc.id}',false)">↺</button>\`
          : \`<button class="secondary" style="font-size:10px;padding:2px 6px;margin-left:3px;color:var(--yellow);border-color:var(--yellow);" onclick="ignoreOne('\${ioc.id}',true)">Ignore</button>\`
        }
      </td>
    </tr>\`;
  }).join('');
  updateSelBar();
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
  loadIOCs(); loadStats();
}
async function deleteOne(id){
  await api('/api/iocs',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});
  loadIOCs(); loadStats(); loadTypeNav();
}

async function ignoreOne(id, ignored){
  await api('/api/iocs/ignore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,ignored})});
  loadIOCs(); loadStats(); loadTypeNav();
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

function addToHuntFromIngest(iocs){
  let added=0;
  for(const {value,type} of iocs){
    if(!value||!type) continue;
    if(huntIOCs.find(i=>i.value===value)) continue;
    huntIOCs.push({value,type});
    added++;
  }
  updateHuntBlocks();
  if(added>0) showAlert('success',\`Added \${added} IOC(s) to Hunt Builder\`);
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
          <button class="secondary" style="font-size:9px;padding:1px 5px;" title="\${isPaused?'Resume':'Pause'} feed"
            data-furl="\${safeUrl}" data-fidx="\${idx}"
            onclick="event.stopPropagation();toggleFeedPause(this.dataset.furl,parseInt(this.dataset.fidx),this)">\${isPaused?'▶':'⏸'}</button>
          <button class="secondary" style="font-size:9px;padding:1px 5px;"
            data-furl="\${safeUrl}"
            onclick="event.stopPropagation();updateFeed(this.dataset.furl,this)">↻</button>
          <button class="danger" style="font-size:9px;padding:1px 5px;"
            data-furl="\${safeUrl}"
            onclick="event.stopPropagation();deleteFeed(this.dataset.furl,this)">✕</button>
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
  el.innerHTML = \`<span class="ioc-type">\${type}</span><span class="ioc-val" title="\${safe}">\${safe}</span><span class="ioc-rm" onclick="removeBlock('\${id}','\${storeName}',\${JSON.stringify(val)})">×</span>\`;
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

function huntAddOne(){
  const inp = document.getElementById('huntAddVal');
  const typeEl = document.getElementById('huntAddType');
  const val = inp.value.trim();
  if(!val) return;
  const type = typeEl.value==='auto' ? (detectIOCType(val)||'hostname') : typeEl.value;
  if(huntIOCs.find(i=>i.value===val)) { inp.value=''; return; }
  huntIOCs.push({value:val, type});
  inp.value='';
  updateHuntBlocks();
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
          <span style="color:var(--red);cursor:pointer;padding:0 4px;font-weight:700;font-size:13px;" onclick="huntRemoveIOC(\${JSON.stringify(val)})">×</span>
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
  for(const l of lines){
    if(huntIOCs.find(i=>i.value===l)) continue;
    let type=detectIOCType(l);
    if(!type){
      const answer=prompt(\`Cannot auto-detect type for:\\n\${l}\\n\\nEnter type (ip, domain, url, sha256, sha1, md5, email, cve, filename, registry_key, hostname) or leave blank to skip:\`);
      if(!answer?.trim()) continue;
      type=answer.trim().toLowerCase();
    }
    huntIOCs.push({value:l,type});
  }
  document.getElementById('huntPasteInput').value='';
  document.getElementById('huntPasteInfo').innerHTML='';
  updateHuntBlocks();
}

async function buildHuntQueries(selectedOnly=false){
  // If global env bar has selections, use those; else fall back to dropdown
  const dropdownPlatform = document.getElementById('huntPlatform').value;
  const platform = 'all'; // always generate all, filter after if envs selected
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
    const filteredQ = _filterQueriesByEnv(huntData.queries, dropdownPlatform);
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
  const filteredQ2 = _filterQueriesByEnv(huntData.queries, dropdownPlatform);
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

// Filter queries: if global envs selected, keep only those platforms
// Falls back to dropdown platform when no envs selected
function _filterQueriesByEnv(queries, dropdownPlatform){
  if(_huntEnvs.size > 0){
    return queries.filter(q => _huntEnvs.has(q.platform));
  }
  if(dropdownPlatform && dropdownPlatform !== 'all'){
    return queries.filter(q => q.platform === dropdownPlatform);
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

  const copyAllBtn = \`<button class="secondary" style="font-size:11px;padding:3px 10px;" onclick="copyAllQueries()">⧉ Copy All</button>\`;

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
          <button class="secondary" style="font-size:10px;padding:2px 7px;" data-qidx="\${idx}" onclick="copyQuery(parseInt(this.dataset.qidx),this)">Copy</button>
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
        <td>\${ioc.enrichment?.country??'—'}</td>
        <td>\${ioc.enrichment?.asnOrg??'—'}</td>
        <td>\${links}</td>
        <td id="abuse_\${ioc.id}" style="font-size:11px;color:var(--text2);">
          <button class="secondary" style="font-size:10px;padding:1px 6px;" onclick="tiAnalyzeIOC('\${escHtml(ioc.value).replace(/'/g,'&#x27;')}','\${ioc.type}')">🎯 Intel</button>
          \${(ioc.type==='ip'||ioc.type==='ipv6') ? \`<button class="secondary" style="font-size:10px;padding:1px 6px;" data-iid="\${ioc.id}" data-ip="\${escHtml(ioc.value)}" onclick="checkLive(this.dataset.iid,this.dataset.ip)">Live Check</button>\` : ''}
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
    <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="copyAllAnalystLinks()">⧉ Copy All Links</button>
    <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="openAllAnalystLinks()">↗ Open VT/Abuse/OTX</button>
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
    parts.push(\`<a class="link-btn abuse" href="https://www.abuseipdb.com/check/\${ioc.value}" target="_blank">AbuseIPDB</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/ip/\${ioc.value}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.shodan.io/host/\${ioc.value}" target="_blank">Shodan</a>\`);
  } else if(t==='domain'||t==='hostname'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/domain/\${v}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://www.abuseipdb.com/check/\${v}" target="_blank">AbuseIPDB</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/domain/\${ioc.value}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist:\${v}" target="_blank">MXBl</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://viewdns.info/iphistory/?domain=\${v}" target="_blank">ViewDNS</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.whois.com/whois/\${ioc.value}" target="_blank">WHOIS</a>\`);
  } else if(t==='url'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/url/\${btoa(ioc.value).replace(/=/g,'')}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://urlscan.io/search/#\${v}" target="_blank">URLScan</a>\`);
  } else if(t==='sha256'||t==='sha1'||t==='md5'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/file/\${ioc.value}" target="_blank">VT</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.hybrid-analysis.com/search?query=\${ioc.value}" target="_blank">Hybrid</a>\`);
    parts.push(\`<a class="link-btn otx" href="https://otx.alienvault.com/indicator/file/\${ioc.value}" target="_blank">OTX</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://bazaar.abuse.ch/sample/\${ioc.value}/" target="_blank">MalBazaar</a>\`);
  } else if(t==='email'){
    const domain = ioc.value.split('@')[1]||'';
    const domEnc = encodeURIComponent(domain);
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/domain/\${domEnc}" target="_blank">VT Domain</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://hunter.io/email-verifier/\${v}" target="_blank">Hunter</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=mx:\${domEnc}" target="_blank">MX Lookup</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://mxtoolbox.com/SuperTool.aspx?action=blacklist:\${domEnc}" target="_blank">MXBl</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://viewdns.info/whois/?domain=\${domEnc}" target="_blank">ViewDNS</a>\`);
  } else if(t==='cve'){
    parts.push(\`<a class="link-btn vt" href="https://nvd.nist.gov/vuln/detail/\${ioc.value}" target="_blank">NVD</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://www.exploit-db.com/search?cve=\${ioc.value.replace('CVE-','')}" target="_blank">ExploitDB</a>\`);
    parts.push(\`<a class="link-btn abuse" href="https://www.cvedetails.com/cve/\${ioc.value}/" target="_blank">Details</a>\`);
  } else if(t==='filename'){
    parts.push(\`<a class="link-btn vt" href="https://www.virustotal.com/gui/search/\${v}" target="_blank">VT Search</a>\`);
    parts.push(\`<a class="link-btn hybrid" href="https://bazaar.abuse.ch/browse.php?search=\${v}" target="_blank">MalBazaar</a>\`);
  }

  // Always add copy button
  parts.push(\`<button class="secondary" style="font-size:10px;padding:1px 6px;" onclick="copy('\${escHtml(ioc.value)}');this.textContent='✓';setTimeout(()=>this.textContent='Copy',1200)">Copy</button>\`);

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
      <button onclick="document.getElementById('_linkModal').remove()" style="background:none;border:none;color:var(--text2);cursor:pointer;font-size:16px;">✕</button>
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


// loadTabContent - loads static HTML content into tab divs
function loadTabContent(tabId, url){
  var el = document.getElementById('tab-'+tabId);
  if(!el || el.dataset.loaded === '1') return;
  fetch(url).then(function(r){ return r.text(); }).then(function(html){
    el.innerHTML = html;
    el.dataset.loaded = '1';
  }).catch(function(e){
    el.innerHTML = '<div style="color:var(--red);padding:20px">Failed to load content: ' + e.message + '</div>';
  });
}

// ══════════════════ TABS / UTIL ══════════════════
function showTab(name){
  ['iocs','hunt','analyst','description','cheatsheet','detection'].forEach(function(t){
    var el = document.getElementById('tab-'+t);
    if(el) el.style.display=t===name?'':'none';
  });
  document.querySelectorAll('.tab').forEach(function(el,i){
    el.classList.toggle('active',['iocs','hunt','analyst','description','cheatsheet','detection'][i]===name);
  });
  if(name==='description') loadDescriptionTab();
  if(name==='analyst') loadAnalystView();
  if(name==='cheatsheet') loadTabContent('cheatsheet','/public/cheatsheet.html');
  if(name==='detection') loadTabContent('detection','/public/detection.html');
}

function exportCSV(){
  api('/api/iocs?limit=9999').then(data=>{
    const rows=[['Value','Type','Classification','Source','Country','Score','Extracted']];
    for(const i of data.iocs) rows.push([i.value,i.type,i.classification,i.source,i.enrichment?.country??'',i.enrichment?.reputationScore??'',i.extractedAt]);
    const csv=rows.map(r=>r.map(c=>'"'+String(c).replace(/"/g,'""')+'"').join(',')).join('\\n');
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

// ── Environment Findings state (persists across tab reloads) ─────────────
const ENV_PLATFORMS = [
  {id:'splunk',   name:'Splunk',             lang:'SPL'},
  {id:'cs',       name:'CrowdStrike',        lang:'CQL'},
  {id:'defender', name:'Microsoft Defender', lang:'KQL'},
  {id:'s1',       name:'SentinelOne',        lang:'S1QL'},
  {id:'wazuh',    name:'Wazuh',              lang:'WQL'},
  {id:'tql',      name:'Trellix',            lang:'TQL'},
];
let envFindings = {}; // id -> {name, lang, status:'none'|'found'|'not_found', hosts:'', events:''}
let _customSeq = 0;
let _addCustomOpen = false;

function initEnvFindings(){
  for(const p of ENV_PLATFORMS){
    if(!envFindings[p.id]) envFindings[p.id] = {name:p.name, lang:p.lang, status:'none', hosts:'', events:''};
  }
}

function _rebuildDescText(){
  const base = window._descBaseLines;
  if(!base) return;
  // Replace __HUNT_NAME__ sentinel with current value or placeholder
  const nameEl = document.getElementById('huntName');
  const huntName = nameEl ? nameEl.value.trim() : '';
  const displayName = huntName || '[INSERT THREAT HUNT NAME]';
  const lines = base.slice().map(l => l.replace(/__HUNT_NAME__/g, displayName));
  // Environment findings (always present — defaults to "no findings")
  lines.push('');
  lines.push(getEnvFindingsText());
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

function _rerenderEnvPanel(){
  const host = document.getElementById('envFindingsPanel');
  if(host) host.innerHTML = renderEnvFindingsPanel(true);
  _rebuildDescText();
}

const ENV_TO_HUNT_PLATFORM = {splunk:'splunk', defender:'kql', cs:'cql', s1:'s1ql', wazuh:'wazuh', tql:'tql'};
function _getHuntPlatform(id){
  if(ENV_TO_HUNT_PLATFORM[id]) return ENV_TO_HUNT_PLATFORM[id];
  const f = envFindings[id];
  if(!f) return null;
  const langMap = {SPL:'splunk',KQL:'kql',CQL:'cql',S1QL:'s1ql',TQL:'tql',WQL:'wazuh',EQL:'elastic'};
  return langMap[(f.lang||'').toUpperCase()] || null;
}

async function _fetchHuntQueriesForPlatform(id){
  const platform = _getHuntPlatform(id);
  if(!platform || !huntIOCs.length) return;
  try {
    const data = await api('/api/hunt',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({platform,rawIOCs:huntIOCs})});
    if(data.queries?.length){
      envFindings[id].cachedHuntQueries = data.queries.map(q=>\`[\${q.platform.toUpperCase()}] \${q.iocType}\n\${q.query}\`).join('\\n\\n');
    }
  } catch(e){ /* ignore */ }
  _rebuildDescText();
}

function setEnvStatus(id, status){
  if(!envFindings[id]) return;
  envFindings[id].status = status;
  if(status !== 'found') envFindings[id].cachedHuntQueries = null;
  _rerenderEnvPanel();
  if(status === 'found') _fetchHuntQueriesForPlatform(id);
}

function setEnvField(id, field, val){
  if(!envFindings[id]) return;
  if(field !== 'hosts' && field !== 'events') return;
  envFindings[id][field] = val;
  // Don't re-render (would blow away focus on textarea) — just rebuild report text
  _rebuildDescText();
}

function toggleAddCustom(){
  _addCustomOpen = !_addCustomOpen;
  _rerenderEnvPanel();
}

function _onCustomLangChange(sel){
  const wrap = document.getElementById('envCustomOtherWrap');
  if(wrap) wrap.style.display = (sel.value === 'Other') ? '' : 'none';
}

function addCustomPlatform(){
  const nameEl  = document.getElementById('envCustomName');
  const langSel = document.getElementById('envCustomLang');
  const otherEl = document.getElementById('envCustomOther');
  if(!nameEl || !langSel) return;
  const name = (nameEl.value||'').trim();
  if(!name){ showAlert('error','Platform name is required'); return; }
  let lang = langSel.value;
  if(lang === 'Other'){
    lang = (otherEl && otherEl.value ? otherEl.value.trim() : '') || 'Other';
  }
  const id = 'custom_' + (_customSeq++);
  envFindings[id] = {name, lang, status:'none', hosts:'', events:''};
  _addCustomOpen = false;
  _rerenderEnvPanel();
}

function _envStatusBtn(id, status, label, color, active){
  const bg = active ? color : 'var(--bg3)';
  const fg = active ? '#000' : 'var(--text2)';
  const border = active ? color : 'var(--border)';
  return \`<button onclick="setEnvStatus('\${id}','\${status}')" style="font-size:10px;padding:2px 8px;background:\${bg};color:\${fg};border:1px solid \${border};border-radius:3px;cursor:pointer;font-family:monospace;">\${label}</button>\`;
}

function _envRow(id, p){
  const f = envFindings[id];
  const status = f.status;
  const notFoundBtn = _envStatusBtn(id,'not_found','Not Found','var(--red)', status==='not_found' || status==='none');
  const foundBtn    = _envStatusBtn(id,'found',    'Found',    'var(--green)', status==='found');
  const langBadge = \`<span style="font-size:9px;padding:1px 5px;background:var(--bg3);border:1px solid var(--border);border-radius:2px;color:var(--accent);font-family:monospace;margin-left:6px;">\${escHtml(f.lang)}</span>\`;
  let body = \`
    <div style="display:flex;align-items:center;gap:8px;padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;">
      <span style="font-size:12px;color:var(--text);flex:1;">\${escHtml(f.name)}\${langBadge}</span>
      \${notFoundBtn}
      \${foundBtn}
    </div>\`;
  if(status === 'found'){
    body += \`
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:4px;padding:0 4px 4px 4px;">
        <div>
          <div style="font-size:10px;color:var(--text2);margin-bottom:2px;">Affected Hosts (one per line)</div>
          <textarea oninput="setEnvField('\${id}','hosts',this.value)" rows="3" style="width:100%;font-family:monospace;font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:2px;padding:4px;resize:vertical;">\${escHtml(f.hosts)}</textarea>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text2);margin-bottom:2px;">Event / Alert IDs (one per line)</div>
          <textarea oninput="setEnvField('\${id}','events',this.value)" rows="3" style="width:100%;font-family:monospace;font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:2px;padding:4px;resize:vertical;">\${escHtml(f.events)}</textarea>
        </div>
      </div>\`;
  }
  return \`<div style="margin-bottom:5px;">\${body}</div>\`;
}

function renderEnvFindingsPanel(innerOnly){
  // innerOnly=true → return just the contents of #envFindingsPanel (used by _rerenderEnvPanel)
  // innerOnly=false → return the full panel wrapper (used by loadDescriptionTab)
  // Build platform rows: filter built-ins to selected envs when any are checked
  const allBuiltinIds = ENV_PLATFORMS.map(p=>p.id);
  const builtinIds = allBuiltinIds;
  const customIds  = Object.keys(envFindings).filter(id=>!allBuiltinIds.includes(id));
  const rows = [...builtinIds, ...customIds]
    .filter(id=>envFindings[id])
    .map(id=>_envRow(id, envFindings[id]))
    .join('');

  // Summary
  const found = Object.entries(envFindings).filter(([,f])=>f.status==='found').map(([,f])=>f.name);
  const checked = Object.entries(envFindings).filter(([,f])=>f.status!=='none');
  let summary;
  if(!checked.length){
    summary = \`<div style="font-size:11px;color:var(--text2);padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;margin-top:6px;">No environments checked yet.</div>\`;
  } else if(!found.length){
    summary = \`<div style="font-size:11px;color:var(--green);padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;margin-top:6px;">✓ No IOCs found in any environment.</div>\`;
  } else {
    summary = \`<div style="font-size:11px;color:var(--yellow);padding:6px 8px;background:var(--bg2);border:1px solid var(--border);border-radius:3px;margin-top:6px;">⚠ IOCs found in: <strong style="color:var(--text);">\${escHtml(found.join(', '))}</strong></div>\`;
  }

  // Add Custom form
  let addBlock;
  if(_addCustomOpen){
    addBlock = \`
      <div style="margin-top:6px;padding:8px;background:var(--bg2);border:1px solid var(--accent);border-radius:3px;">
        <div style="font-size:11px;color:var(--text);margin-bottom:6px;">Add Custom Platform</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px;">
          <input id="envCustomName" type="text" placeholder="Platform name" style="flex:1;min-width:160px;font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:2px;padding:4px 6px;font-family:monospace;" />
          <select id="envCustomLang" onchange="_onCustomLangChange(this)" style="font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:2px;padding:4px 6px;font-family:monospace;">
            <option value="KQL">KQL</option>
            <option value="SPL">SPL</option>
            <option value="TQL">TQL</option>
            <option value="CQL">CQL</option>
            <option value="YQL">YQL</option>
            <option value="Other">Other</option>
          </select>
          <span id="envCustomOtherWrap" style="display:none;">
            <input id="envCustomOther" type="text" placeholder="Query lang" style="font-size:11px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:2px;padding:4px 6px;font-family:monospace;width:90px;" />
          </span>
          <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="addCustomPlatform()">Add</button>
          <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="toggleAddCustom()">Cancel</button>
        </div>
      </div>\`;
  } else {
    addBlock = \`
      <div style="margin-top:6px;">
        <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="toggleAddCustom()">+ Add Custom Platform</button>
      </div>\`;
  }

  const inner = \`<div class="panel-header">🔍 Environment Findings</div>
    <div class="panel-body">
      \${rows}
      \${addBlock}
      \${summary}
    </div>\`;

  if(innerOnly) return inner;
  return \`<div class="panel" id="envFindingsPanel">\${inner}</div>\`;
}

function getEnvFindingsText(){
  const allBuiltinIds = ENV_PLATFORMS.map(p=>p.id);
  const activeBuiltinIds = allBuiltinIds;
  const customIds  = Object.keys(envFindings).filter(id=>!allBuiltinIds.includes(id));
  const orderedIds = [...activeBuiltinIds, ...customIds].filter(id=>envFindings[id]);

  const entries = orderedIds.map(id=>[id, envFindings[id]]);
  const anyChecked = entries.some(([,f])=>f.status!=='none');

  const out = ['ENVIRONMENT FINDINGS', '-'.repeat(20)];
  if(!anyChecked){
    out.push('  Results - No findings observed at this time.');
  } else {
    for(const id of orderedIds){
      const f = envFindings[id];
      if(f.status === 'none') continue;
      const label = f.status === 'found' ? 'FOUND' : 'NOT FOUND';
      out.push(\`  \${f.name} (\${f.lang}): \${label}\`);
      if(f.status === 'found'){
        const hosts  = (f.hosts ||'').split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
        const events = (f.events||'').split(/\\r?\\n/).map(s=>s.trim()).filter(Boolean);
        if(hosts.length)  out.push(\`    Hosts: \${hosts.join(', ')}\`);
        if(events.length) out.push(\`    Event IDs: \${events.join(', ')}\`);
      }
    }
    const foundWithQueries = orderedIds.filter(id=>envFindings[id]?.status==='found' && envFindings[id]?.cachedHuntQueries);
    if(foundWithQueries.length){
      out.push('');
      out.push('HUNT QUERIES (confirmed found)');
      out.push('-'.repeat(30));
      for(const id of foundWithQueries){
        const f = envFindings[id];
        out.push(\`\n[\${f.name} / \${f.lang}]\n\${f.cachedHuntQueries}\`);
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
        <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="addCustomRec()">+ Add</button>
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
    const dbIOCs = (data.iocs||[]).filter(ioc=>!isBlocklistSource(ioc) && ioc.source !== 'manual');
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
  initEnvFindings();
  const div = document.getElementById('tab-description');
  div.innerHTML='<div class="loading">Loading…</div>';

  let data;
  try { data = await api('/api/iocs?limit=2000'); } catch(e) { data = {error:String(e)}; }
  if(data.error){
    div.innerHTML=\`<div style="padding:20px;color:var(--red);font-size:12px;">Failed to load IOC data. <button class="secondary" style="font-size:11px;padding:2px 8px;margin-left:8px;" onclick="loadDescriptionTab()">↻ Click to retry</button></div>\`;
    return;
  }
  const dbIOCs = (data.iocs??[]).filter(ioc=>!isBlocklistSource(ioc) && ioc.source !== 'manual');

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
      <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="copyDescription()">⧉ Copy All</button>
      <button class="secondary" style="font-size:11px;padding:3px 9px;" onclick="window._descBaseLines=null;loadDescriptionTab()">↻ Reload</button>
    </div>
    <div class="panel">
      <div class="panel-header">📋 Ticket-Ready Description</div>
      <div class="panel-body">
        <pre id="descPre" style="white-space:pre-wrap;max-height:620px;overflow-y:auto;font-size:12px;">\${escHtml(_descText)}</pre>
      </div>
    </div>
    \${renderEnvFindingsPanel(false)}
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
        <button class="secondary" style="font-size:10px;padding:2px 7px;margin-left:auto;"
          onclick="copy(document.getElementById('ticketInfoPre').textContent);showAlert('success','Copied ticket info')">⧉ Copy</button>
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
      <button class="secondary" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="_tiCopyApi('\${cardKey}')">⧉ Copy</button>
    </div>
    <div class="panel-body" id="ti_api_\${cardKey}">\${apiRows||'<div style="font-size:11px;color:var(--text2);">No API sources selected</div>'}</div>
  </div>\`:''}

  <!-- Public Sources -->
  \${PUB_PROVIDERS.some(s=>_tiSources.has(s))?\`
  <div class="panel" style="margin-bottom:10px;">
    <div class="panel-header" style="display:flex;align-items:center;gap:8px;">
      🌐 Public Sources
      <span style="font-size:10px;color:var(--text2);font-weight:400;">— live data, optional score override</span>
      <button class="secondary" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="_tiCopyPub('\${cardKey}')">⧉ Copy</button>
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
      <button class="secondary" style="font-size:10px;padding:2px 7px;margin-left:auto;"
        onclick="copy(document.getElementById('tirpt_\${cardKey}').textContent);showAlert('success','Copied')">⧉ Copy</button>
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

// Render UI immediately — don't block on session init
loadStats(); loadIOCs();
// Session init clears previous-session IOCs in background; refresh and pre-warm description after done
api('/api/session/init', {method:'POST'}).then(()=>{ loadStats(); loadIOCs(); setTimeout(()=>_prefetchDescriptionData(), 500); }).catch(()=>{});
loadTypeNav();
loadFeeds();
tiLoadKeys();
</script>
  <div class="footer">
    Created by <a href="https://github.com/hackdHD" target="_blank" rel="noopener">hAckDHD</a> — <a href="https://github.com/hackdhd" target="_blank" rel="noopener">github.com/hackdhd</a>
  </div>
</body>
</html>`;
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
