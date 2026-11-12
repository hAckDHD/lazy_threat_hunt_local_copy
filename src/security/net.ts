import { lookup } from 'dns/promises';
import { isIP } from 'net';

// ── SSRF guard ───────────────────────────────────────────────────────────────
// Every server-side fetch of a user-supplied URL must go through
// fetchPublicURL(), which validates the target before the request AND
// re-validates every redirect hop, so a public URL cannot 30x-bounce the
// server into an internal address.

function ip2n(ip: string): number {
  return ip.split('.').reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0;
}

function inCidr(n: number, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (n & mask) === (ip2n(base) & mask);
}

const BLOCKED_V4: Array<[string, number]> = [
  ['0.0.0.0', 8],        // "this" network
  ['10.0.0.0', 8],       // private
  ['100.64.0.0', 10],    // carrier-grade NAT
  ['127.0.0.0', 8],      // loopback
  ['169.254.0.0', 16],   // link-local / cloud metadata
  ['172.16.0.0', 12],    // private
  ['192.0.0.0', 24],     // IETF protocol assignments
  ['192.0.2.0', 24],     // TEST-NET-1
  ['192.88.99.0', 24],   // 6to4 relay
  ['192.168.0.0', 16],   // private
  ['198.18.0.0', 15],    // benchmarking
  ['198.51.100.0', 24],  // TEST-NET-2
  ['203.0.113.0', 24],   // TEST-NET-3
  ['224.0.0.0', 4],      // multicast
  ['240.0.0.0', 4],      // reserved + broadcast
];

export function isPrivateIPv4(ip: string): boolean {
  const n = ip2n(ip);
  return BLOCKED_V4.some(([base, bits]) => inCidr(n, base, bits));
}

export function isPrivateIPv6(ip: string): boolean {
  const l = ip.toLowerCase();
  if (l === '::' || l === '::1') return true;
  // IPv4-mapped / IPv4-compatible / NAT64 / 6to4 can all smuggle an internal v4 address
  if (l.startsWith('::ffff:') || l.startsWith('::') || l.startsWith('64:ff9b:') || l.startsWith('2002:')) return true;
  // fc00::/7 unique-local, fe80::/10 link-local, fec0::/10 site-local, ff00::/8 multicast
  return /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || /^fe[c-f]/.test(l) || l.startsWith('ff');
}

interface ResolvedTarget { url: URL; address?: string; family?: number }

// Validate a URL and, for host names, return one address that passed the
// check so the caller can connect to exactly that address.
async function resolvePublicTarget(urlStr: string): Promise<ResolvedTarget> {
  let parsed: URL;
  try { parsed = new URL(urlStr); } catch { throw new Error('Invalid URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error(`Protocol not allowed: ${parsed.protocol}`);
  if (parsed.username || parsed.password) throw new Error('Invalid URL: credentials not allowed');
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  const kind = isIP(hostname);
  if (kind === 4) {
    if (isPrivateIPv4(hostname)) throw new Error('Private/internal IP not allowed');
    return { url: parsed };
  }
  if (kind === 6) {
    if (isPrivateIPv6(hostname)) throw new Error('Private IPv6 not allowed');
    return { url: parsed };
  }
  let addrs: Array<{ address: string; family: number }>;
  try { addrs = await lookup(hostname, { all: true }); } catch { throw new Error('DNS resolution failed'); }
  if (!addrs.length) throw new Error('DNS resolution failed');
  for (const { address, family } of addrs) {
    if (family === 4 && isPrivateIPv4(address)) throw new Error('Resolves to private IP');
    if (family === 6 && isPrivateIPv6(address)) throw new Error('Resolves to private IPv6');
  }
  const pick = addrs.find(a => a.family === 4) ?? addrs[0];
  return { url: parsed, address: pick.address, family: pick.family };
}

export async function validateSSRFUrl(urlStr: string): Promise<URL> {
  return (await resolvePublicTarget(urlStr)).url;
}

// Build the request so it connects to the address that was validated, not to
// whatever a second DNS lookup returns (DNS rebinding). The Host header and
// TLS server name stay the real host name, so virtual hosting and certificate
// checks are unchanged. Needs Bun's fetch; other runtimes use the plain URL.
function pinnedRequest(target: ResolvedTarget, headers: Record<string, string> | undefined): { url: string; init: RequestInit } {
  const { url, address, family } = target;
  if (!address || !process.versions.bun) return { url: url.toString(), init: { headers } };
  const pinned = new URL(url.toString());
  pinned.hostname = family === 6 ? `[${address}]` : address;
  return {
    url: pinned.toString(),
    init: { headers: { ...headers, Host: url.host }, tls: { serverName: url.hostname } } as RequestInit,
  };
}

export interface PublicFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  headers?: Record<string, string>;
}

export interface PublicFetchResult {
  finalUrl: string;
  status: number;
  contentType: string;
  body: string;
}

// Fetch a user-supplied URL with SSRF validation on every hop, a hard
// timeout, and a cap on the number of body bytes read into memory.
export async function fetchPublicURL(urlStr: string, opts: PublicFetchOptions = {}): Promise<PublicFetchResult> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const maxBytes = opts.maxBytes ?? 10 * 1024 * 1024;
  const maxRedirects = opts.maxRedirects ?? 5;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let current = urlStr;
    for (let hop = 0; ; hop++) {
      const request = pinnedRequest(await resolvePublicTarget(current), opts.headers);
      const res = await fetch(request.url, { ...request.init, signal: controller.signal, redirect: 'manual' });
      if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
        if (hop >= maxRedirects) throw new Error('Too many redirects');
        current = new URL(res.headers.get('location')!, current).toString();
        try { await res.body?.cancel(); } catch {}
        continue;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
      const declared = Number(res.headers.get('content-length') ?? 0);
      if (declared > maxBytes) throw new Error('Remote content too large');
      const body = await readCapped(res, maxBytes);
      return { finalUrl: current, status: res.status, contentType: res.headers.get('content-type') ?? '', body };
    }
  } finally {
    clearTimeout(timer);
  }
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw new Error('Remote content too large');
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}
