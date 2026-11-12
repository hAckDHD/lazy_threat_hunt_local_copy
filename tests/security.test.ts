import { describe, test, expect } from 'bun:test';
import { isPrivateIPv4, isPrivateIPv6, validateSSRFUrl } from '../src/security/net.js';
import { isSafeQueryValue, sanitizeTimeRange } from '../src/security/validate.js';
import { generateHuntQueries } from '../src/hunting/index.js';
import { handleRequest } from '../src/ui/server.js';
import type { IOC } from '../src/types/index.js';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// Keep the test DB out of the real ~/.ioc-tool data directory.
delete process.env.TURSO_DATABASE_URL;
process.env.IOC_DATA_DIR = mkdtempSync(join(tmpdir(), 'lth-test-'));

describe('SSRF guard', () => {
  test('blocks private, loopback, link-local and metadata IPv4', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255']) {
      expect(isPrivateIPv4(ip)).toBe(true);
    }
  });

  test('allows public IPv4', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '93.184.216.34']) {
      expect(isPrivateIPv4(ip)).toBe(false);
    }
  });

  test('blocks internal IPv6 forms', () => {
    for (const ip of ['::1', '::', '::ffff:127.0.0.1', 'fe80::1', 'fc00::1', 'fd12::1', '64:ff9b::7f00:1', 'ff02::1']) {
      expect(isPrivateIPv6(ip)).toBe(true);
    }
    expect(isPrivateIPv6('2606:4700:4700::1111')).toBe(false);
  });

  test('rejects non-http protocols, credentials and literal internal hosts', async () => {
    await expect(validateSSRFUrl('file:///etc/passwd')).rejects.toThrow();
    await expect(validateSSRFUrl('gopher://example.com')).rejects.toThrow();
    await expect(validateSSRFUrl('http://user:pass@example.com')).rejects.toThrow();
    await expect(validateSSRFUrl('http://127.0.0.1:8847/')).rejects.toThrow();
    await expect(validateSSRFUrl('http://2130706433/')).rejects.toThrow(); // decimal 127.0.0.1
    await expect(validateSSRFUrl('http://[::1]/')).rejects.toThrow();
    await expect(validateSSRFUrl('http://169.254.169.254/latest/meta-data/')).rejects.toThrow();
  });
});

describe('query value validation', () => {
  test('rejects control characters that could inject new query lines', () => {
    expect(isSafeQueryValue('http://x/a\nDROP', 'url')).toBe(false);
    expect(isSafeQueryValue('evil.com\r\n', 'domain')).toBe(false);
  });

  test('enforces strict formats for fixed-shape types', () => {
    expect(isSafeQueryValue('1.2.3.4', 'ip')).toBe(true);
    expect(isSafeQueryValue('1.2.3.4" OR 1=1', 'ip')).toBe(false);
    expect(isSafeQueryValue('a'.repeat(64), 'sha256')).toBe(true);
    expect(isSafeQueryValue('zz' + 'a'.repeat(62), 'sha256')).toBe(false);
    expect(isSafeQueryValue('x', 'not_a_type')).toBe(false);
  });

  test('hunt generator drops unsafe values', () => {
    const iocs: IOC[] = [
      { id: '1', value: '1.2.3.4\n| delete', type: 'ip', classification: 'malicious', source: 'manual', extractedAt: '', tags: [] },
    ];
    expect(generateHuntQueries(iocs, 'all')).toHaveLength(0);
  });

  test('backslash before a quote cannot escape the KQL string', () => {
    const iocs: IOC[] = [
      { id: '1', value: 'C:\\evil\\"; drop', type: 'filename', classification: 'malicious', source: 'manual', extractedAt: '', tags: [] },
    ];
    const kql = generateHuntQueries(iocs, 'kql');
    for (const q of kql) expect(q.query).not.toContain('\\\\"; drop"');
  });

  test('time range only accepts documented shapes', () => {
    expect(sanitizeTimeRange({ type: 'relative', relative: '7d' })).toEqual({ type: 'relative', relative: '7d' });
    expect(sanitizeTimeRange({ type: 'absolute', start: '2024-01-01', end: '2024-02-01' })).toBeTruthy();
    expect(sanitizeTimeRange({ type: 'absolute', start: '2024-01-01") | evil', end: '2024-02-01' })).toBeUndefined();
    expect(sanitizeTimeRange({ type: 'relative', relative: '1y' })).toBeUndefined();
  });
});

describe('HTTP handler', () => {
  const base = 'http://localhost:8847';

  test('rejects cross-origin state-changing requests', async () => {
    const res = await handleRequest(new Request(`${base}/api/session/init`, {
      method: 'POST',
      headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' },
      body: '{}',
    }));
    expect(res.status).toBe(403);
  });

  test('rejects oversized bodies by Content-Length', async () => {
    const res = await handleRequest(new Request(`${base}/api/ingest/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(50 * 1024 * 1024) },
      body: '{}',
    }));
    expect(res.status).toBe(413);
  });

  test('returns 400 for malformed JSON instead of 500', async () => {
    const res = await handleRequest(new Request(`${base}/api/extract/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not json',
    }));
    expect(res.status).toBe(400);
  });

  test('extract endpoint works end to end', async () => {
    const res = await handleRequest(new Request(`${base}/api/extract/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'C2 at 45.33.32.156 and evil-domain.example' }),
    }));
    expect(res.status).toBe(200);
    const body = await res.json() as { iocs: Array<{ value: string; type: string }> };
    expect(body.iocs.some(i => i.value === '45.33.32.156')).toBe(true);
  });

  test('ingest/url refuses internal targets', async () => {
    const res = await handleRequest(new Request(`${base}/api/ingest/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://169.254.169.254/latest/meta-data/' }),
    }));
    expect(res.status).toBe(400);
  });

  test('sends security headers', async () => {
    const res = await handleRequest(new Request(`${base}/api/stats`));
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
  });
});

describe('static files and caching', () => {
  const get = (path: string) => handleRequest(new Request('http://127.0.0.1:8847' + path));

  test('serves only the allow-listed assets', async () => {
    for (const path of ['/cheatsheet.js', '/detection.js', '/ttp-library.js', '/fonts/ChakraPetch-Bold.woff2']) {
      const res = await get(path);
      expect(res.status).toBe(200);
      expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    }
  });

  test('never maps a request path onto the file system', async () => {
    for (const path of ['/package.json', '/.env', '/src/cli.ts', '/public/detection.js', '/fonts/../package.json', '/%2e%2e/package.json', '/detection.js/..%2f..%2fpackage.json', '/constructor', '/__proto__']) {
      expect((await get(path)).status).toBe(404);
    }
  });

  test('API responses are not cacheable', async () => {
    const res = await get('/api/stats');
    expect(res.headers.get('cache-control')).toBe('no-store');
  });
});

describe('PDF upload', () => {
  // Smallest valid one-page PDF with a line of text.
  function tinyPDF(line: string): Buffer {
    const stream = `BT /F1 12 Tf 72 720 Td (${line}) Tj ET`;
    const objs = [
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    ];
    let out = '%PDF-1.4\n';
    const offsets: number[] = [];
    objs.forEach((o, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${o}\nendobj\n`; });
    const xref = out.length;
    out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` + offsets.map(o => String(o).padStart(10, '0') + ' 00000 n \n').join('');
    out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
    return Buffer.from(out, 'latin1');
  }

  test('extracts IOCs from a PDF', async () => {
    const { parseBuffer } = await import('../src/ingestion/file-parser.js');
    const result = await parseBuffer(tinyPDF('Beacon to 45.33.32.156 seen'), 'application/pdf', 'report.pdf');
    expect(result.iocs.map(i => i.value)).toContain('45.33.32.156');
  });

  test('rejects a file that only claims to be a PDF', async () => {
    const { parseBuffer } = await import('../src/ingestion/file-parser.js');
    await expect(parseBuffer(Buffer.from('MZ not a pdf'), 'application/pdf', 'evil.pdf')).rejects.toThrow('Unsupported file type');
  });
});
