import { extract } from '../extractor/index.js';
import type { ExtractionResult } from '../types/index.js';

interface ScrapeOptions {
  timeout?: number;
  userAgent?: string;
  followRedirects?: boolean;
}

const DEFAULT_UA =
  'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0';

export async function scrapeURL(
  url: string,
  opts: ScrapeOptions = {}
): Promise<ExtractionResult> {
  validateURL(url);

  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(),
    opts.timeout ?? 30_000
  );

  let html: string;
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': opts.userAgent ?? DEFAULT_UA },
      signal: controller.signal,
      redirect: opts.followRedirects === false ? 'manual' : 'follow',
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
    }

    const contentType = res.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      const json = await res.text();
      return extract(json, { source: 'scraper', sourceUrl: url, tags: ['scraped'] });
    }

    html = await res.text();
  } finally {
    clearTimeout(timer);
  }

  const text = extractTextFromHTML(html);
  return extract(text, {
    source: 'scraper',
    sourceUrl: url,
    tags: ['scraped'],
  });
}

function validateURL(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }
  // Block SSRF against internal ranges
  const host = parsed.hostname;
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  ) {
    throw new Error(`Blocked internal address: ${host}`);
  }
}

function extractTextFromHTML(html: string): string {
  // Remove <script> and <style> blocks entirely
  let text = html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ');

  // Replace block-level tags with newlines
  text = text.replace(/<\/?(p|div|br|li|tr|th|td|h[1-6]|pre|blockquote)[^>]*>/gi, '\n');

  // Strip remaining tags
  text = text.replace(/<[^>]+>/g, ' ');

  // Decode basic HTML entities
  text = decodeEntities(text);

  // Collapse whitespace
  return text.replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function decodeEntities(text: string): string {
  return text
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export async function scrapeMultipleURLs(
  urls: string[],
  opts: ScrapeOptions = {}
): Promise<ExtractionResult[]> {
  return Promise.all(urls.map(u => scrapeURL(u, opts)));
}
