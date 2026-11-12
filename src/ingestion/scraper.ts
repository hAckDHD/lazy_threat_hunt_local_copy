import { extract } from '../extractor/index.js';
import type { ExtractionResult } from '../types/index.js';
import { fetchPublicURL } from '../security/net.js';

const MAX_SCRAPE_BYTES = 10 * 1024 * 1024;

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
  // SSRF-safe fetch: validates the target and every redirect hop against
  // private/internal ranges, and caps the response size.
  const res = await fetchPublicURL(url, {
    timeoutMs: opts.timeout ?? 30_000,
    maxRedirects: opts.followRedirects === false ? 0 : 5,
    maxBytes: MAX_SCRAPE_BYTES,
    headers: { 'User-Agent': opts.userAgent ?? DEFAULT_UA },
  });

  if (res.contentType.includes('application/json')) {
    return extract(res.body, { source: 'scraper', sourceUrl: url, tags: ['scraped'] });
  }

  const text = extractTextFromHTML(res.body);
  return extract(text, {
    source: 'scraper',
    sourceUrl: url,
    tags: ['scraped'],
  });
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
