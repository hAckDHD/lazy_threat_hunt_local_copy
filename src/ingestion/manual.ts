import { extract } from '../extractor/index.js';
import type { IOC, ExtractionResult } from '../types/index.js';

// Parse a single known IOC value submitted by the user
export function parseManualIOC(value: string): ExtractionResult {
  return extract(value, { source: 'manual' });
}

// Parse multi-line bulk paste or CSV/TXT content submitted manually
export function parseBulkText(text: string): ExtractionResult {
  return extract(text, { source: 'manual' });
}

// Parse CSV rows where one column contains IOC values
export function parseCSVText(csvText: string): ExtractionResult {
  // Flatten CSV into plain text — the extractor handles pattern matching
  const lines = csvText.split('\n').map(l => l.replace(/,/g, ' ')).join('\n');
  return extract(lines, { source: 'manual' });
}

// Parse JSON threat feed where IOC values may be nested
export function parseJSONFeed(jsonText: string): ExtractionResult {
  let flat: string;
  try {
    const parsed = JSON.parse(jsonText);
    flat = flattenJSON(parsed);
  } catch {
    flat = jsonText;
  }
  return extract(flat, { source: 'feed' });
}

function flattenJSON(obj: unknown, depth = 0): string {
  if (depth > 10) return '';
  if (typeof obj === 'string') return obj;
  if (typeof obj === 'number' || typeof obj === 'boolean') return String(obj);
  if (Array.isArray(obj)) return obj.map(i => flattenJSON(i, depth + 1)).join('\n');
  if (obj && typeof obj === 'object') {
    return Object.values(obj as Record<string, unknown>)
      .map(v => flattenJSON(v, depth + 1))
      .join('\n');
  }
  return '';
}
