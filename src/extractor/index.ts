import { randomUUID } from 'crypto';
import type { IOC, IOCType, IOCClassification, IOCSource, ExtractionResult } from '../types/index.js';
import { PATTERNS, defang } from './patterns.js';
import { normalizeIOC, stripPort } from './normalizer.js';
import { runPlugins, postProcessWithPlugins } from './plugins/registry.js';

export interface ExtractorOptions {
  source: IOCSource;
  sourceUrl?: string;
  sourceFile?: string;
  skipPrivateIPs?: boolean;
  skipNoiseDomains?: boolean;
  includeHostnames?: boolean;
  tags?: string[];
}

// Core IOC extraction engine — standalone, callable independently from the UI
export function extract(
  rawText: string,
  options: ExtractorOptions
): ExtractionResult {
  const text = defang(rawText);
  const seen = new Map<string, IOC>(); // deduplicate by normalized value+type
  const now = new Date().toISOString();

  // Track which char positions are already claimed by a higher-priority pattern
  // to prevent SHA256 from also matching as SHA1+MD5 etc.
  const claimedRanges: Array<[number, number]> = [];

  function isClaimed(start: number, end: number): boolean {
    return claimedRanges.some(([s, e]) => start < e && end > s);
  }

  for (const def of PATTERNS.sort((a, b) => b.priority - a.priority)) {
    if (def.type === 'hostname' && !options.includeHostnames) continue;

    const re = new RegExp(def.pattern.source, def.pattern.flags);
    let m: RegExpExecArray | null;

    while ((m = re.exec(text)) !== null) {
      const raw = m[0];
      const start = m.index;
      const end = start + raw.length;

      if (isClaimed(start, end)) continue;

      let value = normalizeIOC(raw, def.type);

      // Strip port from IPs
      if (def.type === 'ip') value = stripPort(value);

      if (def.validate && !def.validate(value)) continue;

      const key = `${def.type}:${value}`;
      if (seen.has(key)) continue;

      claimedRanges.push([start, end]);

      const ioc: IOC = {
        id: randomUUID(),
        value,
        type: def.type,
        classification: 'unknown',
        source: options.source,
        sourceUrl: options.sourceUrl,
        sourceFile: options.sourceFile,
        extractedAt: now,
        tags: options.tags ? [...options.tags] : [],
      };

      seen.set(key, ioc);
    }
  }

  // Run registered plugins for format-specific extraction (STIX, MISP, etc.)
  const pluginIOCs = runPlugins(text, Array.from(seen.values()));
  for (const ioc of pluginIOCs) {
    const key = `${ioc.type}:${ioc.value}`;
    if (!seen.has(key)) seen.set(key, ioc);
  }

  let iocs = postProcessWithPlugins(Array.from(seen.values()));

  const byType: Partial<Record<IOCType, number>> = {};
  for (const ioc of iocs) {
    byType[ioc.type] = (byType[ioc.type] ?? 0) + 1;
  }

  return {
    iocs,
    sourceUrl: options.sourceUrl,
    sourceFile: options.sourceFile,
    rawText,
    extractedAt: now,
    stats: {
      total: iocs.length,
      byType,
      duplicatesRemoved: 0, // tracked in ingestion layer when merging with DB
    },
  };
}

// Convenience: extract from plain string with minimal options
export function extractFromText(
  text: string,
  source: IOCSource = 'manual'
): IOC[] {
  return extract(text, { source }).iocs;
}

