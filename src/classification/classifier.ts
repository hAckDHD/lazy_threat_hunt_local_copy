import type { IOC, IOCClassification } from '../types/index.js';

// Heuristic rules for classification before enrichment data is available
const MALICIOUS_TLDS = new Set(['.onion', '.bit', '.i2p', '.bazar', '.coin', '.lib']);

const SUSPICIOUS_PATTERNS = [
  /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\./, // IP-looking domain
  /[a-z0-9]{25,}\.(com|net|org|info)$/i, // DGA-like long subdomain
  /[0-9a-f]{8,}\.(xyz|top|pw|club|tk|ml|ga|cf|gq)$/i, // hex + cheap TLD
  /update.*\.(xyz|top|pw|club|info)$/i,
  /secure.*\.(xyz|top|pw)$/i,
  /login.*\.(xyz|top|pw)$/i,
];

const SUSPICIOUS_IP_RANGES = [
  /^5\.188\./,     // Common C2 hosting
  /^185\.220\./,   // Tor exit nodes
  /^45\.142\./,    // Bulletproof hosting
  /^91\.108\./,    // Telegram (also used for C2)
];

export function classifyHeuristic(ioc: IOC): IOCClassification {
  // Already classified by enrichment — don't downgrade
  if (ioc.classification === 'malicious') return 'malicious';

  if (ioc.enrichment?.reputationScore !== undefined) {
    if (ioc.enrichment.reputationScore >= 70) return 'malicious';
    if (ioc.enrichment.reputationScore >= 30) return 'suspicious';
    return 'unknown';
  }

  // Heuristic pre-enrichment classification
  switch (ioc.type) {
    case 'domain': {
      const v = ioc.value.toLowerCase();
      if (MALICIOUS_TLDS.has('.' + v.split('.').pop())) return 'malicious';
      if (SUSPICIOUS_PATTERNS.some(p => p.test(v))) return 'suspicious';
      if (isDGA(v)) return 'suspicious';
      break;
    }
    case 'ip': {
      if (SUSPICIOUS_IP_RANGES.some(r => r.test(ioc.value))) return 'suspicious';
      break;
    }
    case 'url': {
      try {
        const host = new URL(ioc.value).hostname;
        const domainIoc = { ...ioc, value: host, type: 'domain' as const };
        return classifyHeuristic(domainIoc);
      } catch {
        break;
      }
    }
  }

  return ioc.classification === 'unknown' ? 'unknown' : ioc.classification;
}

// Simple DGA detector — high consonant ratio + random-looking character distribution
function isDGA(domain: string): boolean {
  const label = domain.split('.')[0];
  if (label.length < 10) return false;

  const vowels = (label.match(/[aeiou]/gi) ?? []).length;
  const ratio = vowels / label.length;
  if (ratio < 0.15) return true; // Very few vowels

  // Check entropy
  const freq: Record<string, number> = {};
  for (const c of label) freq[c] = (freq[c] ?? 0) + 1;
  const entropy = Object.values(freq).reduce((e, count) => {
    const p = count / label.length;
    return e - p * Math.log2(p);
  }, 0);

  return entropy > 3.8; // High entropy → likely DGA
}

export function classifyBatch(iocs: IOC[]): IOC[] {
  return iocs.map(ioc => ({
    ...ioc,
    classification: classifyHeuristic(ioc),
  }));
}

// Classify by tags set by the user
export function classifyByTag(
  ioc: IOC,
  tag: string
): IOCClassification {
  const tagMap: Record<string, IOCClassification> = {
    malicious: 'malicious',
    bad: 'malicious',
    c2: 'malicious',
    suspicious: 'suspicious',
    suspect: 'suspicious',
    internal: 'internal',
    whitelist: 'external',
    external: 'external',
  };
  return tagMap[tag.toLowerCase()] ?? ioc.classification;
}
