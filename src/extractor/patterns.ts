import type { IOCType } from '../types/index.js';

export interface PatternDefinition {
  type: IOCType;
  pattern: RegExp;
  priority: number;   // higher = checked first; used for hash disambiguation
  validate?: (match: string) => boolean;
}

// Defang transformations — convert common threat-intel obfuscation back to canonical form
export function defang(text: string): string {
  return text
    .replace(/hxxp(s?):\/\//gi, 'http$1://')
    .replace(/\[dot\]/gi, '.')
    .replace(/\[\.\]/g, '.')
    .replace(/\(dot\)/gi, '.')
    .replace(/\[at\]/gi, '@')
    .replace(/\[@\]/g, '@')
    .replace(/\[:\]/g, ':')
    .replace(/\.{0,1}\[\.{0,1}\]\.{0,1}/g, '.')
    // common bracket obfuscation e.g. 192[.]168[.]1[.]1
    .replace(/\[(\w)\]/g, '$1');
}

// Private/reserved IP ranges to skip when extracting IPs
const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^0\.0\.0\.0$/,
  /^255\.255\.255\.255$/,
  /^169\.254\./,
  /^::1$/,
  /^fe80:/i,
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

// Common noise domains — skip extracting these
// Subdomain matching is automatic: api.github.com filtered because github.com is here
const NOISE_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net',
  'localhost', 'local',
  'google.com', 'youtube.com', 'microsoft.com', 'office.com', 'live.com',
  'amazon.com', 'amazonaws.com', 'cloudflare.com',
  'github.com', 'githubusercontent.com', 'githubassets.com',
  'schema.org', 'w3.org', 'mozilla.org',
  'jquery.com', 'bootstrapcdn.com',
  'slack.com', 'discord.com', 'twitter.com', 'x.com', 'linkedin.com',
  'npmjs.com', 'pypi.org', 'rubygems.org', 'crates.io',
  'hub.docker.com', 'docker.com',
  'aquasecurity.io', 'aquasec.com',   // legit vendor — typosquats are still caught
  'socket.dev',                        // source site itself
  'virustotal.com', 'abuseipdb.com',   // tool URLs from article links
]);

// Script/binary file extensions that are also ccTLDs — treat as filename, not domain
const SCRIPT_TLDS = new Set(['sh', 'py', 'pl', 'rb', 'lua', 'ps1', 'bat', 'cmd']);

function isNoiseDomain(domain: string): boolean {
  const lower = domain.toLowerCase().replace(/^www\./, '');
  if (NOISE_DOMAINS.has(lower)) return true;
  // Check every parent label: hooks.slack.com → slack.com → in noise
  const parts = lower.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (NOISE_DOMAINS.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

function isScriptFilename(domain: string): boolean {
  const parts = domain.split('.');
  const tld = parts[parts.length - 1].toLowerCase();
  // single-label.scriptExt with no digits = almost certainly a filename, not a domain
  return SCRIPT_TLDS.has(tld) && parts.length === 2 && !/\d/.test(parts[0]);
}

function noiseURL(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return isNoiseDomain(host);
  } catch { return false; }
}

// Hash disambiguation: MD5=32, SHA1=40, SHA256=64
const HEX_ONLY = /^[a-f0-9]+$/i;

export const PATTERNS: PatternDefinition[] = [
  {
    type: 'cve',
    priority: 100,
    pattern: /\bCVE-\d{4}-\d{4,7}\b/gi,
  },
  {
    type: 'registry_key',
    priority: 95,
    pattern: /\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)(?:\\[^\\\s<>"']+)+/gi,
  },
  {
    type: 'sha256',
    priority: 90,
    pattern: /\b[a-f0-9]{64}\b/gi,
    validate: (m) => HEX_ONLY.test(m),
  },
  {
    type: 'sha1',
    priority: 85,
    pattern: /\b[a-f0-9]{40}\b/gi,
    validate: (m) => HEX_ONLY.test(m),
  },
  {
    type: 'md5',
    priority: 80,
    pattern: /\b[a-f0-9]{32}\b/gi,
    validate: (m) => HEX_ONLY.test(m),
  },
  {
    type: 'email',
    priority: 75,
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  },
  {
    type: 'url',
    priority: 70,
    pattern: /https?:\/\/[^\s<>"'`\[\]{}|\\^]+/gi,
    validate: (m) => {
      if (noiseURL(m)) return false;
      // Drop URLs with shell variable interpolation or obvious template artifacts
      if (/\$\{?[A-Z_]|\$[0-9]/.test(m)) return false;
      return true;
    },
  },
  {
    type: 'ipv6',
    priority: 65,
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b/g,
  },
  {
    type: 'ip',
    priority: 60,
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    validate: (m) => !isPrivateIP(m),
  },
  {
    type: 'domain',
    priority: 50,
    // Matches FQDNs — won't catch single-label hostnames
    pattern: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|mil|edu|co|uk|de|fr|ru|cn|jp|br|au|nl|se|no|fi|it|es|info|biz|name|mobi|travel|aero|coop|museum|pro|tel|xxx|int|ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cr|cu|cv|cx|cy|cz|dj|dk|dm|do|dz|ec|ee|eg|eh|er|et|eu|fi|fj|fk|fm|fo|ga|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|iq|ir|is|je|jm|jo|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|rw|sa|sb|sc|sd|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|onion|bit|i2p)\b/gi,
    validate: (m) => !isNoiseDomain(m) && !isScriptFilename(m),
  },
  {
    type: 'hostname',
    priority: 40,
    // Single-label or short hostnames common in internal reports
    pattern: /\b[a-zA-Z][a-zA-Z0-9\-]{2,63}\b/g,
    validate: (m) => {
      // Only keep if looks like a hostname, not a common word
      return /[0-9]/.test(m) || /-/.test(m);
    },
  },
  {
    type: 'filename',
    priority: 72,
    // Executables, scripts, and suspicious file extensions in reports
    // com removed — it's a TLD >99% of the time in threat intel text
    pattern: /\b[\w\-]{1,64}\.(exe|dll|bat|ps1|vbs|js|jar|sh|py|pl|php|asp|aspx|jsp|hta|cmd|scr|pif|sys|msi|msp|lnk|doc|docx|xls|xlsx|pdf|zip|rar|7z|tar|gz)\b/gi,
    validate: (m) => {
      const name = m.split('.')[0].toLowerCase();
      // Skip generic names and things that look like FQDNs (base.ext where ext is also a TLD)
      if (['index', 'readme', 'default', 'style', 'main', 'app', 'base'].includes(name)) return false;
      // Reject if it matches a known domain pattern (letters-only base + common TLD-like ext)
      const ext = m.split('.').pop()!.toLowerCase();
      const looksLikeDomain = /^[a-z]+$/.test(name) && ['net', 'org', 'io', 'co', 'gov', 'edu'].includes(ext);
      return !looksLikeDomain;
    },
  },
  {
    type: 'filename',
    priority: 71,
    // Windows absolute paths
    pattern: /[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n\s]+\\)*[^\\/:*?"<>|\r\n\s]+\.[a-zA-Z]{2,6}/g,
  },
  {
    type: 'filename',
    priority: 70,
    // Linux/Unix suspicious paths
    pattern: /\/(?:tmp|var\/tmp|proc|dev\/shm)\/[\w.\-]{2,64}/g,
  },
];

// Map from IOCType to the pattern definition for fast lookup
export const PATTERN_MAP = new Map<IOCType, PatternDefinition>(
  PATTERNS.map(p => [p.type, p])
);
