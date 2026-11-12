import type { IOC, IOCType, HuntTimeRange } from '../types/index.js';

export const VALID_IOC_TYPES = new Set<IOCType>([
  'ip', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve', 'hostname', 'registry_key', 'filename',
]);

// Control characters (incl. CR/LF) let a value break out of a single line of a
// generated query/rule and inject extra clauses, so they are never allowed.
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

// Shape check applied to every IOC before it is templated into a hunt query
// or detection rule. Strict for fixed-format types, permissive-but-safe for
// free-form types (urls, registry keys, filenames), whose per-language quoting
// is handled by each generator.
export function isSafeQueryValue(value: unknown, type: unknown): boolean {
  if (typeof value !== 'string' || typeof type !== 'string') return false;
  if (!VALID_IOC_TYPES.has(type as IOCType)) return false;
  if (!value || value.length > 2048 || CONTROL_CHARS.test(value)) return false;
  switch (type) {
    case 'ip':       return /^(\d{1,3}\.){3}\d{1,3}$/.test(value);
    case 'ipv6':     return /^[0-9a-fA-F:.]+$/.test(value) && value.length <= 45;
    case 'sha256':   return /^[a-fA-F0-9]{64}$/.test(value);
    case 'sha1':     return /^[a-fA-F0-9]{40}$/.test(value);
    case 'md5':      return /^[a-fA-F0-9]{32}$/.test(value);
    case 'cve':      return /^CVE-\d{4}-\d{4,}$/i.test(value);
    case 'domain':
    case 'hostname': return /^[a-zA-Z0-9_.-]+$/.test(value) && value.length <= 253;
    case 'email':    return /^[^\s@"'`<>\\]+@[a-zA-Z0-9.-]+$/.test(value);
    default:         return true;
  }
}

export function filterSafeQueryIOCs<T extends Pick<IOC, 'value' | 'type'>>(iocs: T[]): T[] {
  return iocs.filter(i => isSafeQueryValue(i.value, i.type));
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
const RELATIVE = new Set(['1d', '7d', '14d', '30d', '90d']);

// Time ranges are templated raw into several query languages — only accept
// the two documented shapes with strictly formatted values.
export function sanitizeTimeRange(tr: unknown): HuntTimeRange | undefined {
  if (!tr || typeof tr !== 'object') return undefined;
  const t = tr as Record<string, unknown>;
  if (t.type === 'relative' && typeof t.relative === 'string' && RELATIVE.has(t.relative)) {
    return { type: 'relative', relative: t.relative } as HuntTimeRange;
  }
  if (t.type === 'absolute' && typeof t.start === 'string' && typeof t.end === 'string'
      && ISO_DATE.test(t.start) && ISO_DATE.test(t.end)) {
    return { type: 'absolute', start: t.start, end: t.end } as HuntTimeRange;
  }
  return undefined;
}
