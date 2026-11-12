import type { IOCType } from '../types/index.js';

export function normalizeIOC(value: string, type: IOCType): string {
  const v = value.trim();
  switch (type) {
    case 'ip':
    case 'ipv6':
      return v.toLowerCase();
    case 'domain':
    case 'hostname':
      return v.toLowerCase().replace(/\.$/, '');
    case 'url':
      return normalizeUrl(v);
    case 'email':
      return v.toLowerCase();
    case 'sha256':
    case 'sha1':
    case 'md5':
      return v.toLowerCase();
    case 'cve':
      return v.toUpperCase();
    case 'registry_key':
      return normalizeRegistryKey(v);
    default:
      return v;
  }
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    // Remove trailing slash on root paths
    if (u.pathname === '/') u.pathname = '';
    return u.toString();
  } catch {
    return url;
  }
}

function normalizeRegistryKey(key: string): string {
  // Normalize HKEY_ prefix variants
  return key
    .replace(/^HKLM\\/i, 'HKEY_LOCAL_MACHINE\\')
    .replace(/^HKCU\\/i, 'HKEY_CURRENT_USER\\')
    .replace(/^HKCR\\/i, 'HKEY_CLASSES_ROOT\\')
    .replace(/^HKU\\/i, 'HKEY_USERS\\')
    .replace(/^HKCC\\/i, 'HKEY_CURRENT_CONFIG\\');
}

// Strip port numbers from IPs like 1.2.3.4:8080
export function stripPort(value: string): string {
  const portMatch = value.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$/);
  return portMatch ? portMatch[1] : value;
}

// Extract domain from URL for cross-referencing
export function extractDomainFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}
