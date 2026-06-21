import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// SentinelOne Deep Visibility — S1QL v2 (dot notation, SQL-like subset)
// Reference: SentinelOne Query Language based on SQL subset
// v2: dot notation for field parameters, expanded char limits
// SELECT ... FROM deep_visibility WHERE ... LIMIT ...

function timeWhere(options?: HuntOptions, prefix = 'AND'): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    // Map relative strings to SQL interval
    const intervalMap: Record<string, string> = {
      '1d': '1 DAY', '7d': '7 DAY', '14d': '14 DAY',
      '30d': '30 DAY', '90d': '90 DAY',
    };
    const interval = intervalMap[tr.relative] ?? '7 DAY';
    return `\n  ${prefix} event.time > DATE_SUB(NOW(), INTERVAL ${interval})`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return `\n  ${prefix} event.time BETWEEN '${tr.start}' AND '${tr.end}'`;
  }
  return '';
}

function inClause(field: string, values: string[]): string {
  return `${field} IN (${values.map(v => `'${v.replace(/'/g, "\\'")}'`).join(', ')})`;
}

export function s1qlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tw = timeWhere(options);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `-- SentinelOne Deep Visibility — IP IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  network.source.ip,
  network.destination.ip,
  network.destination.port,
  process.name,
  process.user
FROM deep_visibility
WHERE (
  ${inClause('network.source.ip', values)}
  OR ${inClause('network.destination.ip', values)}
)${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} IP IOC(s) in network telemetry`;
      break;

    case 'domain':
    case 'hostname':
      query = `-- SentinelOne Deep Visibility — Domain/Hostname IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  network.dns.request,
  network.destination.ip,
  process.name,
  process.user
FROM deep_visibility
WHERE (
  ${inClause('network.dns.request', values)}
  OR ${inClause('network.destination.name', values)}
)${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} domain IOC(s) in DNS and network events`;
      break;

    case 'url':
      query = `-- SentinelOne Deep Visibility — URL IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  network.url,
  network.destination.ip,
  network.destination.port,
  process.name,
  process.user
FROM deep_visibility
WHERE (
  ${inClause('network.url', values)}
)${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} URL IOC(s) in HTTP/web telemetry`;
      break;

    case 'sha256':
      query = `-- SentinelOne Deep Visibility — SHA256 Hash IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  process.name,
  process.image.path,
  process.image.sha256,
  process.user,
  process.cmd_line
FROM deep_visibility
WHERE ${inClause('process.image.sha256', values)}${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} SHA256 hash(es) across process events`;
      break;

    case 'sha1':
      query = `-- SentinelOne Deep Visibility — SHA1 Hash IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  process.name,
  process.image.path,
  process.image.sha1,
  process.user
FROM deep_visibility
WHERE ${inClause('process.image.sha1', values)}${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} SHA1 hash(es) across process events`;
      break;

    case 'md5':
      query = `-- SentinelOne Deep Visibility — MD5 Hash IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  process.name,
  process.image.path,
  process.image.md5,
  process.user
FROM deep_visibility
WHERE ${inClause('process.image.md5', values)}${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} MD5 hash(es) across process events`;
      break;

    case 'email':
      query = `-- SentinelOne Deep Visibility — Email IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  process.name,
  network.email.sender,
  network.email.recipient,
  network.email.subject
FROM deep_visibility
WHERE (
  ${inClause('network.email.sender', values)}
  OR ${inClause('network.email.recipient', values)}
)${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} email IOC(s)`;
      break;

    case 'cve':
      query = `-- SentinelOne Deep Visibility — CVE Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  threat.name,
  threat.classification,
  process.name,
  process.user
FROM deep_visibility
WHERE (
  ${inClause('threat.cve', values)}
  OR ${inClause('threat.name', values)}
)${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for activity related to ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      query = `-- SentinelOne Deep Visibility — Registry Key IOC Hunt (S1QL v2)
SELECT
  event.time,
  endpoint.name,
  registry.key.path,
  registry.value.name,
  registry.value.data,
  process.name,
  process.user
FROM deep_visibility
WHERE ${inClause('registry.key.path', values)}${tw}
ORDER BY event.time DESC
LIMIT 1000`;
      description = `S1QL (SentinelOne): Hunt for ${values.length} registry key IOC(s)`;
      break;

    default:
      return null;
  }

  return { platform: 's1ql', query, description, iocType: type, iocValues: values };
}
