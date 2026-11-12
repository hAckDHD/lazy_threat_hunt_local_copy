import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// SentinelOne Singularity — PowerQuery.
//
// The previous version of this file emitted a SQL SELECT/FROM/WHERE/LIMIT
// dialect labeled "S1QL v2" that research could not corroborate against any
// SentinelOne documentation. Real SentinelOne query languages are either:
//   - S1QL 1.0: a flat PascalCase filter-bar grammar (ProcessName = "x" AND ...),
//     no SELECT/FROM/WHERE/LIMIT, used by the legacy Deep Visibility UI.
//   - PowerQuery: a pipe-based language (filter | group | columns | sort | limit)
//     over a src./tgt./dst./event./endpoint. dot-notation field namespace, used
//     by Singularity Data Lake / the current XDR console.
// This file now targets PowerQuery, since it is the current product surface.
// Only `endpoint.name` and `event.time` were independently confirmed against a
// primary SentinelOne source during research; every other field below is a
// best-inference from community references and is marked UNVERIFIED — confirm
// against your own SentinelOne tenant's PowerQuery field browser before relying
// on it operationally.

function timeFilter(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    const days: Record<string, number> = { '1d': 1, '7d': 7, '14d': 14, '30d': 30, '90d': 90 };
    const d = days[tr.relative] ?? 7;
    return ` and event.time > now() - ${d}d`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return ` and event.time between "${tr.start}" and "${tr.end}"`;
  }
  return '';
}

function inClause(field: string, values: string[]): string {
  return `${field} in (${values.map(v => `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(', ')})`;
}

export function s1qlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tw = timeFilter(options);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `// SentinelOne PowerQuery — IP IOC Hunt (fields other than endpoint.name/event.time UNVERIFIED)
| filter (${inClause('src.ip.address', values)} or ${inClause('dst.ip.address', values)})${tw}
| columns event.time, endpoint.name, src.ip.address, dst.ip.address, dst.port.number, tgt.process.name, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} IP IOC(s) in network telemetry`;
      break;

    case 'domain':
    case 'hostname':
      query = `// SentinelOne PowerQuery — Domain/Hostname IOC Hunt (UNVERIFIED fields)
| filter (${inClause('dns.request', values)} or ${inClause('dst.name', values)})${tw}
| columns event.time, endpoint.name, dns.request, dst.ip.address, tgt.process.name, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} domain IOC(s) in DNS and network events`;
      break;

    case 'url':
      query = `// SentinelOne PowerQuery — URL IOC Hunt (UNVERIFIED fields)
| filter ${inClause('url.address', values)}${tw}
| columns event.time, endpoint.name, url.address, dst.ip.address, dst.port.number, tgt.process.name
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} URL IOC(s) in HTTP/web telemetry`;
      break;

    case 'sha256':
      query = `// SentinelOne PowerQuery — SHA256 Hash IOC Hunt (UNVERIFIED fields)
| filter ${inClause('tgt.file.sha256', values)}${tw}
| columns event.time, endpoint.name, tgt.process.name, tgt.process.image.path, tgt.file.sha256, tgt.process.user, tgt.process.cmdline
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} SHA256 hash(es) across process events`;
      break;

    case 'sha1':
      query = `// SentinelOne PowerQuery — SHA1 Hash IOC Hunt (UNVERIFIED fields)
| filter ${inClause('tgt.file.sha1', values)}${tw}
| columns event.time, endpoint.name, tgt.process.name, tgt.process.image.path, tgt.file.sha1, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} SHA1 hash(es) across process events`;
      break;

    case 'md5':
      query = `// SentinelOne PowerQuery — MD5 Hash IOC Hunt (UNVERIFIED fields)
| filter ${inClause('tgt.file.md5', values)}${tw}
| columns event.time, endpoint.name, tgt.process.name, tgt.process.image.path, tgt.file.md5, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} MD5 hash(es) across process events`;
      break;

    case 'email':
      query = `// SentinelOne PowerQuery — Email IOC Hunt (UNVERIFIED fields)
| filter (${inClause('email.sender', values)} or ${inClause('email.recipient', values)})${tw}
| columns event.time, endpoint.name, tgt.process.name, email.sender, email.recipient, email.subject
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} email IOC(s)`;
      break;

    case 'cve':
      query = `// SentinelOne PowerQuery — CVE Hunt (UNVERIFIED fields)
| filter (${inClause('threat.cve', values)} or ${inClause('threat.name', values)})${tw}
| columns event.time, endpoint.name, threat.name, threat.classification, tgt.process.name, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for activity related to ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      query = `// SentinelOne PowerQuery — Registry Key IOC Hunt (UNVERIFIED fields)
| filter ${inClause('registry.keypath', values)}${tw}
| columns event.time, endpoint.name, registry.keypath, registry.value, tgt.process.name, tgt.process.user
| sort event.time desc
| limit 1000`;
      description = `PowerQuery (SentinelOne): Hunt for ${values.length} registry key IOC(s)`;
      break;

    default:
      return null;
  }

  return { platform: 's1ql', query, description, iocType: type, iocValues: values };
}
