import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// Wazuh — WQL (Wazuh Query Language) for the management API + Lucene for the dashboard
// WQL format: field:operator:value (=, !=, <, >, ~)
// Dashboard Security Events uses Lucene/OpenSearch syntax

function timeFilter(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    const map: Record<string, string> = { '1d': 'now-1d', '7d': 'now-7d', '14d': 'now-14d', '30d': 'now-30d', '90d': 'now-90d' };
    return ` AND timestamp:[${map[tr.relative] ?? 'now-7d'} TO now]`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return ` AND timestamp:[${tr.start} TO ${tr.end}]`;
  }
  return '';
}

function luceneOr(field: string, values: string[]): string {
  return values.map(v => `${field}:"${v.replace(/"/g, '\\"')}"`).join(' OR ');
}

export function wazuhQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tf = timeFilter(options);
  // WQL: comma-separated OR for multi-value filters
  const wqlList = values.map(v => v.replace(/["]/g, '\\"')).join(',');
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('data.srcip', values)} OR ${luceneOr('data.dstip', values)} OR ${luceneOr('data.win.eventdata.sourceIp', values)} OR ${luceneOr('data.win.eventdata.destinationIp', values)})${tf}

// Wazuh API — WQL filter (GET /events)
// q=data.srcip~${wqlList} OR data.dstip~${wqlList}

// Wazuh Ruleset Check (rule groups containing network IOCs)
// GET /rules?q=groups~network AND status=enabled`;
      description = `Wazuh: Hunt for ${values.length} IP IOC(s) in security events and network alerts`;
      break;

    case 'domain':
    case 'hostname':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('data.dns.question.name', values)} OR ${luceneOr('data.dns.rdata', values)} OR ${luceneOr('data.url', values)})${tf}

// Wazuh API — WQL filter (GET /events)
// q=data.dns.question.name~${wqlList}

// Check Wazuh FIM (File Integrity Monitoring) if hostname matches endpoint name
// GET /agents?q=name~${values[0] ?? ''}`;
      description = `Wazuh: Hunt for ${values.length} domain/hostname IOC(s) in DNS and alert data`;
      break;

    case 'url':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('data.url', values)} OR ${luceneOr('data.http.url', values)} OR ${luceneOr('data.win.eventdata.queryName', values)})${tf}

// Wazuh API — WQL filter
// q=data.url~${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} URL IOC(s) in HTTP and web alert events`;
      break;

    case 'sha256':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('syscheck.sha256_after', values)} OR ${luceneOr('data.win.eventdata.hashes', values.map(v => `SHA256=${v}`))} OR ${luceneOr('data.VirusTotal.source.sha256', values)})${tf}

// Wazuh API — WQL filter (FIM events)
// q=syscheck.sha256_after=${wqlList}

// Wazuh File Integrity Monitoring — API lookup
// GET /syscheck/{agent_id}?q=sha256_after~${values[0] ?? ''}`;
      description = `Wazuh: Hunt for ${values.length} SHA256 hash(es) in FIM and endpoint alert events`;
      break;

    case 'sha1':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('syscheck.sha1_after', values)} OR ${luceneOr('data.win.eventdata.hashes', values.map(v => `SHA1=${v}`))})${tf}

// Wazuh API — FIM lookup
// q=syscheck.sha1_after=${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} SHA1 hash(es) in FIM events`;
      break;

    case 'md5':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('syscheck.md5_after', values)} OR ${luceneOr('data.win.eventdata.hashes', values.map(v => `MD5=${v}`))})${tf}

// Wazuh API — FIM lookup
// q=syscheck.md5_after=${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} MD5 hash(es) in FIM events`;
      break;

    case 'email':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('data.email.from', values)} OR ${luceneOr('data.email.to', values)} OR ${luceneOr('data.win.eventdata.targetUserName', values)})${tf}

// Wazuh API — WQL filter
// q=data.email.from~${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} email IOC(s) in alert events`;
      break;

    case 'cve':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('data.vulnerability.cve', values)} OR ${luceneOr('data.cve', values)})${tf}

// Wazuh Vulnerability Detector API
// GET /vulnerability/{agent_id}?q=cve=${wqlList}

// Wazuh API — WQL filter
// q=data.vulnerability.cve=${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} CVE(s) via Vulnerability Detector and alert data`;
      break;

    case 'registry_key':
      query = `// Wazuh Dashboard — Security Events (Lucene)
(${luceneOr('syscheck.path', values)} OR ${luceneOr('data.win.registryKey.path', values)})${tf}

// Wazuh FIM (Registry monitoring) — API lookup
// GET /syscheck/{agent_id}?q=path~${wqlList}

// Wazuh API — WQL filter
// q=syscheck.path~${wqlList}`;
      description = `Wazuh: Hunt for ${values.length} registry key IOC(s) in FIM/Syscheck registry events`;
      break;

    default:
      return null;
  }

  return { platform: 'wazuh', query, description, iocType: type, iocValues: values };
}
