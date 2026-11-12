import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

function timeClause(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) return `earliest=-${tr.relative} latest=now `;
  if (tr.type === 'absolute' && tr.start && tr.end) return `earliest="${tr.start}" latest="${tr.end}" `;
  return '';
}

// SPL double-quoted string escaping: backslash must be escaped before the quote,
// otherwise a value ending in a backslash (e.g. a Windows registry path) closes
// the string early and lets the remainder of the value inject SPL.
function splunkEscape(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function splunkQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tc = timeClause(options);
  const idx = options?.splunkIndex ?? '*';
  const list = values.map(v => `"${splunkEscape(v)}"`).join(' ');
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      // src_ip/dest_ip are CIM Network_Traffic fields; src/dst are not (dst isn't
      // a CIM field at all — dest is) so the raw src/dest pair below is dropped.
      query = `${tc}index=${idx} (src_ip IN (${list}) OR dest_ip IN (${list}))
| stats count by _time, src_ip, dest_ip, index, sourcetype
| sort -count`;
      description = `Splunk: Hunt for ${values.length} suspicious IP(s) in network traffic`;
      break;

    case 'domain':
    case 'hostname':
      // CIM Network_Resolution (DNS) model field is "query", not "dns.query".
      query = `${tc}index=${idx} (query IN (${list}) OR url IN (${list}) OR domain IN (${list}))
| eval ioc_match=coalesce(query, url, domain)
| stats count by _time, src, ioc_match, index, sourcetype
| sort -count`;
      description = `Splunk: Hunt for ${values.length} domain/hostname IOC(s) in DNS and proxy logs`;
      break;

    case 'url':
      query = `${tc}index=${idx} (url IN (${list}) OR request_url IN (${list}))
| stats count by _time, src_ip, url, status, index
| sort -count`;
      description = `Splunk: Hunt for ${values.length} malicious URL(s) in proxy/web logs`;
      break;

    case 'sha256':
      query = `${tc}index=${idx} (sha256 IN (${list}) OR file_hash IN (${list}) OR hash IN (${list}))
| stats count by _time, file_name, file_path, sha256, host, user
| sort -count`;
      description = `Splunk: Hunt for ${values.length} SHA256 file hash(es) in endpoint telemetry`;
      break;

    case 'sha1':
      query = `${tc}index=${idx} (sha1 IN (${list}) OR file_hash IN (${list}))
| stats count by _time, file_name, sha1, host, user
| sort -count`;
      description = `Splunk: Hunt for ${values.length} SHA1 hash(es)`;
      break;

    case 'md5':
      query = `${tc}index=${idx} (md5 IN (${list}) OR file_hash IN (${list}))
| stats count by _time, file_name, md5, host, user
| sort -count`;
      description = `Splunk: Hunt for ${values.length} MD5 hash(es)`;
      break;

    case 'email':
      // sender/recipient are CIM Email fields; from/to are not, dropped.
      query = `${tc}index=${idx} (sender IN (${list}) OR recipient IN (${list}))
| stats count by _time, sender, recipient, subject, index
| sort -count`;
      description = `Splunk: Hunt for ${values.length} suspicious email address(es)`;
      break;

    case 'cve':
      query = `${tc}index=${idx} (vulnerability IN (${list}) OR cve IN (${list}) OR signature IN (${list}))
| stats count by _time, host, signature, severity
| sort -count`;
      description = `Splunk: Hunt for exploitation attempts of ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      // registry_path is the CIM Endpoint.Registry field; TargetObject (raw Sysmon)
      // is kept alongside it since many real deployments only have the raw field.
      query = `${tc}index=${idx} sourcetype=xmlwineventlog EventCode IN (12,13,14) (${values.map(v => `TargetObject="${splunkEscape(v)}*" OR registry_path="${splunkEscape(v)}*"`).join(' OR ')})
| stats count by _time, host, TargetObject, Details, EventCode
| sort -count`;
      description = `Splunk: Hunt for ${values.length} registry key IOC(s) via Windows Event Logs`;
      break;

    default:
      return null;
  }

  return { platform: 'splunk', query, description, iocType: type, iocValues: values };
}
