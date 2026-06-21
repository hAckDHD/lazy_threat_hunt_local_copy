import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// CrowdStrike Falcon Next-Gen SIEM — CrowdStrike Query Language (CQL)
// Based on LogScale (Humio) query language.
// Architecture: Filter | Aggregate | Display (pipe-chained stages)
// Time handled as first filter using #event_time or timestamp field

function timeFilter(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    return `#event_time > -${tr.relative}\n`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return `#event_time >= "${tr.start}" #event_time <= "${tr.end}"\n`;
  }
  return '';
}

function inList(values: string[]): string {
  return '["' + values.map(v => v.replace(/"/g, '\\"')).join('", "') + '"]';
}

export function cqlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tf = timeFilter(options);
  const ilist = inList(values);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `${tf}// CrowdStrike Falcon SIEM — IP IOC Hunt
#event_simpleName IN ["NetworkConnectIP4", "NetworkConnectIP6", "DnsRequest"]
| in(field=RemoteAddressIP4, values=${ilist})
    OR in(field=LocalAddressIP4, values=${ilist})
    OR in(field=RemoteAddressIP6, values=${ilist})
| groupBy(
    [RemoteAddressIP4, LocalAddressIP4, RemotePort, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} IP IOC(s) across network connection events`;
      break;

    case 'domain':
    case 'hostname':
      query = `${tf}// CrowdStrike Falcon SIEM — Domain/Hostname IOC Hunt
#event_simpleName = "DnsRequest"
| in(field=DomainName, values=${ilist})
| groupBy(
    [DomainName, RemoteAddressIP4, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} domain IOC(s) in DNS request events`;
      break;

    case 'url':
      query = `${tf}// CrowdStrike Falcon SIEM — URL IOC Hunt
#event_simpleName = "NetworkConnectIP4"
| in(field=HttpUrl, values=${ilist})
    OR HttpUrl = /^(${values.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})/i
| groupBy(
    [HttpUrl, RemoteAddressIP4, RemotePort, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} URL IOC(s) in HTTP network events`;
      break;

    case 'sha256':
      query = `${tf}// CrowdStrike Falcon SIEM — SHA256 Hash IOC Hunt
#event_simpleName IN ["ProcessRollup2", "SyntheticProcessRollup2", "PeFileWritten", "EppDetectionSummaryEvent"]
| in(field=SHA256HashData, values=${ilist})
    OR in(field=TargetSHA256HashData, values=${ilist})
| groupBy(
    [SHA256HashData, FileName, FilePath, ComputerName, UserName, CommandLine],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} SHA256 hash(es) in process and file events`;
      break;

    case 'sha1':
      query = `${tf}// CrowdStrike Falcon SIEM — SHA1 Hash IOC Hunt
#event_simpleName IN ["ProcessRollup2", "PeFileWritten"]
| in(field=SHA1HashData, values=${ilist})
| groupBy(
    [SHA1HashData, FileName, FilePath, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} SHA1 hash(es) in endpoint events`;
      break;

    case 'md5':
      query = `${tf}// CrowdStrike Falcon SIEM — MD5 Hash IOC Hunt
#event_simpleName IN ["ProcessRollup2", "PeFileWritten"]
| in(field=MD5HashData, values=${ilist})
| groupBy(
    [MD5HashData, FileName, FilePath, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} MD5 hash(es) in endpoint events`;
      break;

    case 'email':
      query = `${tf}// CrowdStrike Falcon SIEM — Email IOC Hunt
#event_simpleName IN ["EmailMessageEvent", "SmtpActivity"]
| in(field=SenderAddress, values=${ilist})
    OR in(field=RecipientAddress, values=${ilist})
| groupBy(
    [SenderAddress, RecipientAddress, Subject, ComputerName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} email IOC(s)`;
      break;

    case 'cve':
      query = `${tf}// CrowdStrike Falcon SIEM — CVE Exploitation Hunt
#event_simpleName = "EppDetectionSummaryEvent"
| in(field=ExternalApiType, values=${inList(values.map(v => v.toUpperCase()))})
    OR Technique = /${values.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')}/i
| groupBy(
    [Technique, ComputerName, UserName, SeverityName, DetectDescription],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for exploitation activity related to ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      query = `${tf}// CrowdStrike Falcon SIEM — Registry Key IOC Hunt
#event_simpleName IN ["RegGenericValueUpdate", "RegValueUpdate", "RegKeyCreate", "RegKeyDelete"]
| in(field=RegObjectName, values=${ilist})
    OR RegObjectName = /${values.map(v => v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')}/i
| groupBy(
    [RegObjectName, RegValueName, RegStringValue, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} registry key IOC(s) in registry events`;
      break;

    default:
      return null;
  }

  return { platform: 'cql', query, description, iocType: type, iocValues: values };
}
