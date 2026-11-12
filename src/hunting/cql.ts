import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// CrowdStrike Falcon Next-Gen SIEM — CrowdStrike Query Language (CQL).
// Based on LogScale (Humio) query language.
// Architecture: Filter | Aggregate | Display (pipe-chained stages)
//
// LogScale does NOT support `OR` directly between two filter-function calls
// (e.g. `in(field=A, values=[...]) OR in(field=B, values=[...])`) — LogScale's
// own docs state AND/OR do not work with functions. The supported idiom for
// "match if any of these field/value filter functions matches" is a case{}
// block that sets a marker field, filtered on afterward.
//
// Time range is NOT reliably settable via inline query text in LogScale —
// it is set via the UI time-picker or the API's start=/end= parameters. Any
// inline "time filter" text below is a comment for the operator, not a
// functioning part of the query.

function timeRangeNote(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    return `// Time range: set via API start=-${tr.relative} or UI time-picker (not inline query text)\n`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return `// Time range: set via API start="${tr.start}" end="${tr.end}" (not inline query text)\n`;
  }
  return '';
}

function inList(values: string[]): string {
  return '["' + values.map(v => v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')).join('", "') + '"]';
}

// Builds a LogScale case{} block that ORs several `in(field=..., values=[...])`
// filter functions together via a boolean marker field, since bare `in(...) OR
// in(...)` is not valid LogScale syntax.
function orInFilter(clauses: Array<{ field: string; values: string[] }>): string {
  const cases = clauses
    .map(c => `    in(field=${c.field}, values=${inList(c.values)}) => #ioc_match := true;`)
    .join('\n');
  return `case {\n${cases}\n    * => #ioc_match := false;\n}\n| #ioc_match = true`;
}

export function cqlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tf = timeRangeNote(options);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `${tf}// CrowdStrike Falcon SIEM — IP IOC Hunt
#event_simpleName IN ["NetworkConnectIP4", "NetworkConnectIP6", "DnsRequest"]
| ${orInFilter([
        { field: 'RemoteAddressIP4', values },
        { field: 'LocalAddressIP4', values },
        { field: 'RemoteAddressIP6', values },
      ])}
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
| in(field=DomainName, values=${inList(values)})
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
| in(field=HttpUrl, values=${inList(values)})
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
| ${orInFilter([
        { field: 'SHA256HashData', values },
        { field: 'TargetSHA256HashData', values },
      ])}
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
| in(field=SHA1HashData, values=${inList(values)})
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
| in(field=MD5HashData, values=${inList(values)})
| groupBy(
    [MD5HashData, FileName, FilePath, ComputerName, UserName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} MD5 hash(es) in endpoint events`;
      break;

    case 'email':
      // UNVERIFIED: EmailMessageEvent/SmtpActivity have no corroborating source
      // in CrowdStrike's public schema references — verify against a real
      // Falcon Event Stream/FDR schema before relying on this branch.
      query = `${tf}// CrowdStrike Falcon SIEM — Email IOC Hunt
// UNVERIFIED event names — confirm EmailMessageEvent/SmtpActivity exist in your Falcon schema
#event_simpleName IN ["EmailMessageEvent", "SmtpActivity"]
| ${orInFilter([
        { field: 'SenderAddress', values },
        { field: 'RecipientAddress', values },
      ])}
| groupBy(
    [SenderAddress, RecipientAddress, Subject, ComputerName],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for ${values.length} email IOC(s) [UNVERIFIED event schema]`;
      break;

    case 'cve':
      query = `${tf}// CrowdStrike Falcon SIEM — CVE Exploitation Hunt
#event_simpleName = "EppDetectionSummaryEvent"
| in(field=ExternalApiType, values=${inList(values.map(v => v.toUpperCase()))})
| groupBy(
    [ExternalApiType, ComputerName, UserName, SeverityName, DetectDescription],
    function=count()
  )
| sort(_count, order=desc, limit=200)`;
      description = `CQL (CrowdStrike): Hunt for exploitation activity related to ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      query = `${tf}// CrowdStrike Falcon SIEM — Registry Key IOC Hunt
#event_simpleName IN ["RegGenericValueUpdate", "RegValueUpdate", "RegKeyCreate", "RegKeyDelete"]
| in(field=RegObjectName, values=${inList(values)})
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
