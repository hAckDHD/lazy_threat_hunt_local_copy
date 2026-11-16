import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';
import { emailUsernames } from './username.js';

// Trellix (McAfee) ePO — legacy on-prem SQL Query Builder against the ePO
// reporting database. NOTE: this targets classic ePO only. Trellix Helix
// (the modern XDR/data-lake product) uses a completely different, non-SQL
// field:value/boolean search grammar ("TQL" in Helix's own UI) descended from
// FireEye/Mandiant MQL — do not run this SQL against a Helix environment.
//
// TargetHash (used below for all hash-type IOCs) lives on the joined
// EPExtendedEvent table in real ePO schemas, not flat on EPOEvents — add the
// appropriate JOIN for your ePO version/schema before running.

function timeWhere(options?: HuntOptions, prefix = 'AND'): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    const hours: Record<string, number> = {
      '1d': 24, '7d': 168, '14d': 336, '30d': 720, '90d': 2160,
    };
    const h = hours[tr.relative] ?? 168;
    return `\n  ${prefix} ReceivedUTC >= NOW() - ${h} * 3600`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return `\n  ${prefix} ReceivedUTC BETWEEN '${tr.start}' AND '${tr.end}'`;
  }
  return '';
}

function inList(field: string, values: string[]): string {
  return `${field} IN (${values.map(v => `'${v.replace(/'/g, "''")}'`).join(', ')})`;
}

export function tqlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const tw = timeWhere(options);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `-- Trellix/McAfee ePO — IP IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  SourceIPV4,
  DestinationIPV4,
  DestinationPort,
  ProcessName,
  UserName,
  ThreatName,
  ThreatType
FROM EPOEvents
WHERE (
  ${inList('SourceIPV4', values)}
  OR ${inList('DestinationIPV4', values)}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} IP IOC(s) in network events`;
      break;

    case 'domain':
    case 'hostname':
      query = `-- Trellix/McAfee ePO — Domain/Hostname IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetHostName,
  SourceIPV4,
  DestinationIPV4,
  ProcessName,
  UserName,
  ThreatName
FROM EPOEvents
WHERE (
  ${inList('TargetHostName', values)}
  OR ${inList('TargetFileName', values)}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} domain/hostname IOC(s) in network events`;
      break;

    case 'url':
      query = `-- Trellix/McAfee ePO — URL IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetURL,
  SourceIPV4,
  DestinationIPV4,
  ProcessName,
  UserName,
  ThreatName,
  ThreatType
FROM EPOEvents
WHERE (
  ${inList('TargetURL', values)}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} URL IOC(s) in web events`;
      break;

    case 'sha256':
      query = `-- Trellix/McAfee ePO — SHA256 Hash IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetFileName,
  TargetFilePath,
  TargetHash,
  ProcessName,
  UserName,
  ThreatName,
  ThreatType,
  ThreatActionTaken
FROM EPOEvents
WHERE ${inList('TargetHash', values)}${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} SHA256 hash(es) in file/process events`;
      break;

    case 'sha1':
    case 'md5':
      query = `-- Trellix/McAfee ePO — ${type.toUpperCase()} Hash IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetFileName,
  TargetFilePath,
  TargetHash,
  ProcessName,
  UserName,
  ThreatName,
  ThreatType,
  ThreatActionTaken
FROM EPOEvents
WHERE ${inList('TargetHash', values)}${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} ${type.toUpperCase()} hash(es) in file/process events`;
      break;

    case 'filename':
      query = `-- Trellix/McAfee ePO — Filename IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetFileName,
  TargetFilePath,
  TargetHash,
  ProcessName,
  UserName,
  ThreatName,
  ThreatActionTaken
FROM EPOEvents
WHERE (
  ${inList('TargetFileName', values)}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} filename IOC(s) in file events`;
      break;

    case 'email':
      query = `-- Trellix/McAfee ePO — Email IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  SourceUserName,
  TargetUserName,
  ThreatName,
  ThreatType,
  ProcessName
FROM EPOEvents
WHERE (
  ${inList('SourceUserName', emailUsernames(values))}
  OR ${inList('TargetUserName', emailUsernames(values))}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} email IOC(s) by account/login name`;
      break;

    case 'registry_key':
      query = `-- Trellix/McAfee ePO — Registry Key IOC Hunt (TQL)
SELECT
  ReceivedUTC,
  HostName,
  TargetFileName,
  ProcessName,
  UserName,
  ThreatName,
  ThreatActionTaken
FROM EPOEvents
WHERE (
  ${inList('TargetFileName', values)}
)${tw}
ORDER BY ReceivedUTC DESC`;
      description = `TQL (Trellix/ePO): Hunt for ${values.length} registry key IOC(s)`;
      break;

    default:
      return null;
  }

  return { platform: 'tql', query, description, iocType: type, iocValues: values };
}
