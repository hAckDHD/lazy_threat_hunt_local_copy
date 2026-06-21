import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';

// Microsoft KQL — works for Sentinel, Defender ATP, and Azure Log Analytics

function timeWhere(options?: HuntOptions): string {
  const tr = options?.timeRange;
  if (!tr) return '';
  if (tr.type === 'relative' && tr.relative) {
    const map: Record<string, string> = { '1d':'1d','7d':'7d','14d':'14d','30d':'30d','90d':'90d' };
    return `\n     | where TimeGenerated >= ago(${map[tr.relative] ?? '7d'})`;
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    const s = tr.start.split('T')[0];
    const e = tr.end.split('T')[0];
    return `\n     | where TimeGenerated between (datetime(${s}) .. datetime(${e}))`;
  }
  return '';
}

export function kqlQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  const valueList = values.map(v => `"${v.replace(/"/g, '\\"')}"`).join(', ');
  const tw = timeWhere(options);
  let query = '';
  let description = '';
  const ts = new Date().toISOString();

  switch (type) {
    case 'ip':
    case 'ipv6':
      query = `// Generated ${ts}
let ioc_ips = dynamic([${valueList}]);
union
    (DeviceNetworkEvents${tw}
     | where RemoteIP in (ioc_ips) or LocalIP in (ioc_ips)
     | project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName, ActionType),
    (CommonSecurityLog${tw}
     | where SourceIP in (ioc_ips) or DestinationIP in (ioc_ips)
     | project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, DestinationPort, Activity),
    (SigninLogs${tw}
     | where IPAddress in (ioc_ips)
     | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType)
| order by TimeGenerated desc`;
      description = `KQL (Sentinel/Defender): Hunt for ${values.length} IP IOC(s) across network and sign-in logs`;
      break;

    case 'domain':
    case 'hostname':
      query = `// Generated ${ts}
let ioc_domains = dynamic([${valueList}]);
union
    (DeviceNetworkEvents${tw}
     | where RemoteUrl has_any (ioc_domains) or RemoteIP has_any (ioc_domains)
     | project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName),
    (DnsEvents${tw}
     | where Name in~ (ioc_domains) or QueryType == "A"
     | project TimeGenerated, Computer, Name, IPAddresses),
    (DeviceEvents${tw}
     | where RemoteUrl has_any (ioc_domains)
     | project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName)
| order by TimeGenerated desc`;
      description = `KQL: Hunt for ${values.length} domain IOC(s) in DNS and network events`;
      break;

    case 'sha256':
      query = `// Generated ${ts}
let ioc_hashes = dynamic([${valueList}]);
union
    (DeviceFileEvents${tw}
     | where SHA256 in (ioc_hashes)
     | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessAccountName),
    (DeviceProcessEvents${tw}
     | where SHA256 in (ioc_hashes)
     | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, AccountName),
    (DeviceImageLoadEvents${tw}
     | where SHA256 in (ioc_hashes)
     | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256)
| order by TimeGenerated desc`;
      description = `KQL: Hunt for ${values.length} SHA256 file hash(es) in Defender ATP telemetry`;
      break;

    case 'md5':
      query = `// Generated ${ts}
let ioc_hashes = dynamic([${valueList}]);
DeviceFileEvents${tw}
| where MD5 in (ioc_hashes)
| project TimeGenerated, DeviceName, FileName, FolderPath, MD5, InitiatingProcessAccountName, ActionType
| order by TimeGenerated desc`;
      description = `KQL: Hunt for ${values.length} MD5 hash(es) in file events`;
      break;

    case 'email':
      query = `// Generated ${ts}
let ioc_emails = dynamic([${valueList}]);
union
    (EmailEvents${tw}
     | where SenderFromAddress in~ (ioc_emails) or RecipientEmailAddress in~ (ioc_emails)
     | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction),
    (AuditLogs${tw}
     | where InitiatedBy has_any (ioc_emails)
     | project TimeGenerated, OperationName, InitiatedBy, Result)
| order by TimeGenerated desc`;
      description = `KQL: Hunt for ${values.length} email address IOC(s) in email events`;
      break;

    case 'cve':
      query = `// Generated ${ts}
let ioc_cves = dynamic([${valueList}]);
union
    (SecurityAlert${tw}
     | where Entities has_any (ioc_cves) or ExtendedProperties has_any (ioc_cves)
     | project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Entities),
    (CommonSecurityLog${tw}
     | where FlexString2 in (ioc_cves) or Message has_any (ioc_cves)
     | project TimeGenerated, Computer, SourceIP, DestinationIP, Activity, Message)
| order by TimeGenerated desc`;
      description = `KQL: Hunt for exploitation activity related to ${values.length} CVE(s)`;
      break;

    case 'registry_key':
      query = `// Generated ${ts}
let ioc_keys = dynamic([${valueList}]);
DeviceRegistryEvents${tw}
| where RegistryKey has_any (ioc_keys) or PreviousRegistryKey has_any (ioc_keys)
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated desc`;
      description = `KQL: Hunt for ${values.length} registry key IOC(s) in Defender registry events`;
      break;

    default:
      return null;
  }

  return { platform: 'kql', query, description, iocType: type, iocValues: values };
}
