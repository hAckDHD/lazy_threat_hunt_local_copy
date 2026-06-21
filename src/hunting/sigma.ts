import type { IOCType, HuntQuery } from '../types/index.js';

export function sigmaRule(type: IOCType, values: string[]): HuntQuery | null {
  if (!values.length) return null;

  const ts = new Date().toISOString().split('T')[0];
  let detection = '';
  let logsource = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6':
      logsource = `logsource:
    category: network_connection`;
      detection = `detection:
    selection:
        dst_ip|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: Network connection to ${values.length} known-malicious IP(s)`;
      break;

    case 'domain':
    case 'hostname':
      logsource = `logsource:
    category: dns`;
      detection = `detection:
    selection:
        dns.question.name|contains:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: DNS lookup for ${values.length} malicious domain(s)`;
      break;

    case 'sha256':
      logsource = `logsource:
    category: process_creation
    product: windows`;
      detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'SHA256=${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: Process creation with ${values.length} known-malicious SHA256 hash(es)`;
      break;

    case 'md5':
      logsource = `logsource:
    category: process_creation
    product: windows`;
      detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'MD5=${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: Process with ${values.length} known-malicious MD5 hash(es)`;
      break;

    case 'sha1':
      logsource = `logsource:
    category: process_creation
    product: windows`;
      detection = `detection:
    selection:
        Hashes|contains:
${values.map(v => `            - 'SHA1=${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: Process with ${values.length} known-malicious SHA1 hash(es)`;
      break;

    case 'registry_key':
      logsource = `logsource:
    category: registry_event
    product: windows`;
      detection = `detection:
    selection:
        TargetObject|startswith:
${values.map(v => `            - '${v}'`).join('\n')}
    condition: selection`;
      description = `SIGMA: Registry modification of ${values.length} suspicious key(s)`;
      break;

    default:
      return null;
  }

  const query = `title: IOC Hunt — ${type.toUpperCase()} Indicators
id: ${generateUUID()}
status: experimental
description: ${description}
references:
    - 'IOC extracted on ${ts}'
author: IOC Tool
date: ${ts}
tags:
    - attack.threat_hunting
    - ioc
${logsource}
${detection}
falsepositives:
    - Unknown
level: high`;

  return { platform: 'sigma', query, description, iocType: type, iocValues: values };
}

function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}
