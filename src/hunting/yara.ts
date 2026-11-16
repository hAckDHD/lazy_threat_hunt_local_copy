import type { IOC, IOCType, HuntQuery } from '../types/index.js';

export function yaraRule(type: IOCType, iocs: IOC[]): HuntQuery | null {
  // YARA is most useful for file-based IOCs (hashes, strings in files)
  const fileTypes: IOCType[] = ['sha256', 'sha1', 'md5', 'domain', 'url', 'ip', 'email', 'filename'];
  if (!fileTypes.includes(type)) return null;
  if (!iocs.length) return null;

  const ts = new Date().toISOString().split('T')[0];
  const ruleName = `IOC_${type.toUpperCase()}_${ts.replace(/-/g, '')}`;
  let strings = '';
  let condition = '';
  let description = '';

  switch (type) {
    case 'sha256': {
      // YARA's hash module always returns lowercase hex — condition must compare
      // against lowercased values or a mixed-case IOC silently never matches.
      // "any of them" resolves against declared $-prefixed strings only, so it
      // cannot reference hash.sha256() conditions — chain them with `or` instead,
      // matching the pattern already used for md5/sha1 below.
      description = `YARA (artifact/memory scan, not a live SIEM query): SHA256 hash match for ${iocs.length} indicator(s)`;
      const conditions = iocs.map(i => `hash.sha256(0, filesize) == "${i.value.toLowerCase()}"`).join(' or\n        ');
      strings = '';
      condition = `    ${conditions}`;
      break;
    }

    case 'md5': {
      description = `YARA (artifact/memory scan, not a live SIEM query): MD5 hash match for ${iocs.length} indicator(s)`;
      const conditions = iocs.map(i => `hash.md5(0, filesize) == "${i.value.toLowerCase()}"`).join(' or\n        ');
      strings = '';
      condition = `    ${conditions}`;
      break;
    }

    case 'sha1': {
      description = `YARA (artifact/memory scan, not a live SIEM query): SHA1 hash match for ${iocs.length} indicator(s)`;
      const conditions = iocs.map(i => `hash.sha1(0, filesize) == "${i.value.toLowerCase()}"`).join(' or\n        ');
      strings = '';
      condition = `    ${conditions}`;
      break;
    }

    case 'domain':
    case 'url':
    case 'ip': {
      description = `YARA (artifact/memory scan, not a live SIEM query): string match for ${iocs.length} network indicator(s) in file content`;
      strings = iocs.map((i, idx) => {
        const escaped = i.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `    $ioc_${idx} = "${escaped}" nocase`;
      }).join('\n');
      condition = `    any of ($ioc_*)`;
      break;
    }

    case 'filename': {
      // Filenames/paths referenced as literal strings inside a sample (droppers,
      // loaders, scripts that write or launch the file by name).
      description = `YARA (artifact/memory scan, not a live SIEM query): filename/path string match for ${iocs.length} indicator(s) in file content`;
      strings = iocs.map((i, idx) =>
        `    $file_${idx} = "${i.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" nocase`
      ).join('\n');
      condition = `    any of ($file_*)`;
      break;
    }

    case 'email': {
      description = `YARA (artifact/memory scan, not a live SIEM query): string match for ${iocs.length} email IOC(s) in documents/files`;
      strings = iocs.map((i, idx) =>
        `    $email_${idx} = "${i.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" nocase`
      ).join('\n');
      condition = `    any of ($email_*)`;
      break;
    }

    default:
      return null;
  }

  const values = iocs.map(i => i.value);
  const query = `import "hash"

rule ${ruleName}
{
    meta:
        description = "${description}"
        author = "IOC Tool"
        date = "${ts}"
        type = "${type}"
        ioc_count = "${iocs.length}"
${strings ? `\n    strings:\n${strings}` : ''}

    condition:
${condition}
}`;

  return { platform: 'yara', query, description, iocType: type, iocValues: values };
}
