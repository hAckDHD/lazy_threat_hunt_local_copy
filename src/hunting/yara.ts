import type { IOC, IOCType, HuntQuery } from '../types/index.js';

export function yaraRule(type: IOCType, iocs: IOC[]): HuntQuery | null {
  // YARA is most useful for file-based IOCs (hashes, strings in files)
  const fileTypes: IOCType[] = ['sha256', 'sha1', 'md5', 'domain', 'url', 'ip', 'email'];
  if (!fileTypes.includes(type)) return null;
  if (!iocs.length) return null;

  const ts = new Date().toISOString().split('T')[0];
  const ruleName = `IOC_${type.toUpperCase()}_${ts.replace(/-/g, '')}`;
  let strings = '';
  let condition = '';
  let description = '';

  switch (type) {
    case 'sha256': {
      // YARA doesn't match hashes directly — generate hash-based condition comment
      // and include a meta block for use with YARA + hash module
      const hashList = iocs.map(i => `// ${i.value}`).join('\n        ');
      description = `YARA: Note — SHA256 matching requires the YARA hash module or external tooling.`;
      strings = `    /* SHA256 hashes — use with yara -d sha256=<hash> or hash.sha256(0, filesize) */
        ${hashList}`;
      condition = `    /* Match any file whose SHA256 is in the IOC list */
        hash.sha256(0, filesize) == "${iocs[0].value}"`;
      if (iocs.length > 1) {
        condition = `    /* Use hash module: install yara with hash module */
        any of them`;
      }
      break;
    }

    case 'md5': {
      description = `YARA: MD5 hash match for ${iocs.length} indicator(s)`;
      const conditions = iocs.map(i => `hash.md5(0, filesize) == "${i.value}"`).join(' or\n        ');
      strings = '';
      condition = `    ${conditions}`;
      break;
    }

    case 'sha1': {
      description = `YARA: SHA1 hash match for ${iocs.length} indicator(s)`;
      const conditions = iocs.map(i => `hash.sha1(0, filesize) == "${i.value}"`).join(' or\n        ');
      strings = '';
      condition = `    ${conditions}`;
      break;
    }

    case 'domain':
    case 'url':
    case 'ip': {
      description = `YARA: String match for ${iocs.length} network indicator(s) in file content`;
      strings = iocs.map((i, idx) => {
        const escaped = i.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return `    $ioc_${idx} = "${escaped}" nocase`;
      }).join('\n');
      condition = `    any of ($ioc_*)`;
      break;
    }

    case 'email': {
      description = `YARA: String match for ${iocs.length} email IOC(s) in documents/files`;
      strings = iocs.map((i, idx) =>
        `    $email_${idx} = "${i.value.replace(/"/g, '\\"')}" nocase`
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
