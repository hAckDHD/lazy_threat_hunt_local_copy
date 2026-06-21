import type { IOCType, HuntQuery } from '../types/index.js';

export function elasticQuery(type: IOCType, values: string[]): HuntQuery | null {
  if (!values.length) return null;

  const terms = JSON.stringify(values);
  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'source.ip': values } },
              { terms: { 'destination.ip': values } },
              { terms: { 'client.ip': values } },
              { terms: { 'server.ip': values } },
            ],
            minimum_should_match: 1,
          },
        },
        aggs: {
          by_host: { terms: { field: 'host.name', size: 20 } },
          by_ip: { terms: { field: 'source.ip', size: 20 } },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} IP IOC(s) in network logs`;
      break;
    }

    case 'domain':
    case 'hostname': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'dns.question.name': values } },
              { terms: { 'url.domain': values } },
              { terms: { 'destination.domain': values } },
            ],
            minimum_should_match: 1,
          },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} domain IOC(s)`;
      break;
    }

    case 'sha256': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'file.hash.sha256': values } },
              { terms: { 'process.hash.sha256': values } },
            ],
            minimum_should_match: 1,
          },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} SHA256 hash(es) in endpoint events`;
      break;
    }

    case 'md5': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'file.hash.md5': values } },
              { terms: { 'process.hash.md5': values } },
            ],
            minimum_should_match: 1,
          },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} MD5 hash(es)`;
      break;
    }

    case 'sha1': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'file.hash.sha1': values } },
              { terms: { 'process.hash.sha1': values } },
            ],
            minimum_should_match: 1,
          },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} SHA1 hash(es)`;
      break;
    }

    case 'email': {
      query = JSON.stringify({
        query: {
          bool: {
            should: [
              { terms: { 'email.from.address': values } },
              { terms: { 'email.to.address': values } },
              { terms: { 'user.email': values } },
            ],
            minimum_should_match: 1,
          },
        },
      }, null, 2);
      description = `Elastic DSL: Hunt for ${values.length} email IOC(s)`;
      break;
    }

    default:
      return null;
  }

  return { platform: 'elastic', query, description, iocType: type, iocValues: values };
}
