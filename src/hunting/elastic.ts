import type { IOCType, HuntQuery, HuntOptions } from '../types/index.js';
import { emailUsernames } from './username.js';

// Elastic Common Schema (ECS) field targets — see research/elastic_dsl_eql.md.
// registry.path (not registry.key.path) is the real ECS registry field.

function timeRangeFilter(options?: HuntOptions): Record<string, unknown> | null {
  const tr = options?.timeRange;
  if (!tr) return null;
  if (tr.type === 'relative' && tr.relative) {
    return { range: { '@timestamp': { gte: `now-${tr.relative}`, lte: 'now' } } };
  }
  if (tr.type === 'absolute' && tr.start && tr.end) {
    return { range: { '@timestamp': { gte: tr.start, lte: tr.end } } };
  }
  return null;
}

function boolQuery(should: Record<string, unknown>[], options?: HuntOptions, extra?: Record<string, unknown>): Record<string, unknown> {
  const tf = timeRangeFilter(options);
  const bool: Record<string, unknown> = { should, minimum_should_match: 1 };
  if (tf) bool.filter = [tf];
  return { query: { bool }, ...extra };
}

export function elasticQuery(type: IOCType, values: string[], options?: HuntOptions): HuntQuery | null {
  if (!values.length) return null;

  let query = '';
  let description = '';

  switch (type) {
    case 'ip':
    case 'ipv6': {
      query = JSON.stringify(boolQuery([
        { terms: { 'source.ip': values } },
        { terms: { 'destination.ip': values } },
        { terms: { 'client.ip': values } },
        { terms: { 'server.ip': values } },
      ], options, {
        aggs: {
          by_host: { terms: { field: 'host.name', size: 20 } },
          by_ip: { terms: { field: 'source.ip', size: 20 } },
        },
      }), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} IP IOC(s) in network logs`;
      break;
    }

    case 'domain':
    case 'hostname': {
      query = JSON.stringify(boolQuery([
        { terms: { 'dns.question.name': values } },
        { terms: { 'url.domain': values } },
        { terms: { 'destination.domain': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} domain IOC(s)`;
      break;
    }

    case 'url': {
      query = JSON.stringify(boolQuery([
        { terms: { 'url.full': values } },
        { terms: { 'url.original': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} URL IOC(s) in proxy/web logs`;
      break;
    }

    case 'sha256': {
      query = JSON.stringify(boolQuery([
        { terms: { 'file.hash.sha256': values } },
        { terms: { 'process.hash.sha256': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} SHA256 hash(es) in endpoint events`;
      break;
    }

    case 'md5': {
      query = JSON.stringify(boolQuery([
        { terms: { 'file.hash.md5': values } },
        { terms: { 'process.hash.md5': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} MD5 hash(es)`;
      break;
    }

    case 'sha1': {
      query = JSON.stringify(boolQuery([
        { terms: { 'file.hash.sha1': values } },
        { terms: { 'process.hash.sha1': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} SHA1 hash(es)`;
      break;
    }

    case 'filename': {
      // ECS file.* and process.* fields. A bare-name IOC matches file.name /
      // process.name; a full-path IOC matches file.path / process.executable.
      query = JSON.stringify(boolQuery([
        { terms: { 'file.name': values } },
        { terms: { 'file.path': values } },
        { terms: { 'process.name': values } },
        { terms: { 'process.executable': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} filename/path IOC(s) in file & process events`;
      break;
    }

    case 'email': {
      // The address doubles as the login identity, so also match ECS user.name /
      // source.user.name against the full address + local part.
      const usernames = emailUsernames(values);
      query = JSON.stringify(boolQuery([
        { terms: { 'email.from.address': values } },
        { terms: { 'email.to.address': values } },
        { terms: { 'user.email': values } },
        { terms: { 'user.name': usernames } },
        { terms: { 'source.user.name': usernames } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} email IOC(s) in mail and identity events`;
      break;
    }

    case 'registry_key': {
      query = JSON.stringify(boolQuery([
        { terms: { 'registry.path': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for ${values.length} registry key IOC(s)`;
      break;
    }

    case 'cve': {
      query = JSON.stringify(boolQuery([
        { terms: { 'vulnerability.id': values } },
      ], options), null, 2);
      description = `Elastic DSL: Hunt for exploitation activity related to ${values.length} CVE(s)`;
      break;
    }

    case 'aws_access_key': {
      // ECS CloudTrail: the access key is aws.cloudtrail.user_identity.access_key_id.
      query = JSON.stringify(boolQuery([
        { terms: { 'aws.cloudtrail.user_identity.access_key_id': values } },
        { terms: { 'aws.cloudtrail.request_parameters.accessKeyId': values } },
      ], options, {
        aggs: {
          by_event: { terms: { field: 'event.action', size: 25 } },
          by_source_ip: { terms: { field: 'source.ip', size: 20 } },
        },
      }), null, 2);
      description = `Elastic DSL: Hunt AWS CloudTrail for ${values.length} leaked access key(s)`;
      break;
    }

    default:
      return null;
  }

  return { platform: 'elastic', query, description, iocType: type, iocValues: values };
}
