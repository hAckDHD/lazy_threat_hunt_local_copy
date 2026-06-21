import type { IOC, IOCType, HuntQuery, HuntOptions } from '../types/index.js';
import { splunkQuery } from './splunk.js';
import { elasticQuery } from './elastic.js';
import { kqlQuery } from './kql.js';
import { cqlQuery } from './cql.js';
import { s1qlQuery } from './s1ql.js';
import { wazuhQuery } from './wazuh.js';
import { sigmaRule } from './sigma.js';
import { yaraRule } from './yara.js';
import { tqlQuery } from './tql.js';

export type HuntPlatform = 'splunk' | 'elastic' | 'kql' | 'cql' | 's1ql' | 'wazuh' | 'tql' | 'sigma' | 'yara' | 'all';

export function generateHuntQueries(
  iocs: IOC[],
  platform: HuntPlatform = 'all',
  options?: HuntOptions
): HuntQuery[] {
  const byType = groupByType(iocs);
  const queries: HuntQuery[] = [];

  const platforms: Exclude<HuntPlatform, 'all'>[] =
    platform === 'all'
      ? ['splunk', 'kql', 'cql', 's1ql', 'wazuh', 'tql', 'elastic', 'sigma', 'yara']
      : [platform];

  for (const p of platforms) {
    for (const [type, typeIOCs] of Object.entries(byType) as [IOCType, IOC[]][]) {
      const values = typeIOCs.map(i => i.value);
      let query: HuntQuery | null = null;

      switch (p) {
        case 'splunk':  query = splunkQuery(type, values, options); break;
        case 'elastic': query = elasticQuery(type, values); break;
        case 'kql':     query = kqlQuery(type, values, options); break;
        case 'cql':     query = cqlQuery(type, values, options); break;
        case 's1ql':    query = s1qlQuery(type, values, options); break;
        case 'wazuh':   query = wazuhQuery(type, values, options); break;
        case 'tql':     query = tqlQuery(type, values, options); break;
        case 'sigma':   query = sigmaRule(type, values); break;
        case 'yara':    query = yaraRule(type, typeIOCs); break;
      }

      if (query) queries.push(query);
    }
  }

  return queries;
}

function groupByType(iocs: IOC[]): Partial<Record<IOCType, IOC[]>> {
  const map: Partial<Record<IOCType, IOC[]>> = {};
  for (const ioc of iocs) {
    if (!map[ioc.type]) map[ioc.type] = [];
    map[ioc.type]!.push(ioc);
  }
  return map;
}

export { splunkQuery, elasticQuery, kqlQuery, cqlQuery, s1qlQuery, wazuhQuery, sigmaRule, yaraRule };
