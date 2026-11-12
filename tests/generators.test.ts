import { describe, test, expect } from 'bun:test';
import * as yaml from 'js-yaml';
import { generateHuntQueries } from '../src/hunting/index.js';
import { generateDetectionRules } from '../src/detection/index.js';
import type { IOC } from '../src/types/index.js';

// Regression tests for query/rule generator escaping and output validity.

const iocs: IOC[] = [
  { id: '1', value: '198.51.100.7', type: 'ip', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
  { id: '2', value: 'evil-c2.example', type: 'domain', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
  { id: '3', value: 'a'.repeat(64), type: 'sha256', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [], enrichment: { provider: 'vt', attackTechniques: ['T1027'] } },
  { id: '4', value: 'b'.repeat(64), type: 'sha256', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
  { id: '5', value: "HKEY_LOCAL_MACHINE\\SOFTWARE\\Evil'; DROP", type: 'registry_key', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
  { id: '6', value: 'CVE-2024-1234', type: 'cve', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
  { id: '7', value: 'http://evil.example/payload', type: 'url', classification: 'malicious', source: 'manual', extractedAt: new Date().toISOString(), tags: [] },
];

const hunt = generateHuntQueries(iocs, 'all', { timeRange: { type: 'relative', relative: '7d' } });
const rules = generateDetectionRules(iocs, 'all');

describe('Sigma hunt queries (src/hunting/sigma.ts)', () => {
  const sigma = hunt.filter(q => q.platform === 'sigma');

  test('every generated rule is valid YAML', () => {
    for (const q of sigma) expect(() => yaml.load(q.query)).not.toThrow();
  });

  test('a single quote in an IOC value is escaped, not left to break out of the YAML scalar', () => {
    const regKey = sigma.find(q => q.iocType === 'registry_key')!;
    expect(regKey.query).toContain("Evil''");
  });

  test('a description containing a colon does not break YAML parsing', () => {
    const ip = sigma.find(q => q.iocType === 'ip')!;
    const parsed = yaml.load(ip.query) as any;
    expect(parsed.description).toContain('SIGMA:');
  });
});

describe('KQL hunt queries (src/hunting/kql.ts)', () => {
  test('domain case no longer matches all A-record traffic via QueryType=="A"', () => {
    const domain = hunt.find(q => q.platform === 'kql' && q.iocType === 'domain')!;
    expect(domain.query).not.toContain('QueryType == "A"');
  });
});

describe('CrowdStrike CQL hunt queries (src/hunting/cql.ts)', () => {
  test('no bare `in(...) OR in(...)` composition (invalid LogScale syntax)', () => {
    const cql = hunt.filter(q => q.platform === 'cql');
    for (const q of cql) expect(q.query).not.toMatch(/\)\s+OR\s+in\(/);
  });
});

describe('Elastic hunt queries (src/hunting/elastic.ts)', () => {
  const elastic = hunt.filter(q => q.platform === 'elastic');

  test('every generated query is valid JSON', () => {
    for (const q of elastic) expect(() => JSON.parse(q.query)).not.toThrow();
  });

  test('a time range option produces an @timestamp filter clause', () => {
    const ip = elastic.find(q => q.iocType === 'ip')!;
    const parsed = JSON.parse(ip.query);
    expect(parsed.query.bool.filter?.[0]?.range?.['@timestamp']).toBeDefined();
  });

  test('url and cve cases are supported (previously fell through to null)', () => {
    expect(elastic.some(q => q.iocType === 'url')).toBe(true);
    expect(elastic.some(q => q.iocType === 'cve')).toBe(true);
  });
});

describe('YARA hunt queries (src/hunting/yara.ts)', () => {
  test('multi-hash SHA256 rule uses or-chained hash.sha256() conditions, not "any of them" against an empty strings block', () => {
    const yaraSha256 = hunt.find(q => q.platform === 'yara' && q.iocType === 'sha256')!;
    expect(yaraSha256.query).not.toContain('any of them');
    expect(yaraSha256.query).toContain('hash.sha256(0, filesize) ==');
  });
});

describe('Detection rules (src/detection/index.ts)', () => {
  test('Sigma rules parse as YAML', () => {
    for (const r of rules.filter(r => r.platform === 'sigma')) {
      expect(() => yaml.load(r.rule)).not.toThrow();
    }
  });

  test('real enriched ATT&CK technique wins over the static per-type guess', () => {
    const sha256Sigma = rules.find(r => r.platform === 'sigma' && r.iocType === 'sha256')!;
    expect(sha256Sigma.mitreAttack).toContain('T1027');
  });

  test('Elastic rules use the threat_match rule type with a real threat_mapping, except CVE', () => {
    for (const r of rules.filter(r => r.platform === 'elastic')) {
      const parsed = JSON.parse(r.rule);
      if (r.iocType === 'cve') {
        expect(parsed.type).toBe('query');
      } else {
        expect(parsed.type).toBe('threat_match');
        expect(Array.isArray(parsed.threat_mapping)).toBe(true);
        expect(parsed.threat_mapping.length).toBeGreaterThan(0);
      }
    }
  });

  test('Elastic threat.tactic.id is a real TA-prefixed tactic id, not a technique id fragment', () => {
    for (const r of rules.filter(r => r.platform === 'elastic')) {
      const parsed = JSON.parse(r.rule);
      expect(parsed.threat[0].tactic.id).toMatch(/^TA\d{4}$/);
    }
  });

  test('Elastic registry rule uses the real ECS field registry.path, not registry.key.path', () => {
    const reg = rules.find(r => r.platform === 'elastic' && r.iocType === 'registry_key')!;
    expect(reg.rule).toContain('"registry.path"');
    expect(reg.rule).not.toContain('registry.key.path');
  });

  test('Splunk rules target CIM fields (dest/query), not raw dst/dns.query', () => {
    for (const r of rules.filter(r => r.platform === 'splunk')) {
      expect(r.rule).not.toMatch(/\bdst IN\b/);
      expect(r.rule).not.toContain('dns.query IN');
    }
  });

  test('Splunk risk stanza uses indexed RBA keys, not the malformed non-indexed ones', () => {
    for (const r of rules.filter(r => r.platform === 'splunk')) {
      expect(r.rule).toContain('action.risk.param._risk_object_1');
      expect(r.rule).not.toContain('action.risk.param._risk_object_type =');
    }
  });

  test('KQL rules have kind/version/requiredDataConnectors and emit TimeGenerated', () => {
    for (const r of rules.filter(r => r.platform === 'kql')) {
      expect(r.rule).toContain('kind: Scheduled');
      expect(r.rule).toContain('version: 1');
      expect(r.rule).toContain('TimeGenerated = LastSeen');
      expect(r.rule).toContain('reopenClosedIncident');
      expect(r.rule).not.toContain('reopeningStrategy');
    }
  });
});
