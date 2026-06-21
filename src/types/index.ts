export type IOCType =
  | 'ip'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'sha256'
  | 'sha1'
  | 'md5'
  | 'email'
  | 'cve'
  | 'hostname'
  | 'registry_key'
  | 'filename';

export type IOCClassification =
  | 'malicious'
  | 'suspicious'
  | 'unknown'
  | 'internal'
  | 'external';

export type IOCSource = 'manual' | 'scraper' | 'file' | 'feed';

export interface IOCEnrichment {
  reputationScore?: number;     // 0-100, higher = more malicious
  asn?: string;
  asnOrg?: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  malwareFamily?: string[];
  attackTechniques?: string[];  // MITRE ATT&CK IDs e.g. T1566
  firstSeen?: string;
  lastSeen?: string;
  provider: string;
  positives?: number;
  total?: number;
  raw?: Record<string, unknown>;
}

export interface IOC {
  id: string;
  value: string;
  type: IOCType;
  classification: IOCClassification;
  source: IOCSource;
  sourceUrl?: string;
  sourceFile?: string;
  extractedAt: string;
  enrichedAt?: string;
  enrichment?: IOCEnrichment;
  tags: string[];
  notes?: string;
  tlp?: 'white' | 'green' | 'amber' | 'red';
  ignored?: boolean;
}

export interface ExtractionResult {
  iocs: IOC[];
  sourceUrl?: string;
  sourceFile?: string;
  rawText?: string;
  extractedAt: string;
  stats: {
    total: number;
    byType: Partial<Record<IOCType, number>>;
    duplicatesRemoved: number;
  };
}

export interface EnrichmentConfig {
  virusTotal?: string;
  abuseIpDb?: string;
  shodan?: string;
}

export interface HuntTimeRange {
  type: 'relative' | 'absolute';
  relative?: '1d' | '7d' | '14d' | '30d' | '90d';
  start?: string;
  end?: string;
}

export interface HuntOptions {
  timeRange?: HuntTimeRange;
}

export interface HuntQuery {
  platform: 'splunk' | 'elastic' | 'kql' | 'sigma' | 'yara' | 'cql' | 's1ql' | 'wazuh' | 'tql';
  query: string;
  description: string;
  iocType: IOCType;
  iocValues: string[];
}

export interface ExecutiveReport {
  generatedAt: string;
  periodStart: string;
  periodEnd: string;
  totalIOCs: number;
  criticalCount: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  businessImpact: {
    affectedSystems: string[];
    usersAtRisk: number;
    externalCommunications: boolean;
    estimatedImpact: string;
    geographicSpread: string[];
  };
  timeline: Array<{
    timestamp: string;
    event: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  attackTechniques: string[];
  recommendations: string[];
}

export interface AnalystReport {
  generatedAt: string;
  iocs: IOC[];
  huntQueries: HuntQuery[];
  enrichmentSummary: {
    enriched: number;
    pending: number;
    failed: number;
  };
  iocsByType: Partial<Record<IOCType, IOC[]>>;
  iocsByClassification: Partial<Record<IOCClassification, IOC[]>>;
  threatActorHypotheses: string[];
  detectionOpportunities: string[];
}

export interface IOCFilter {
  type?: IOCType[];
  classification?: IOCClassification[];
  source?: IOCSource[];
  sourceUrl?: string;
  since?: string;
  tags?: string[];
  search?: string;
  includeIgnored?: boolean;
  limit?: number;
  offset?: number;
}
