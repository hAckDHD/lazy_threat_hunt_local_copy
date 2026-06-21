import { createClient, type Client } from '@libsql/client';
import { join } from 'path';
import { homedir } from 'os';
import { mkdirSync } from 'fs';
import type { IOC, IOCFilter, IOCType, IOCClassification } from '../types/index.js';

let _client: Client | null = null;
let _ready = false;

function makeClient(): Client {
  const dir = process.env.IOC_DATA_DIR ?? join(homedir(), '.ioc-tool');
  mkdirSync(dir, { recursive: true });
  return createClient({ url: `file:${join(dir, 'iocs.db')}` });
}

export async function getDB(): Promise<Client> {
  if (!_client) _client = makeClient();
  if (!_ready) { await migrate(_client); _ready = true; }
  return _client;
}

async function migrate(db: Client): Promise<void> {
  await db.execute(`CREATE TABLE IF NOT EXISTS iocs (
    id          TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    type        TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'unknown',
    source      TEXT NOT NULL,
    source_url  TEXT,
    source_file TEXT,
    extracted_at TEXT NOT NULL,
    enriched_at  TEXT,
    enrichment  TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    notes       TEXT,
    tlp         TEXT
  )`);
  await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_value_type ON iocs(value, type)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_classification ON iocs(classification)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_extracted_at ON iocs(extracted_at)');
  try { await db.execute('ALTER TABLE iocs ADD COLUMN ignored INTEGER NOT NULL DEFAULT 0'); } catch {}
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_ignored ON iocs(ignored)');

}

export async function upsertIOC(ioc: IOC): Promise<{ inserted: boolean }> {
  const db = await getDB();
  const existing = await db.execute({ sql: 'SELECT id FROM iocs WHERE value = ? AND type = ?', args: [ioc.value, ioc.type] });
  if (existing.rows.length > 0) return { inserted: false };
  await db.execute({
    sql: `INSERT INTO iocs
      (id, value, type, classification, source, source_url, source_file,
       extracted_at, enriched_at, enrichment, tags, notes, tlp)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      ioc.id, ioc.value, ioc.type, ioc.classification, ioc.source,
      ioc.sourceUrl ?? null, ioc.sourceFile ?? null, ioc.extractedAt,
      ioc.enrichedAt ?? null, ioc.enrichment ? JSON.stringify(ioc.enrichment) : null,
      JSON.stringify(ioc.tags), ioc.notes ?? null, ioc.tlp ?? null,
    ],
  });
  return { inserted: true };
}

export async function bulkUpsertIOCs(iocs: IOC[]): Promise<{ inserted: number }> {
  if (!iocs.length) return { inserted: 0 };
  const db = await getDB();
  const CHUNK = 100;
  let inserted = 0;
  for (let i = 0; i < iocs.length; i += CHUNK) {
    const chunk = iocs.slice(i, i + CHUNK);
    const stmts = chunk.map(ioc => ({
      sql: `INSERT OR IGNORE INTO iocs
        (id, value, type, classification, source, source_url, source_file,
         extracted_at, enriched_at, enrichment, tags, notes, tlp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        ioc.id, ioc.value, ioc.type, ioc.classification, ioc.source,
        ioc.sourceUrl ?? null, ioc.sourceFile ?? null, ioc.extractedAt,
        ioc.enrichedAt ?? null, ioc.enrichment ? JSON.stringify(ioc.enrichment) : null,
        JSON.stringify(ioc.tags), ioc.notes ?? null, ioc.tlp ?? null,
      ] as (string | number | null)[],
    }));
    const results = await db.batch(stmts);
    for (const r of results) inserted += r.rowsAffected;
  }
  return { inserted };
}

export async function bulkLinkSourceUrl(iocs: IOC[], sourceUrl: string): Promise<{ updated: number }> {
  if (!iocs.length) return { updated: 0 };
  const db = await getDB();
  const CHUNK = 100;
  let updated = 0;
  for (let i = 0; i < iocs.length; i += CHUNK) {
    const chunk = iocs.slice(i, i + CHUNK);
    const stmts = chunk.map(ioc => ({
      sql: `UPDATE iocs SET source_url = ?, source = 'scraper' WHERE value = ? AND type = ? AND source_url IS NULL`,
      args: [sourceUrl, ioc.value, ioc.type] as (string | null)[],
    }));
    const results = await db.batch(stmts);
    for (const r of results) updated += r.rowsAffected;
  }
  return { updated };
}

export async function updateEnrichment(id: string, enrichment: IOC['enrichment']): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET enrichment = ?, enriched_at = ? WHERE id = ?', args: [JSON.stringify(enrichment), new Date().toISOString(), id] });
}

export async function updateClassification(id: string, classification: IOCClassification): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET classification = ? WHERE id = ?', args: [classification, id] });
}

export async function getIOC(id: string): Promise<IOC | null> {
  const db = await getDB();
  const result = await db.execute({ sql: 'SELECT * FROM iocs WHERE id = ?', args: [id] });
  const row = result.rows[0];
  return row ? rowToIOC(row as unknown as RawRow) : null;
}


function buildWhereClause(filter: IOCFilter): { where: string; args: (string | number | null)[] } {
  let where = filter.includeIgnored ? '1=1' : 'ignored=0';
  const args: (string | number | null)[] = [];

  if (filter.type?.length) {
    where += ` AND type IN (${filter.type.map(() => '?').join(',')})`;
    args.push(...filter.type);
  }
  if (filter.classification?.length) {
    where += ` AND classification IN (${filter.classification.map(() => '?').join(',')})`;
    args.push(...filter.classification);
  }
  if (filter.source?.length) {
    where += ` AND source IN (${filter.source.map(() => '?').join(',')})`;
    args.push(...filter.source);
  }
  if (filter.sourceUrl !== undefined) {
    if (filter.sourceUrl === '') {
      where += ' AND source_url IS NULL';
    } else {
      where += ' AND source_url = ?';
      args.push(filter.sourceUrl);
    }
  }
  if (filter.since) {
    where += ' AND extracted_at >= ?';
    args.push(filter.since);
  }
  if (filter.search) {
    where += ' AND value LIKE ?';
    args.push(`%${filter.search}%`);
  }

  return { where, args };
}

export async function listIOCs(filter: IOCFilter = {}): Promise<IOC[]> {
  const db = await getDB();
  const { where, args } = buildWhereClause(filter);
  let sql = `SELECT * FROM iocs WHERE ${where}`;

  sql += ' ORDER BY extracted_at DESC';
  const limit = filter.limit ?? 500;
  const offset = filter.offset ?? 0;
  sql += ' LIMIT ? OFFSET ?';
  args.push(limit, offset);

  const result = await db.execute({ sql, args });
  return result.rows.map(r => rowToIOC(r as unknown as RawRow));
}

export async function countIOCs(filter: IOCFilter = {}): Promise<number> {
  const db = await getDB();
  const { where, args } = buildWhereClause(filter);
  const sql = `SELECT COUNT(*) as n FROM iocs WHERE ${where}`;
  const result = await db.execute({ sql, args });
  return Number(result.rows[0]?.n ?? 0);
}

export async function clearAllIOCs(): Promise<void> {
  const db = await getDB();
  await db.execute('DELETE FROM iocs');
}

export async function deleteIOC(id: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'DELETE FROM iocs WHERE id = ?', args: [id] });
}

export async function ignoreIOC(id: string, ignored: boolean): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET ignored=? WHERE id=?', args: [ignored ? 1 : 0, id] });
}

export async function restoreAllIgnored(): Promise<number> {
  const db = await getDB();
  const result = await db.execute('UPDATE iocs SET ignored=0 WHERE ignored=1');
  return result.rowsAffected;
}

export async function getStatsByType(source?: string): Promise<Record<string, { total: number; malicious: number; suspicious: number }>> {
  const db = await getDB();
  const SAFE = ['scraper', 'manual', 'file', 'feed'];
  const whereExtra = (source && SAFE.includes(source)) ? ` AND source = '${source}'` : '';
  const result = await db.execute(`
    SELECT type,
      COUNT(*) as total,
      SUM(CASE WHEN classification='malicious' THEN 1 ELSE 0 END) as malicious,
      SUM(CASE WHEN classification='suspicious' THEN 1 ELSE 0 END) as suspicious
    FROM iocs WHERE ignored=0${whereExtra} GROUP BY type
  `);
  const out: Record<string, { total: number; malicious: number; suspicious: number }> = {};
  for (const r of result.rows) {
    out[r.type as string] = { total: Number(r.total), malicious: Number(r.malicious), suspicious: Number(r.suspicious) };
  }
  return out;
}

export async function getFeeds(): Promise<Array<{ url: string; count: number; lastSeen: string }>> {
  const db = await getDB();
  const result = await db.execute(`
    SELECT source_url as url, COUNT(*) as count, MAX(extracted_at) as lastSeen
    FROM iocs WHERE source_url IS NOT NULL
    GROUP BY source_url ORDER BY count DESC
  `);
  return result.rows.map(r => ({ url: r.url as string, count: Number(r.count), lastSeen: r.lastSeen as string }));
}

export async function getStatsBySource(): Promise<Array<{ source: string; sourceUrl: string | null; label: string; count: number; byType: Record<string, number> }>> {
  const db = await getDB();
  const groupsResult = await db.execute(`
    SELECT source, source_url, COUNT(*) as count
    FROM iocs GROUP BY source, source_url ORDER BY count DESC
  `);
  const out = [];
  for (const g of groupsResult.rows) {
    const sourceUrl = (g.source_url as string | null);
    const source = g.source as string;
    const count = Number(g.count);
    const byTypeResult = await db.execute(
      sourceUrl
        ? { sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source_url = ? GROUP BY type', args: [sourceUrl] }
        : { sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source = ? AND source_url IS NULL GROUP BY type', args: [source] }
    );
    const byType: Record<string, number> = {};
    for (const r of byTypeResult.rows) byType[r.type as string] = Number(r.n);
    const label = sourceUrl ? sourceUrl.replace(/^https?:\/\//, '').slice(0, 50) : source;
    out.push({ source, sourceUrl, label, count, byType });
  }
  return out;
}

export async function getFeedsWithTypes(): Promise<Array<{ url: string; count: number; lastSeen: string; byType: Record<string, number> }>> {
  const feeds = await getFeeds();
  const db = await getDB();
  return Promise.all(feeds.map(async f => {
    const result = await db.execute({ sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source_url = ? GROUP BY type', args: [f.url] });
    const byType: Record<string, number> = {};
    for (const r of result.rows) byType[r.type as string] = Number(r.n);
    return { ...f, byType };
  }));
}

export async function deleteBySourceUrl(url: string): Promise<number> {
  const db = await getDB();
  const result = await db.execute({ sql: 'DELETE FROM iocs WHERE source_url = ?', args: [url] });
  return result.rowsAffected;
}

export async function getStats(): Promise<Record<string, number>> {
  const db = await getDB();
  const [totalR, ignoredR, byTypeR, byClassR] = await Promise.all([
    db.execute('SELECT COUNT(*) as n FROM iocs WHERE ignored=0'),
    db.execute('SELECT COUNT(*) as n FROM iocs WHERE ignored=1'),
    db.execute('SELECT type, COUNT(*) as n FROM iocs WHERE ignored=0 GROUP BY type'),
    db.execute('SELECT classification, COUNT(*) as n FROM iocs WHERE ignored=0 GROUP BY classification'),
  ]);
  const stats: Record<string, number> = {
    total: Number(totalR.rows[0]?.n ?? 0),
    ignored: Number(ignoredR.rows[0]?.n ?? 0),
  };
  for (const r of byTypeR.rows) stats[`type:${r.type}`] = Number(r.n);
  for (const r of byClassR.rows) stats[`class:${r.classification}`] = Number(r.n);
  return stats;
}

interface RawRow {
  id: string;
  value: string;
  type: string;
  classification: string;
  source: string;
  source_url: string | null;
  source_file: string | null;
  extracted_at: string;
  enriched_at: string | null;
  enrichment: string | null;
  tags: string;
  notes: string | null;
  tlp: string | null;
  ignored: number | bigint;
}

function rowToIOC(row: RawRow): IOC {
  return {
    id: row.id,
    value: row.value,
    type: row.type as IOCType,
    classification: row.classification as IOCClassification,
    source: row.source as IOC['source'],
    sourceUrl: row.source_url ?? undefined,
    sourceFile: row.source_file ?? undefined,
    extractedAt: row.extracted_at,
    enrichedAt: row.enriched_at ?? undefined,
    enrichment: row.enrichment ? JSON.parse(row.enrichment) : undefined,
    tags: JSON.parse(row.tags),
    notes: row.notes ?? undefined,
    tlp: (row.tlp as IOC['tlp']) ?? undefined,
    ignored: Number(row.ignored) === 1,
  };
}

