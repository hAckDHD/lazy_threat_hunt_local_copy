import { join } from 'path';
import { homedir } from 'os';
import { mkdirSync } from 'fs';
import type { IOC, IOCFilter, IOCType, IOCClassification } from '../types/index.js';

// ── Database client ──────────────────────────────────────────────────────────
// Two backends behind one small interface, neither of which needs a native
// add-on, so the tool runs wherever Bun runs (Windows, macOS, Linux; x64 and
// ARM64):
//   local  — Bun's built-in SQLite, a file under IOC_DATA_DIR (default ~/.ioc-tool)
//   remote — Turso/libSQL over HTTPS (TURSO_DATABASE_URL), for serverless hosts
type Arg = string | number | null;
type Statement = string | { sql: string; args?: Arg[] };
interface Result { rows: Record<string, unknown>[]; rowsAffected: number }
interface Client {
  execute(stmt: Statement): Promise<Result>;
  batch(stmts: Statement[]): Promise<Result[]>;
}

let _client: Promise<Client> | null = null;

async function openRemote(url: string): Promise<Client> {
  const { createClient } = await import('@libsql/client/web');
  const db = createClient({ url, authToken: process.env.TURSO_AUTH_TOKEN ?? '' });
  return db as unknown as Client;
}

async function openLocal(): Promise<Client> {
  if (!process.versions.bun) {
    throw new Error('The local database needs the Bun runtime. Run with Bun, or set TURSO_DATABASE_URL.');
  }
  const dir = process.env.IOC_DATA_DIR || join(homedir(), '.ioc-tool');
  mkdirSync(dir, { recursive: true, mode: 0o700 });  // IOC data is private to this user
  const { Database } = await import('bun:sqlite');
  const db = new Database(join(dir, 'iocs.db'), { create: true });
  db.exec('PRAGMA busy_timeout = 5000');

  const run = (stmt: Statement): Result => {
    const { sql, args = [] } = typeof stmt === 'string' ? { sql: stmt } : stmt;
    const q = db.query(sql);
    if (q.columnNames.length) return { rows: q.all(...args) as Record<string, unknown>[], rowsAffected: 0 };
    return { rows: [], rowsAffected: q.run(...args).changes };
  };
  return {
    execute: async stmt => run(stmt),
    batch: async stmts => db.transaction(() => stmts.map(run))(),  // all or nothing
  };
}

export async function getDB(): Promise<Client> {
  if (!_client) {
    const url = process.env.TURSO_DATABASE_URL;
    _client = (url ? openRemote(url) : openLocal()).then(async db => { await migrate(db); return db; });
    _client.catch(() => { _client = null; });  // let the next call retry
  }
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
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_classification ON iocs(classification)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_extracted_at ON iocs(extracted_at)');
  try { await db.execute('ALTER TABLE iocs ADD COLUMN ignored INTEGER NOT NULL DEFAULT 0'); } catch {}
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_ignored ON iocs(ignored)');
  try { await db.execute("ALTER TABLE iocs ADD COLUMN hunt_status TEXT"); } catch {}
  try { await db.execute("ALTER TABLE iocs ADD COLUMN ticket_ref TEXT"); } catch {}
  try { await db.execute("ALTER TABLE iocs ADD COLUMN affected_host TEXT"); } catch {}
  try { await db.execute("ALTER TABLE iocs ADD COLUMN ticket_entries TEXT"); } catch {}
  // Per-instance isolation: each browser session gets its own opaque token
  // (minted fresh on every "/" load) and every row is scoped to it, so one
  // visitor's data is invisible to another. The old global-unique index on
  // (value, type) is replaced with one scoped by session, so two sessions
  // can independently hold "the same" IOC without colliding.
  try { await db.execute("ALTER TABLE iocs ADD COLUMN session_id TEXT NOT NULL DEFAULT ''"); } catch {}
  await db.execute('DROP INDEX IF EXISTS idx_iocs_value_type');
  await db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_value_type_session ON iocs(value, type, session_id)');
  await db.execute('CREATE INDEX IF NOT EXISTS idx_iocs_session ON iocs(session_id)');
}

export async function upsertIOC(ioc: IOC, sessionId: string): Promise<{ inserted: boolean }> {
  const db = await getDB();
  const existing = await db.execute({ sql: 'SELECT id FROM iocs WHERE value = ? AND type = ? AND session_id = ?', args: [ioc.value, ioc.type, sessionId] });
  if (existing.rows.length > 0) return { inserted: false };
  await db.execute({
    sql: `INSERT INTO iocs
      (id, value, type, classification, source, source_url, source_file,
       extracted_at, enriched_at, enrichment, tags, notes, tlp, session_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      ioc.id, ioc.value, ioc.type, ioc.classification, ioc.source,
      ioc.sourceUrl ?? null, ioc.sourceFile ?? null, ioc.extractedAt,
      ioc.enrichedAt ?? null, ioc.enrichment ? JSON.stringify(ioc.enrichment) : null,
      JSON.stringify(ioc.tags), ioc.notes ?? null, ioc.tlp ?? null, sessionId,
    ],
  });
  return { inserted: true };
}

export async function bulkUpsertIOCs(iocs: IOC[], sessionId: string): Promise<{ inserted: number }> {
  if (!iocs.length) return { inserted: 0 };
  const db = await getDB();
  const CHUNK = 100;
  let inserted = 0;
  for (let i = 0; i < iocs.length; i += CHUNK) {
    const chunk = iocs.slice(i, i + CHUNK);
    const stmts = chunk.map(ioc => ({
      sql: `INSERT OR IGNORE INTO iocs
        (id, value, type, classification, source, source_url, source_file,
         extracted_at, enriched_at, enrichment, tags, notes, tlp, session_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        ioc.id, ioc.value, ioc.type, ioc.classification, ioc.source,
        ioc.sourceUrl ?? null, ioc.sourceFile ?? null, ioc.extractedAt,
        ioc.enrichedAt ?? null, ioc.enrichment ? JSON.stringify(ioc.enrichment) : null,
        JSON.stringify(ioc.tags), ioc.notes ?? null, ioc.tlp ?? null, sessionId,
      ] as (string | number | null)[],
    }));
    const results = await db.batch(stmts);
    for (const r of results) inserted += r.rowsAffected;
  }
  return { inserted };
}

export async function bulkLinkSourceUrl(iocs: IOC[], sourceUrl: string, sessionId: string): Promise<{ updated: number }> {
  if (!iocs.length) return { updated: 0 };
  const db = await getDB();
  const CHUNK = 100;
  let updated = 0;
  for (let i = 0; i < iocs.length; i += CHUNK) {
    const chunk = iocs.slice(i, i + CHUNK);
    const stmts = chunk.map(ioc => ({
      sql: `UPDATE iocs SET source_url = ?, source = 'scraper' WHERE value = ? AND type = ? AND source_url IS NULL AND session_id = ?`,
      args: [sourceUrl, ioc.value, ioc.type, sessionId] as (string | null)[],
    }));
    const results = await db.batch(stmts);
    for (const r of results) updated += r.rowsAffected;
  }
  return { updated };
}

export async function updateEnrichment(id: string, enrichment: IOC['enrichment'], sessionId: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET enrichment = ?, enriched_at = ? WHERE id = ? AND session_id = ?', args: [JSON.stringify(enrichment), new Date().toISOString(), id, sessionId] });
}

export async function updateClassification(id: string, classification: IOCClassification, sessionId: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET classification = ? WHERE id = ? AND session_id = ?', args: [classification, id, sessionId] });
}

export async function getIOC(id: string, sessionId: string): Promise<IOC | null> {
  const db = await getDB();
  const result = await db.execute({ sql: 'SELECT * FROM iocs WHERE id = ? AND session_id = ?', args: [id, sessionId] });
  const row = result.rows[0];
  return row ? rowToIOC(row as unknown as RawRow) : null;
}


function buildWhereClause(filter: IOCFilter): { where: string; args: (string | number | null)[] } {
  let where = filter.includeIgnored ? '1=1' : 'ignored=0';
  const args: (string | number | null)[] = [];

  if (filter.sessionId !== undefined) {
    where += ' AND session_id = ?';
    args.push(filter.sessionId);
  }
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

export async function clearAllIOCs(sessionId: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'DELETE FROM iocs WHERE session_id = ?', args: [sessionId] });
}

export async function deleteIOC(id: string, sessionId: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'DELETE FROM iocs WHERE id = ? AND session_id = ?', args: [id, sessionId] });
}

export async function ignoreIOC(id: string, ignored: boolean, sessionId: string): Promise<void> {
  const db = await getDB();
  await db.execute({ sql: 'UPDATE iocs SET ignored=? WHERE id=? AND session_id=?', args: [ignored ? 1 : 0, id, sessionId] });
}

export interface IOCAnnotation {
  huntStatus?: IOC['huntStatus'] | null;
  ticketEntries?: IOC['ticketEntries'] | null;
}

// Partial update of the analyst-facing enrichment fields — only touches the
// fields actually present in `fields` so callers can update just one at a time.
export async function annotateIOC(id: string, fields: IOCAnnotation, sessionId: string): Promise<void> {
  const db = await getDB();
  const sets: string[] = [];
  const args: (string | null)[] = [];
  if ('huntStatus' in fields) { sets.push('hunt_status=?'); args.push(fields.huntStatus ?? null); }
  if ('ticketEntries' in fields) { sets.push('ticket_entries=?'); args.push(fields.ticketEntries?.length ? JSON.stringify(fields.ticketEntries) : null); }
  if (!sets.length) return;
  args.push(id, sessionId);
  await db.execute({ sql: `UPDATE iocs SET ${sets.join(', ')} WHERE id=? AND session_id=?`, args });
}

export async function restoreAllIgnored(sessionId: string): Promise<number> {
  const db = await getDB();
  const result = await db.execute({ sql: 'UPDATE iocs SET ignored=0 WHERE ignored=1 AND session_id=?', args: [sessionId] });
  return result.rowsAffected;
}

export async function getStatsByType(sessionId: string, source?: string): Promise<Record<string, { total: number; malicious: number; suspicious: number }>> {
  const db = await getDB();
  const SAFE = ['scraper', 'manual', 'file', 'feed'];
  const filterSource = Boolean(source && SAFE.includes(source));
  const result = await db.execute({
    sql: `
    SELECT type,
      COUNT(*) as total,
      SUM(CASE WHEN classification='malicious' THEN 1 ELSE 0 END) as malicious,
      SUM(CASE WHEN classification='suspicious' THEN 1 ELSE 0 END) as suspicious
    FROM iocs WHERE ignored=0 AND session_id=?${filterSource ? ' AND source = ?' : ''} GROUP BY type
  `, args: filterSource ? [sessionId, source!] : [sessionId],
  });
  const out: Record<string, { total: number; malicious: number; suspicious: number }> = {};
  for (const r of result.rows) {
    out[r.type as string] = { total: Number(r.total), malicious: Number(r.malicious), suspicious: Number(r.suspicious) };
  }
  return out;
}

export async function getFeeds(sessionId: string): Promise<Array<{ url: string; count: number; lastSeen: string }>> {
  const db = await getDB();
  const result = await db.execute({
    sql: `
    SELECT source_url as url, COUNT(*) as count, MAX(extracted_at) as lastSeen
    FROM iocs WHERE source_url IS NOT NULL AND session_id = ?
    GROUP BY source_url ORDER BY count DESC
  `, args: [sessionId],
  });
  return result.rows.map(r => ({ url: r.url as string, count: Number(r.count), lastSeen: r.lastSeen as string }));
}

export async function getStatsBySource(sessionId: string): Promise<Array<{ source: string; sourceUrl: string | null; label: string; count: number; byType: Record<string, number> }>> {
  const db = await getDB();
  const groupsResult = await db.execute({
    sql: `
    SELECT source, source_url, COUNT(*) as count
    FROM iocs WHERE session_id = ? GROUP BY source, source_url ORDER BY count DESC
  `, args: [sessionId],
  });
  const out = [];
  for (const g of groupsResult.rows) {
    const sourceUrl = (g.source_url as string | null);
    const source = g.source as string;
    const count = Number(g.count);
    const byTypeResult = await db.execute(
      sourceUrl
        ? { sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source_url = ? AND session_id = ? GROUP BY type', args: [sourceUrl, sessionId] }
        : { sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source = ? AND source_url IS NULL AND session_id = ? GROUP BY type', args: [source, sessionId] }
    );
    const byType: Record<string, number> = {};
    for (const r of byTypeResult.rows) byType[r.type as string] = Number(r.n);
    const label = sourceUrl ? sourceUrl.replace(/^https?:\/\//, '').slice(0, 50) : source;
    out.push({ source, sourceUrl, label, count, byType });
  }
  return out;
}

export async function getFeedsWithTypes(sessionId: string): Promise<Array<{ url: string; count: number; lastSeen: string; byType: Record<string, number> }>> {
  const feeds = await getFeeds(sessionId);
  const db = await getDB();
  return Promise.all(feeds.map(async f => {
    const result = await db.execute({ sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE source_url = ? AND session_id = ? GROUP BY type', args: [f.url, sessionId] });
    const byType: Record<string, number> = {};
    for (const r of result.rows) byType[r.type as string] = Number(r.n);
    return { ...f, byType };
  }));
}

export async function deleteBySourceUrl(url: string, sessionId: string): Promise<number> {
  const db = await getDB();
  const result = await db.execute({ sql: 'DELETE FROM iocs WHERE source_url = ? AND session_id = ?', args: [url, sessionId] });
  return result.rowsAffected;
}

export async function getStats(sessionId: string): Promise<Record<string, number>> {
  const db = await getDB();
  const [totalR, ignoredR, byTypeR, byClassR] = await Promise.all([
    db.execute({ sql: 'SELECT COUNT(*) as n FROM iocs WHERE ignored=0 AND session_id=?', args: [sessionId] }),
    db.execute({ sql: 'SELECT COUNT(*) as n FROM iocs WHERE ignored=1 AND session_id=?', args: [sessionId] }),
    db.execute({ sql: 'SELECT type, COUNT(*) as n FROM iocs WHERE ignored=0 AND session_id=? GROUP BY type', args: [sessionId] }),
    db.execute({ sql: 'SELECT classification, COUNT(*) as n FROM iocs WHERE ignored=0 AND session_id=? GROUP BY classification', args: [sessionId] }),
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
  hunt_status: string | null;
  ticket_entries: string | null;
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
    huntStatus: (row.hunt_status as IOC['huntStatus']) ?? undefined,
    ticketEntries: row.ticket_entries ? JSON.parse(row.ticket_entries) : undefined,
  };
}

