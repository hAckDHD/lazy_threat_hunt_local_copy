#!/usr/bin/env bun
import { parseArgs } from 'util';
import { scrapeURL } from './ingestion/scraper.js';
import { parseBulkText, parseJSONFeed } from './ingestion/manual.js';
import { parseFile } from './ingestion/file-parser.js';
import { upsertIOC, listIOCs, getStats, deleteIOC } from './storage/db.js';
import { enrichBatch, loadConfig } from './enrichment/index.js';
import { classifyBatch } from './classification/classifier.js';
import { generateHuntQueries } from './hunting/index.js';
import { generateExecutiveReport } from './reporting/executive.js';
import { generateAnalystReport, formatAnalystReportText } from './reporting/analyst.js';
import { startServer } from './ui/server.js';
import type { IOCFilter } from './types/index.js';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const MAGENTA = '\x1b[35m';

function color(c: string, s: string): string {
  return c + s + RESET;
}

function classColor(cls: string): string {
  switch (cls) {
    case 'malicious':  return RED;
    case 'suspicious': return YELLOW;
    case 'internal':   return CYAN;
    case 'external':   return GREEN;
    default:           return DIM;
  }
}

const HELP = `
${BOLD}IOC Intelligence Platform${RESET}

${BOLD}USAGE${RESET}
  ioc <command> [options]

${BOLD}COMMANDS${RESET}
  extract <url|file>       Scrape URL or parse file, extract IOCs, store
  paste                    Read stdin, extract IOCs
  enrich [--all]           Enrich stored IOCs (requires API keys in .env)
  list [options]           List stored IOCs
  hunt [--platform=<p>]    Generate hunting queries for malicious/suspicious IOCs
  report exec              Generate executive report (stdout)
  report analyst           Generate analyst report (stdout)
  stats                    Show DB stats
  delete <id>              Delete an IOC by ID
  serve                    Start web UI server

${BOLD}OPTIONS (list)${RESET}
  --type=ip,domain,...     Filter by type
  --class=malicious,...    Filter by classification
  --search=<term>          Search IOC values
  --since=<ISO date>       Filter by extraction date

${BOLD}HUNT PLATFORMS${RESET}
  splunk, elastic, kql, sigma, yara, all (default)

${BOLD}ENVIRONMENT${RESET}
  VT_API_KEY               VirusTotal API key
  ABUSEIPDB_API_KEY        AbuseIPDB API key
  SHODAN_API_KEY           Shodan API key
  IOC_DATA_DIR             Override data directory (default: ~/.ioc-tool)
  IOC_PORT                 Web UI port (default: 8847)

${BOLD}EXAMPLES${RESET}
  ioc extract https://threatreport.example.com/apt29
  ioc extract ./malware-report.pdf
  echo "1.2.3.4 evil.com" | ioc paste
  ioc enrich --all
  ioc list --class=malicious
  ioc hunt --platform=splunk
  ioc report exec
  ioc serve
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (!args.length || args[0] === '--help' || args[0] === '-h') {
    console.log(HELP);
    process.exit(0);
  }

  const cmd = args[0];

  switch (cmd) {
    case 'extract': {
      const target = args[1];
      if (!target) { console.error('Usage: ioc extract <url|file>'); process.exit(1); }

      console.log(color(CYAN, `Extracting from: ${target}`));

      let result;
      if (target.startsWith('http://') || target.startsWith('https://')) {
        result = await scrapeURL(target);
      } else {
        result = await parseFile(target);
      }

      const classified = classifyBatch(result.iocs);
      let inserted = 0;
      for (const ioc of classified) {
        const r = await upsertIOC(ioc);
        if (r.inserted) inserted++;
      }

      printExtractionResult(classified, inserted, result.stats.duplicatesRemoved);
      break;
    }

    case 'paste': {
      const chunks: string[] = [];
      process.stdin.setEncoding('utf-8');
      for await (const chunk of process.stdin) chunks.push(chunk);
      const text = chunks.join('');
      const result = parseBulkText(text);
      const classified = classifyBatch(result.iocs);
      let inserted = 0;
      for (const ioc of classified) {
        const r = await upsertIOC(ioc);
        if (r.inserted) inserted++;
      }
      printExtractionResult(classified, inserted, 0);
      break;
    }

    case 'enrich': {
      const all = args.includes('--all');
      const cfg = loadConfig();
      const hasKeys = cfg.virusTotal || cfg.abuseIpDb || cfg.shodan;
      if (!hasKeys) {
        console.error(color(YELLOW, 'No API keys configured. Set VT_API_KEY, ABUSEIPDB_API_KEY, or SHODAN_API_KEY'));
        process.exit(1);
      }

      const filter: IOCFilter = all ? {} : { classification: ['unknown'] };
      const iocs = await listIOCs(filter);
      console.log(color(CYAN, `Enriching ${iocs.length} IOC(s)...`));

      const enriched = await enrichBatch(iocs, cfg, 3);
      const changed = enriched.filter(i => i.enrichedAt).length;
      console.log(color(GREEN, `Enriched ${changed}/${iocs.length} IOC(s)`));
      break;
    }

    case 'list': {
      const filter = parseListFilter(args.slice(1));
      const iocs = await listIOCs(filter);

      if (!iocs.length) {
        console.log(color(DIM, 'No IOCs found.'));
        break;
      }

      console.log(
        color(DIM, 'Value'.padEnd(45)) +
        color(DIM, 'Type'.padEnd(14)) +
        color(DIM, 'Class'.padEnd(14)) +
        color(DIM, 'Country'.padEnd(10)) +
        color(DIM, 'Score'.padEnd(8)) +
        color(DIM, 'Extracted')
      );
      console.log('─'.repeat(110));

      for (const ioc of iocs) {
        const score = ioc.enrichment?.reputationScore;
        const scoreStr = score !== undefined ? String(score).padEnd(8) : '—'.padEnd(8);
        const cls = ioc.classification;
        console.log(
          ioc.value.substring(0, 44).padEnd(45) +
          color(MAGENTA, ioc.type.padEnd(14)) +
          color(classColor(cls), cls.padEnd(14)) +
          (ioc.enrichment?.country ?? '—').padEnd(10) +
          scoreStr +
          color(DIM, ioc.extractedAt.split('T')[0])
        );
      }
      console.log(color(DIM, `\n${iocs.length} IOC(s) shown`));
      break;
    }

    case 'hunt': {
      const platformArg = args.find(a => a.startsWith('--platform='));
      const platform = (platformArg?.split('=')[1] ?? 'all') as 'all';
      const iocs = await listIOCs({ classification: ['malicious', 'suspicious'] });

      if (!iocs.length) {
        console.log(color(YELLOW, 'No malicious/suspicious IOCs to generate queries for.'));
        break;
      }

      const queries = generateHuntQueries(iocs, platform);
      for (const q of queries) {
        console.log('\n' + color(BOLD, `[${q.platform.toUpperCase()}] ${q.description}`));
        console.log(color(DIM, '─'.repeat(60)));
        console.log(q.query);
      }
      console.log(color(DIM, `\n${queries.length} query/queries generated`));
      break;
    }

    case 'report': {
      const type = args[1];
      const since = new Date(Date.now() - 7 * 86400000).toISOString();
      const iocs = await listIOCs({ since });

      if (type === 'exec' || type === 'executive') {
        const report = generateExecutiveReport(iocs, since, new Date().toISOString());
        printExecutiveReport(report);
      } else if (type === 'analyst') {
        const report = generateAnalystReport(iocs);
        console.log(formatAnalystReportText(report));
      } else {
        console.error('Usage: ioc report [exec|analyst]');
        process.exit(1);
      }
      break;
    }

    case 'stats': {
      const stats = await getStats();
      console.log(color(BOLD, 'IOC Database Stats'));
      console.log('─'.repeat(30));
      for (const [k, v] of Object.entries(stats)) {
        const label = k.includes(':') ? k.split(':').join(' → ').padEnd(25) : k.padEnd(25);
        console.log(label + color(CYAN, String(v)));
      }
      break;
    }

    case 'delete': {
      const id = args[1];
      if (!id) { console.error('Usage: ioc delete <id>'); process.exit(1); }
      await deleteIOC(id);
      console.log(color(GREEN, `Deleted ${id}`));
      break;
    }

    case 'serve': {
      startServer();
      break;
    }

    default:
      console.error(color(RED, `Unknown command: ${cmd}`));
      console.log(HELP);
      process.exit(1);
  }
}

function printExtractionResult(
  iocs: ReturnType<typeof classifyBatch>,
  inserted: number,
  dupes: number
): void {
  if (!iocs.length) {
    console.log(color(YELLOW, 'No IOCs extracted.'));
    return;
  }

  const byType: Record<string, number> = {};
  const byCls: Record<string, number> = {};
  for (const ioc of iocs) {
    byType[ioc.type] = (byType[ioc.type] ?? 0) + 1;
    byCls[ioc.classification] = (byCls[ioc.classification] ?? 0) + 1;
  }

  console.log(color(GREEN, `\nExtracted ${iocs.length} IOC(s) — ${inserted} new`));
  if (dupes > 0) console.log(color(DIM, `${dupes} duplicates removed`));
  console.log('');
  console.log('By type:  ' + Object.entries(byType).map(([t, n]) => `${color(MAGENTA, t)}:${n}`).join('  '));
  console.log('By class: ' + Object.entries(byCls).map(([c, n]) => `${color(classColor(c), c)}:${n}`).join('  '));
}

function parseListFilter(args: string[]): IOCFilter {
  const filter: IOCFilter = {};
  for (const arg of args) {
    if (arg.startsWith('--type=')) filter.type = arg.split('=')[1].split(',') as IOCFilter['type'];
    if (arg.startsWith('--class=')) filter.classification = arg.split('=')[1].split(',') as IOCFilter['classification'];
    if (arg.startsWith('--since=')) filter.since = arg.split('=')[1];
    if (arg.startsWith('--search=')) filter.search = arg.split('=')[1];
  }
  return filter;
}

function printExecutiveReport(r: ReturnType<typeof generateExecutiveReport>): void {
  const sevColor = { critical: RED, high: YELLOW, medium: CYAN, low: GREEN }[r.severity] ?? DIM;

  console.log('\n' + color(BOLD, '═══ EXECUTIVE THREAT INTELLIGENCE REPORT ═══'));
  console.log(color(DIM, `Generated: ${r.generatedAt}  |  Period: ${r.periodStart.split('T')[0]} → ${r.periodEnd.split('T')[0]}`));
  console.log('');
  console.log(color(BOLD, 'SEVERITY:  ') + color(sevColor, r.severity.toUpperCase()));
  console.log(color(BOLD, 'Total IOCs: ') + r.totalIOCs);
  console.log(color(BOLD, 'Confirmed Malicious: ') + color(RED, String(r.criticalCount)));
  console.log('');
  console.log(color(BOLD, 'BUSINESS IMPACT'));
  console.log('  Impact: ' + r.businessImpact.estimatedImpact);
  console.log('  Users at risk: ' + r.businessImpact.usersAtRisk);
  console.log('  External C2: ' + (r.businessImpact.externalCommunications
    ? color(RED, 'YES') : color(GREEN, 'No')));
  console.log('  Affected systems:');
  for (const s of r.businessImpact.affectedSystems) console.log('    • ' + s);
  if (r.businessImpact.geographicSpread.length) {
    console.log('  Geographic spread: ' + r.businessImpact.geographicSpread.join(', '));
  }
  console.log('');
  if (r.attackTechniques.length) {
    console.log(color(BOLD, 'ATT&CK TECHNIQUES'));
    for (const t of r.attackTechniques) console.log('  ' + color(MAGENTA, t));
    console.log('');
  }
  console.log(color(BOLD, 'TIMELINE'));
  for (const e of r.timeline) {
    console.log(`  ${color(DIM, e.timestamp)}  ${e.event}`);
  }
  console.log('');
  console.log(color(BOLD, 'RECOMMENDATIONS'));
  for (const rec of r.recommendations) {
    console.log('  ' + color(CYAN, '→') + ' ' + rec);
  }
  console.log('');
}

main().catch(err => {
  console.error(color(RED, 'Fatal: ') + err.message);
  process.exit(1);
});
