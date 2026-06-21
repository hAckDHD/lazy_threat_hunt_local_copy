# Lazy Threat Hunt — Local Instance

A local-only copy of the Lazy Threat Hunt IOC intelligence platform. No Vercel, no Turso, no cloud dependencies. Just Bun + SQLite on your box.

## What It Does

Extract, classify, enrich, hunt, and report on IOCs — all from a single terminal or web UI. Paste threat intel, scrape feeds, upload PDFs, and get hunting queries for Splunk, Elastic, KQL, Sigma, YARA, and more.

## Requirements

- [Bun](https://bun.sh) v1.3+
- That's it. Seriously.

## Quick Start

```bash
git clone git@github.com:hAckDHD/lazy_threat_hunt_local_copy.git
cd lazy_threat_hunt_local_copy
bun install
bun src/cli.ts serve
```

Open `http://localhost:8847` in your browser. Done.

## CLI Usage

```bash
# Extract IOCs from a URL
bun src/cli.ts extract https://threatreport.example.com/apt29

# Extract from a file
bun src/cli.ts extract ./malware-report.pdf

# Paste IOCs directly
echo "1.2.3.4 evil.com" | bun src/cli.ts paste

# List stored IOCs
bun src/cli.ts list --class=malicious

# Generate hunting queries
bun src/cli.ts hunt --platform=splunk

# Enrich IOCs (requires API keys in .env)
bun src/cli.ts enrich --all

# Generate reports
bun src/cli.ts report exec
bun src/cli.ts report analyst

# Web UI
bun src/cli.ts serve
```

## Configuration

Copy `.env.example` to `.env` and fill in what you want:

```bash
cp .env.example .env
```

| Variable | Required | Notes |
|----------|----------|-------|
| `IOC_API_TOKEN` | No | Set to require auth on all API routes |
| `IOC_ALLOWED_ORIGIN` | No | CORS origin (leave empty for local-only) |
| `VT_API_KEY` | No | VirusTotal enrichment |
| `ABUSEIPDB_API_KEY` | No | AbuseIPDB enrichment |
| `SHODAN_API_KEY` | No | Shodan enrichment |
| `IOC_PORT` | No | Web UI port (default: 8847) |
| `IOC_DATA_DIR` | No | SQLite DB location (default: `~/.ioc-tool`) |

All API keys are optional. The tool works fine without them — you'll just get links to the public pages instead of inline results.

## Tech Stack

- **Runtime:** Bun
- **Language:** TypeScript
- **Database:** SQLite (via @libsql/client)
- **UI:** Vanilla HTML/CSS/JS (no framework, no build step)
- **Dependencies:** 3 packages — @libsql/client, mammoth, pdf-parse

## Why Local?

Because sometimes your threat intel doesn't need to touch the cloud. This is a stripped-down version of [Lazy Threat Hunt](https://github.com/hAckDHD/LAZY_THREAT_HUNT) with all the Vercel/Turso stuff removed. Runs entirely on your machine, data stays on your disk.

---

Created by [hAckDHD](https://github.com/hackdhd)
