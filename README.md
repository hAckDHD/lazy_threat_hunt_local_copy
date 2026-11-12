# Lazy Threat Hunt

Lazy Threat Hunt is an IOC intelligence platform. It extracts indicators of compromise from threat reports, feeds, and files. It classifies and enriches them, then generates hunt queries and detection rules for your SIEM/EDR.

## Features

- **Two ways to hunt**: *IOC Hunt* starts from indicators. *Hypothesis Hunt* starts from a suspicion: a 5 W's hypothesis builder, a shareable summary, and a hunt report.
- **TTP library**: MITRE ATT&CK techniques with ready Sigma, KQL, Splunk, and Elastic queries, filterable by threat actor and platform.
- **Extraction**: pull IPs, domains, URLs, hashes, emails, CVEs, registry keys, and filenames from text, URLs, and `.txt` / `.csv` / `.json` / `.pdf` / `.docx` / `.md` files.
- **Classification and enrichment**: VirusTotal, AbuseIPDB, Shodan, ipinfo, ARIN RDAP, urlscan.io, and crt.sh.
- **Hunt queries**: Splunk SPL, Elastic DSL, Microsoft KQL, CrowdStrike CQL, SentinelOne S1QL, Wazuh, TQL, Sigma, and YARA.
- **Detection rules**: Sigma, KQL analytics rules, Splunk correlation searches, and Elastic rules, with MITRE ATT&CK mapping.
- **Reports**: an executive summary and an analyst view.
- **Session isolation**: each browser session sees only its own data. No accounts are needed.
- **Demo data**: one click loads sample IOCs or a sample hypothesis.
- **Themes**: four dark themes, one light theme, and a true-black High Contrast switch.

## Requirements

- [Bun](https://bun.sh) 1.2 or later. Nothing else: there are no native add-ons to compile.

## Supported platforms

| OS | x64 | ARM64 |
|---|---|---|
| Linux (glibc and musl) | yes | yes |
| macOS | yes (Intel) | yes (Apple silicon) |
| Windows 10 / 11 | yes | yes |

CI runs the tests and starts the server on all six combinations.

The local database uses Bun's built-in SQLite, and the remote database uses HTTPS, so the same code runs on every platform Bun supports.

## Quick start

Install Bun:

```bash
# macOS and Linux
curl -fsSL https://bun.sh/install | bash
```

```powershell
# Windows (PowerShell)
irm bun.sh/install.ps1 | iex
```

Then, in the project folder (the commands are the same on every OS):

```bash
bun install
bun run serve           # http://127.0.0.1:8847
```

Optional: copy `.env.example` to `.env` and add API keys or a token. Bun loads `.env` by itself.

Your data is stored in `~/.ioc-tool` (`%USERPROFILE%\.ioc-tool` on Windows). Set `IOC_DATA_DIR` to change it.

### CLI

```bash
bun src/cli.ts extract https://example.com/report
bun src/cli.ts extract ./report.pdf
echo "1.2.3.4 evil.example" | bun src/cli.ts paste
bun src/cli.ts hunt --platform=splunk
bun src/cli.ts --help
```

### Tests

```bash
bun test
```

## Configuration

All settings are environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Purpose |
|---|---|
| `IOC_API_TOKEN` | Requires `Authorization: Bearer <token>` on every API call. **Set this for any shared deployment.** |
| `IOC_HOST` / `IOC_PORT` | Bind address and port. The default is `127.0.0.1:8847` (loopback only). |
| `IOC_ALLOWED_ORIGIN` | Single allowed CORS origin. Leave it empty to block cross-origin calls. |
| `TURSO_DATABASE_URL` / `TURSO_AUTH_TOKEN` | Remote libSQL database. This is required on serverless hosts. |
| `IOC_DATA_DIR` | Local SQLite directory. The default is `~/.ioc-tool`. |
| `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `URLSCAN_API_KEY` | Optional enrichment keys. |
| `IOC_SHARE_SERVER_KEYS` | Set to `1` to let anonymous users of a public instance use the server's API keys. |
| `IOC_TRUST_PROXY` | Set to `1` behind a reverse proxy, so that the rate limiter uses `X-Forwarded-For`. |

Users can also paste their own VirusTotal and AbuseIPDB keys in the UI. These keys stay in the browser session and are sent only to this server.

## Deploying to Vercel

1. Import the repository in Vercel.
2. Set `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, and `IOC_API_TOKEN` in **Project Settings, then Environment Variables**.
3. Optional: set `IOC_ALLOWED_ORIGIN` to your deployment URL, and add any enrichment keys.

## Security

See [SECURITY.md](SECURITY.md) for the hardening summary and how to report a vulnerability.

## License

Add a license of your choice (for example, MIT) before you publish.
