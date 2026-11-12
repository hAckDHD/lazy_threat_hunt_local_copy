# Security Policy

## Reporting a vulnerability

Do not open a public issue for a security problem. Use GitHub's **Report a vulnerability** button (private security advisory) on this repository instead. Include the steps to reproduce the problem and its impact.

## Hardening summary

This repository contains no credentials. All secrets come from environment variables (see `.env.example`), and `.env` is git-ignored.

| Area | Control |
|---|---|
| Authentication | Optional bearer token (`IOC_API_TOKEN`), compared in constant time. |
| Data isolation | Each browser gets a random 256-bit session ID in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` in production). Every database query is scoped to that session ID. |
| CSRF | Cross-origin `POST`/`DELETE` requests are rejected by an `Origin` check, in addition to the `SameSite=Strict` cookie. |
| SSRF | URL ingestion allows only `http`/`https` and rejects embedded credentials. It resolves DNS and blocks private, loopback, link-local, CGNAT, multicast, reserved, and cloud-metadata ranges (IPv4 and IPv6, including mapped and NAT64 forms). The check runs again on **every redirect hop**, and each request connects to the exact address that passed the check. Response size and time are capped. Intel lookups call only fixed third-party hosts, with strictly validated IOC values. |
| Injection | All SQL is parameterized. Every value is checked against its IOC type before it goes into a hunt query or detection rule. Values with control characters are dropped. Each value is escaped for its target language (YAML, KQL, SPL, Lucene, and others). Time ranges must match a strict ISO format. |
| XSS | All dynamic UI content is HTML-escaped. The Content Security Policy blocks framing, plugins, `<base>` hijacking, and cross-origin script or connect targets. CSV export neutralises spreadsheet formulas. |
| Abuse / DoS | Per-IP rate limits apply to every endpoint that calls an external service. Request bodies are capped at 6 MB, uploads at 5 MB, and pasted text at 2 MB. Custom IOC lists are capped at 5,000 entries. |
| API-key protection | Server-side enrichment keys are used only when the instance is private (token set, or loopback only), unless the operator opts in with `IOC_SHARE_SERVER_KEYS=1`. |
| Uploads | Uploaded files are parsed in memory. Nothing is written to disk. PDF text is extracted with a current, pure-JavaScript parser that never renders pages or runs scripts. |
| Static files | Served from a fixed allow-list. No request path ever reaches the file system. |
| Local data | The SQLite file lives in a per-user directory created with owner-only permissions. API responses are sent with `Cache-Control: no-store`. |
| Dependencies | Three runtime dependencies, no native add-ons, lockfile committed, `bun audit` clean and checked in CI. |
| Headers | `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and HSTS in production. |
| Error handling | Internal error details are logged on the server and never returned to clients. |

## Deployment checklist

- [ ] Set `IOC_API_TOKEN` for any instance that other people can reach.
- [ ] Keep `IOC_HOST=127.0.0.1` unless you need network access.
- [ ] Set `IOC_ALLOWED_ORIGIN` only if a separate front end must call the API.
- [ ] Keep API keys in your host's secret store, never in the repository.
- [ ] Rotate any key that was ever committed or shared.

## Operating guidance

- Run one shared rate limiter or firewall in front of multi-instance and serverless deployments. The built-in limiter works per instance.
- For deployments that ingest URLs from untrusted users, also restrict outbound traffic at the network layer (egress proxy or firewall rules).
- Keep Bun and the dependencies current: run `bun update` and `bun audit` regularly. CI runs the audit on every push.
