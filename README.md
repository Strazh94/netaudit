# netaudit

Lightweight port scanner and security audit in pure Python (standard library only).

Scans a given subnet, detects open ports (**80, 443, 22, 5432** by default), grabs service banners and matches them against a local database of known vulnerabilities. Optionally checks whether services accept default passwords — with a hard attempt limit.

> [!WARNING]
> The tool is intended **only for auditing networks you have explicit permission for**.
> Unauthorized scanning of other people's networks is illegal.

## Features

- **Subnet connect-scan** — CIDR (`192.168.1.0/24`), a single IP or a hostname; thread pool, timeouts, subnet size limit. No administrator privileges required (no raw/SYN sockets).
- **Service detection from banners**: SSH, HTTP(S), PostgreSQL, plus banner-based auto-detect for non-standard ports.
- **Vulnerability database matching** (`vulnbase.json`): regular expressions + version comparison → known CVEs. Matching only, no exploitation.
- **TLS checks**: expired/untrusted certificates, outdated TLS 1.0/1.1.
- **Limited default password check** (`--check-creds`, at most 5 attempts per target):
  - HTTP Basic Auth — on pure stdlib;
  - PostgreSQL — own protocol implementation over sockets (cleartext / MD5 / Trust; SCRAM-SHA-256 is honestly reported as unsupported);
  - SSH — only when `paramiko` is installed, otherwise an honest `[skip]`.
- **Report**: console table + machine-readable `report.json`.

## Installation and usage

Python 3.10+ is required. No dependencies are needed for a basic scan.

```bash
git clone git@github.com:Strazh94/netaudit.git
cd netaudit

# basic subnet scan
python netaudit.py 192.168.1.0/24

# custom ports, timeout and report
python netaudit.py 192.168.1.10 --ports 22,80,443,5432 --timeout 2 --out audit.json

# + limited default password check (with confirmation)
python netaudit.py 192.168.1.10 --check-creds
python netaudit.py 192.168.1.10 --check-creds --yes   # for cron/CI
```

Optionally, only for SSH password checks:

```bash
pip install paramiko
```

## Options

| Option | Default | Description |
|---|---|---|
| `network` | — | CIDR, a single IP or a hostname |
| `--ports` | `22,80,443,5432` | list of ports and ranges: `22,80,8000-8010` |
| `--timeout` | `1.0` | connection timeout, seconds |
| `--workers` | `100` | number of threads |
| `--max-hosts` | `4096` | maximum hosts in the subnet (protection against accidental scans) |
| `--out` | `report.json` | path for the JSON report |
| `--vulnbase` | `vulnbase.json` | path to the vulnerability database |
| `--check-creds` | off | check default passwords (≤5 attempts per target) |
| `--yes` | off | do not ask for confirmation for `--check-creds` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | no problems found |
| `1` | problems found |
| `2` | startup/arguments error |

Handy for cron and CI: `python netaudit.py 10.0.0.0/24 || notify.sh`.

## Vulnerability database format

`vulnbase.json` is a plain, human-editable JSON. Example rule:

```json
{
  "service": "http",
  "pattern": "Apache/([0-9]+(?:\\.[0-9]+)*)",
  "vulnerable_from": "2.4.49",
  "vulnerable_below": "2.4.51",
  "severity": "critical",
  "title": "Apache HTTP Server: path traversal / RCE",
  "cve": ["CVE-2021-41773", "CVE-2021-42013"],
  "advisory": "Urgently update Apache httpd to 2.4.51+."
}
```

- `pattern` — regular expression, default capture group `1` is the version;
- `vulnerable_from` / `vulnerable_below` — vulnerable range (bounds: `from` inclusive, `below` exclusive);
- `service`: `ssh`, `http` (also used for HTTPS), `postgres`, `*`.

Rules contain **only the problem description and CVEs** — no exploitation code.

## Sample output

```
HOST             PORT   STATE  SERVICE    VERSION                  FINDINGS
---------------------------------------------------------------------------------
192.168.1.10     22     open   ssh        7.4                      MEDIUMx2
192.168.1.10     80     open   http       Apache 2.4.49            CRITICALx1, HIGHx1

=== Problems found ===
[CRITICAL] 192.168.1.10:80  Apache HTTP Server: path traversal / RCE CVE-2021-41773, CVE-2021-42013
           -> version 2.4.49: Urgently update Apache httpd to 2.4.51+.
[CRITICAL] 192.168.1.10:80  Default password works!
           -> http: admin:admin (successful login on /)
```

## Security limitations

- connect-scan only — no administrator privileges required;
- host limit, thread limit, timeouts on all operations;
- `--check-creds`: at most 5 combinations per target, explicit confirmation (or `--yes`), every attempt is recorded in the report;
- the permission disclaimer is printed on every run.

## License

MIT — see [LICENSE](LICENSE).
