# Log Analysis Tool (Windows build)

Reads SSH, web and PowerShell logs, and reports suspicious activity in a generated report.

---

## Requirements

Windows PowerShell.

---

## How to run

- `.\run.ps1` runs all files.
- Logs are read from `samples\`.
- Writes findings to `investigation_report.txt`.

---

## What it checks

**`detect_auth.ps1`**

- Repeated failed SSH logins per IP.
- Login attempts to nonexistent accounts.
- IPs that failed, but later succeeded.

**`detect_ioc.ps1`**

- Access logs are cross-checked against a list of known malicious IPs and URLs.

**`detect_powershell.ps1`**

- Encoded commands.
- Execution policy bypass.
- `-NoProfile`.
- Plain HTTP downloads.
- Archive creation.
- Uploads following an archive.
- Reconnaissance commands.

**`generate_report.ps1`**

- Writes findings across checks with a summary count.

---

## What it found across the samples

**53 findings:**

- **20** auth
- **9** PowerShell
- **24** IOC

Two profiles stand out: one IP tried sysadmin accounts (nagios, oracle, postgres), another tried device defaults (cisco, ubnt, pi).

---

## How to use your own logs

- Four variables at the top of `run.ps1` can be pointed towards your own files.
- Reads standard sshd auth logs.
- Reads Apache/nginx access logs.
- `ioc.txt` format: one IP or URL path per line.
- Thresholds can be tuned across scripts.

---

## Sample data

- `auth.log` - OpenSSH dataset from Loghub, `github.com/logpai/loghub`. He et al., *Loghub: A Large Collection of System Log Datasets*, ISSRE 2023.
- `access.log` - real NASA traffic (July 1995, Internet Traffic Archive) plus 13 synthetic scanner requests. Those use RFC 5737 addresses, reserved for documentation and never assigned.
- `powershell_log.txt` - constructed for this project.

---

## License

MIT. See `LICENSE`.
