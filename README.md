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

**132 findings:**

- **109** auth
- **9** PowerShell
- **14** IOC

---

## How to use your own logs

- Four variables at the top of `run.ps1` can be pointed towards your own files.
- Reads standard sshd auth logs.
- Reads Apache/nginx access logs.
- `ioc.txt` format: one IP or URL path per line.
- Thresholds can be tuned across scripts.

---

## License
