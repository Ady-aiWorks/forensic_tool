# forensic_tool.sh

**Advanced Linux Malware Forensics & Analysis Toolkit** — version 2.0

A single, self-contained Bash script for incident responders and forensic analysts working on (potentially compromised) Linux systems. It performs APT / rootkit / malware detection, scores suspicious artifacts, optionally quarantines them, runs deep analysis, and produces both human-readable and JSON reports bundled into a portable archive.

It is designed to be **non-destructive by default** and to **keep running through transient errors** (e.g. `/proc` race conditions, missing files), so it can be used safely for live triage.

---

## Features

The toolkit is organized into independent modules:

| Module | What it checks |
| --- | --- |
| **Process scanning** | Hidden PIDs (`/proc` vs `ps`), processes running deleted executables, anonymous RWX memory regions (shellcode), high CPU/MEM, suspicious `LD_*` env vars, anomalous parent/child (e.g. `nginx` spawning `bash`) |
| **Filesystem scanning** | Files in suspicious dirs (`/tmp`, `/dev/shm`, ...), recently modified system files, SUID/SGID audit, world-writable system files, hidden files, ELF binaries with suspicious strings, high-entropy (packed/encrypted) files |
| **Rootkit detection** | `chkrootkit` / `rkhunter` / `clamscan` (if installed), critical binary integrity checks, kernel module audit, `/proc/kallsyms` hook detection, `/etc/ld.so.preload` audit |
| **Network artifacts** | Active connections, raw sockets, `/etc/hosts` & DNS config, firewall (iptables/nft) rules, NAT/REDIRECT detection, suspicious IPs in logs, promiscuous interfaces |
| **Persistence** | Crontabs, systemd services/timers, init scripts, shell-profile backdoors, XDG autostart, PAM modules, `at` jobs, SSH `authorized_keys` |
| **Memory analysis** | `volatility3` (if installed), `/proc/kcore` & `/proc/meminfo`, per-process memory map inspection (memfd / `/dev/shm`-backed exec regions) |
| **User & account audit** | UID=0 accounts, accounts with shells, `NOPASSWD` sudo grants, empty passwords, orphaned shadow entries, login history |
| **Deep analysis** | For flagged items: hashes (MD5/SHA1/SHA256), `strings`, `file`, `ldd`, hexdump, `objdump`/`readelf`, short `strace` of matching live PID |
| **Quarantine** | Copies flagged files to a quarantine dir, records metadata + hash, sets the copy immutable (`chattr +i`), removes the execute bit on the original |
| **Reporting** | Severity-scored text report, JSON report, and a `.tar.gz` evidence bundle |

### Scoring

Each suspicious artifact accumulates a numeric **suspicion score**. The score maps to a severity label:

| Severity | Score |
| --- | --- |
| LOW | `< 3` |
| WARN | `>= 3` |
| HIGH | `>= 6` |
| CRITICAL | `>= 9` |

Quarantine only acts on **HIGH+** items; deep analysis runs on **WARN+** file items.

---

## Requirements

- **Bash 4+** (uses associative arrays)
- **Root privileges** (run with `sudo`) — required to read `/proc/*/environ`, `/proc/kcore`, shadow files, etc.
- A Linux host (tested across Ubuntu, Debian, Fedora, RHEL, Arch, etc.)

**Optional** tools that enhance results if present: `chkrootkit`, `rkhunter`, `clamscan` (ClamAV), `volatility3`/`vol3`, `objdump`, `readelf`, `strace`, `ss`, `iptables`, `nft`, `chattr`. The script gracefully skips anything that's missing.

---

## Installation

```bash
git clone <this-repo>
cd forensic_tools
chmod +x forensic_tool.sh
```

---

## Usage

```bash
sudo ./forensic_tool.sh [MODE] [OPTIONS]
```

### Modes

| Mode | Description |
| --- | --- |
| `scan` | Run all scanning modules (no quarantine, no bundled report) |
| `quarantine` | Scan silently, then quarantine HIGH+ items (needs `--quarantine`) |
| `analyze` | Scan silently, then deep-analyze flagged items |
| `report` | Scan + analyze, then generate full reports and archive bundle |
| `full` | **(default)** Everything end-to-end |

### Options

| Option | Description |
| --- | --- |
| `-v`, `--verbose` | Verbose output (show all checks) |
| `-q`, `--quiet` | Suppress informational output; show only alerts |
| `-h`, `--help` | Show built-in help |
| `--quarantine` | Enable file quarantine (required to actually move/neutralize files) |
| `--whitelist <file>` | Path to whitelist file (one path/substring per line; matched files are skipped) |
| `--output <dir>` | Output base directory for reports (default: `/var/forensics`) |
| `--quarantine-dir <dir>` | Quarantine base directory (default: `/var/quarantine`) |
| `--target <path>` | Limit filesystem / ELF / entropy / analysis scope to this path |

> Note: `--quarantine` is the flag that **enables** quarantining. The `quarantine` mode runs the quarantine step, but it will be a no-op unless `--quarantine` is also passed.

### Examples

```bash
# Full end-to-end run, verbose, with quarantine enabled
sudo ./forensic_tool.sh full -v --quarantine

# Quiet scan using a whitelist of known-good paths
sudo ./forensic_tool.sh scan -q --whitelist /etc/forensic_whitelist.txt

# Deep analysis of a single suspicious binary
sudo ./forensic_tool.sh analyze --target /tmp/suspicious_binary

# Generate reports to an external/USB location
sudo ./forensic_tool.sh report --output /mnt/usb/forensics
```

---

## Output

By default, everything is written under `/var/forensics/reports/<timestamp>/`:

| Path | Contents |
| --- | --- |
| `reports/<timestamp>/` | Top-level report directory for this run |
| `reports/<timestamp>/forensic.log` | Full run log |
| `reports/<timestamp>/report.txt` | Human-readable report (executive summary + flagged items) |
| `reports/<timestamp>/report.json` | Machine-readable report |
| `reports/<timestamp>/system_info.txt` | Host/kernel/uptime info |
| `reports/<timestamp>/evidence/` | Per-module evidence (processes, filesystem, rootkits, network, persistence, memory, users, analysis) |
| `reports/<timestamp>.tar.gz` | Archive bundle of the whole run |

Quarantined files (when enabled) go to `/var/quarantine/<timestamp>/`, alongside a `quarantine.log` recording original path, destination, score, reasons, hash, and metadata.

While running, each module prints `STARTING` / `DONE` banners and a `[STILL RUNNING]` heartbeat every 15 seconds for long-running steps.

---

## Whitelist format

A whitelist file contains one path or substring per line. Any scanned file whose path contains a whitelisted string is skipped (suppressing false positives for known-good artifacts):

```
/opt/myapp/bin/agent
/usr/local/bin/custom_tool
/home/deploy/.ssh/authorized_keys
```

---

## Safety notes

- Runs **non-destructively by default**. No files are moved or modified unless you pass `--quarantine`.
- Even with `--quarantine`, originals are **not deleted** — the script copies the file to quarantine, makes the copy immutable, and only removes the execute bit on the original.
- All transient errors are logged and the scan continues; a `forensic.log.err` is kept if any errors occurred.
- Best run from trusted/external media when investigating a suspected rootkit, since on-host binaries (`ps`, `ls`, `netstat`, ...) may themselves be tampered with — the tool flags such tampering but still relies on system tools where applicable.

---

## License

Licensed under the **MIT License** — see the [`LICENSE`](LICENSE) file for the full text. You are free to use, modify, and distribute this tool, including commercially, provided the copyright notice and license are retained.

Provided as-is, without warranty, for forensic and incident-response use. Review and test in a safe environment before running on production systems.

## Contributing

Contributions are welcome. By submitting a pull request, you agree that your contribution is licensed under the same MIT License as the project.
