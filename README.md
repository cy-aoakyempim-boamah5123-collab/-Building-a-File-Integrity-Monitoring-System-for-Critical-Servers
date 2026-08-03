# File Integrity Monitoring (FIM) System for Critical Servers

A blue-team defensive security tool that detects unauthorized changes to critical Linux system files — built from first principles rather than deployed from an existing tool like AIDE or Tripwire — to demonstrate a practical understanding of detection logic, tamper-resistance, and operational deployment.

> **Course project:** CY376 – Network Monitoring, Security and Auditing, University of Mines and Technology
> **Author:** Akyempim-Boamah Abena Owusua (FCM.41.018.035.23)
> **Team:** Blue Team

---

## Overview

Attackers who gain a foothold on a server frequently need to modify a small set of high-value files — adding a backdoor account, installing a malicious cron job, replacing a system binary, or weakening SSH configuration. `fim.py` records a cryptographic baseline of these files, protects that baseline against silent tampering, and detects changes either on a schedule or in real time.

This maps directly to established frameworks:
- **MITRE ATT&CK** — T1565 (Data Manipulation), T1543 (Create/Modify System Process), T1036 (Masquerading)
- **CIS Distribution Independent Linux Benchmark** — 1.3.2, "Ensure filesystem integrity is regularly checked"
- **NIST SP 800-53** — SI-7 and SI-7(1), integrity verification at startup, on events, or on a defined schedule

## Features

- **Cryptographic baselining** — SHA-256 content hash plus metadata (size, mode, UID/GID, mtime, symlink target) for every monitored file
- **Tamper-evident baseline** — a separate hash of the baseline file itself is verified before every check; a mismatch halts the check and raises an alert instead of trusting a possibly-rewritten baseline
- **Two detection modes**
  - Scheduled polling via a `systemd` service/timer pair (default every 5 minutes)
  - Real-time, event-driven detection via the `watchdog` library (inotify)
- **Change classification** — added, deleted, modified (hash changed), or permission/ownership changed
- **Multi-channel alerting** — local log file, syslog (for SIEM forwarding), optional webhook and/or email, with notification failures never blocking the core integrity check
- **Config-driven** — monitored paths, exclusions, and file locations are defined in a single JSON config, no code changes required

## Architecture

```
/opt/fim/         fim.py, fim_config.json         (chmod 700)
/var/lib/fim/      baseline.json, baseline.json.sha256   (chmod 700)
/var/log/fim/      fim.log                        (chmod 750)
```

The tool exposes four modes:

| Mode       | Function       | Purpose                                                            |
|------------|----------------|---------------------------------------------------------------------|
| `baseline` | `do_baseline()` | Snapshot hashes/metadata of all monitored files, store baseline + self-hash |
| `verify`   | `do_verify()`   | Re-hash the baseline and compare to the stored self-hash            |
| `check`    | `do_check()`    | Re-walk monitored paths and classify changes vs. the baseline       |
| `watch`    | `do_watch()`    | Subscribe to filesystem events (inotify) for real-time detection    |

## Requirements

- Linux (developed/tested on Ubuntu)
- Python 3
- [`watchdog`](https://pypi.org/project/watchdog/) (only required for real-time `watch` mode)
- Root privileges (to read protected files such as `/etc/shadow` and to install under `/opt`, `/var/lib`, `/var/log`)

```bash
pip install watchdog
```

## Configuration

Monitored paths and alert settings live in `fim_config.json`:

```json
{
  "monitor_paths": [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/hosts"
  ],
  "exclude": ["/proc", "/sys", "/tmp", ".log"],
  "baseline_file": "/var/lib/fim/baseline.json",
  "baseline_hash_file": "/var/lib/fim/baseline.json.sha256",
  "log_file": "/var/log/fim/fim.log"
}
```

## Usage

**1. Create the initial baseline** (do this on a known-clean system — baselining an already-compromised host will treat any existing backdoor as normal):

```bash
sudo python3 /opt/fim/fim.py baseline -c /opt/fim/fim_config.json
```

**2. Run a manual check:**

```bash
sudo python3 /opt/fim/fim.py check -c /opt/fim/fim_config.json
```

**3. Run real-time monitoring:**

```bash
sudo python3 /opt/fim/fim.py watch -c /opt/fim/fim_config.json
```

**4. Automate scheduled checks with systemd:**

`/etc/systemd/system/fim-check.service`
```ini
[Unit]
Description=File Integrity Monitor - integrity check
Wants=fim-check.timer

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/fim/fim.py check -c /opt/fim/fim_config.json
User=root

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/fim-check.timer`
```ini
[Unit]
Description=Run File Integrity Monitor check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fim-check.timer
sudo systemctl list-timers fim-check.timer
```

## Testing Summary

The system was validated in an isolated VM across five scenarios:

| Test scenario                  | Expected outcome                              | Result        |
|--------------------------------|------------------------------------------------|---------------|
| Baseline creation              | 4 files recorded, self-hash stored              | ✅ PASS |
| Clean-state check              | No changes reported                             | ✅ PASS |
| Simulated attack (`useradd`)    | `/etc/passwd` and `/etc/shadow` flagged         | ✅ PASS |
| Revert (`userdel`)             | No changes reported (documented limitation)     | ✅ PASS (expected) |
| Baseline tampering             | Tampering detected, check halted                | ✅ PASS |
| Real-time watch mode           | Change on `/etc/hosts` flagged instantly        | ✅ PASS |
| Automated timer run            | Check fires unattended on schedule              | ✅ PASS |

## Known Limitation

State-based, snapshot-comparison FIM cannot retroactively reveal changes that are reverted between checks. For example, if an attacker creates and removes a backdoor account within a single polling interval, no trace remains in the next scan. This is a known property of this class of tool, not an implementation defect — it's mitigated by shortening the check interval for high-value files and/or relying on real-time (`watch`) mode for the highest-risk paths.

## Recommendations for Production Hardening

1. **Store the baseline off-host** — the single highest-value change, so an attacker with full host access can't delete/edit both the baseline and its hash together.
2. **Replace the self-hash with a cryptographic signature** (GPG/RSA) verified with a key that never touches the monitored host.
3. **Shorten the detection window** for high-value paths, or extend real-time `watch` coverage beyond the current four files.
4. **Forward alerts to a centralized SIEM** (e.g., Wazuh, ELK, Splunk) for cross-host correlation and off-host alert retention.
5. **Add a maintenance-window mechanism** to suppress expected changes (patching, log rotation) and avoid alert fatigue.
6. **Benchmark against an established tool** (AIDE/Tripwire) run in parallel to validate there are no detection blind spots.

## References

1. MITRE ATT&CK, *Data Manipulation (T1565)* — https://attack.mitre.org/techniques/T1565/
2. MITRE ATT&CK, *Create or Modify System Process (T1543)* — https://attack.mitre.org/techniques/T1543/
3. MITRE ATT&CK, *Masquerading (T1036)* — https://attack.mitre.org/techniques/T1036/
4. Center for Internet Security, *CIS Distribution Independent Linux Benchmark* — https://www.cisecurity.org/cis-benchmarks
5. NIST SP 800-53 Rev. 5, Control SI-7 / SI-7(1) — Software, Firmware, and Information Integrity
6. AIDE Project — https://aide.github.io/
7. Wazuh Documentation, *File Integrity Monitoring* — https://documentation.wazuh.com/
8. Python `watchdog` — https://pypi.org/project/watchdog/

## License

This project was developed for academic purposes as part of CY376: Network Monitoring, Security and Auditing.
