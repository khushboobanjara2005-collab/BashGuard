```markdown
# BashGuard 🛡️
> A Lightweight System Security Monitoring Tool for Linux

![Shell Script](https://img.shields.io/badge/Shell-Bash-green)
![Version](https://img.shields.io/badge/Version-1.4-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux-orange)

---

## What is BashGuard?

BashGuard is a terminal-based security monitoring tool written purely
in Bash. It scans your system across three attack surfaces and produces
a color-coded threat report — no installation, no root access, no
external dependencies.

---

## Features

| Module              | What it does                                                 |
|---------------------|--------------------------------------------------------------|
| 🔴 Process Monitor | Detects CPU-heavy processes and classifies them by severity   |
| 🌐 Port Scanner    | Flags open ports not present in the approved whitelist        |
| 🔒 File Integrity  | Uses SHA-256 hashing to catch modified, deleted, or new files |
| 📋 Alert Logger    | Timestamps and logs every HIGH/MEDIUM alert automatically     |

---

## Requirements

- Linux (Ubuntu 20.04+ recommended)
- Bash 5.0+
- Standard utilities: `ss` `sha256sum` `ps` `awk`

> All utilities are pre-installed on most Linux distributions.
> BashGuard will verify this automatically on launch.

---

## Getting Started

```bash
# Step 1 — Clone the repository
git clone https://github.com/khushboobanajara2005-collab/BashGuard
cd bashguard

# Step 2 — Make the script executable
chmod +x bashguard.sh

# Step 3 — First run (creates test files and baseline hashes)
./bashguard.sh

# Step 4 — Second run onwards (active detection begins)
./bashguard.sh
```

---

## Testing the Tool

Simulate real security events to see BashGuard in action:

```bash
# Simulate file modification
echo "hacked" >> test_files/config.cfg

# Simulate unauthorized new file
echo "ghost" > test_files/newfile.txt

# Simulate file deletion
rm test_files/credentials.txt

# Run BashGuard — all three will be caught
./bashguard.sh
```

---

## Resetting the Baseline

If you make legitimate changes and want to re-establish a clean state:

```bash
rm baseline_hashes.txt
./bashguard.sh    # Fresh baseline is created automatically
```

---

## Output Example

```
  [HIGH]    stress  (User: user1 | CPU: 95.4%)
  [MEDIUM]  python3 (User: user1 | CPU: 62.1%)
  [ALERT]   Port 9090 is OPEN and NOT in whitelist
  [ALERT]   config.cfg — MODIFIED (hash mismatch)
  [WARN]    newfile.txt — NEW FILE (not in baseline)
```

---

## Log File

All alerts are saved to `bashguard.log` with timestamps:

```
[2026-04-13 10:14:22] HIGH - Process 'stress' using 95.4% CPU
[2026-04-13 10:14:23] HIGH - Unexpected open port: 9090
[2026-04-13 10:14:24] HIGH - File modified: test_files/config.cfg
```

> Log is automatically rotated to the last 100 entries on each run.

---

## Project Info

- **Course:** Operating Systems
- **Author:** [Khushboo Banjara] — [Roll Number- 243501088]
- **Institution:** [Lachoo Memorial College of Science and Technology]
- **Version:** 1.4 — Final
```

---

