# SecSentinel

[![CI](https://github.com/khalil135711/secsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/khalil135711/secsentinel/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

A small, **dependency-free defensive security toolkit** (blue team) written in pure Python.
It bundles three practical tools behind a single command line interface:

| Tool | Command | What it does |
|------|---------|--------------|
| SSH log analyzer | `secsentinel logs` | Detects brute-force bursts in `auth.log` and escalates when the attacker later logs in successfully |
| File integrity monitor | `secsentinel integrity` | Builds a SHA-256 baseline of a directory and reports modified, added and removed files |
| Password auditor | `secsentinel passwords` | Offline strength check: common passwords, leetspeak variants, sequences, keyboard patterns |

Everything runs locally. No network access, no third-party packages, no changes to the systems it inspects.

## Quick start

```bash
git clone https://github.com/khalil135711/secsentinel.git
cd secsentinel

# run directly, no installation needed
python3 -m secsentinel --help

# or install the `secsentinel` command
pip install .
```

Requires Python 3.9 or newer.

## Usage

### 1. SSH brute-force detection

```bash
python3 -m secsentinel logs samples/auth.log --year 2026
```

```text
SecSentinel - SSH log report
Events parsed : 15 (failed: 11, accepted: 3)
Rule          : >= 5 failures within 60s

[CRITICAL] 203.0.113.45  peak=7  total=7  users=admin,oracle,root,test,ubuntu
           first=2026-11-07 04:02:10  last=2026-11-07 04:02:23
           A successful login from this IP followed the burst - investigate the account.
```

Options: `--threshold N` (default 5), `--window SECONDS` (default 60), `--year YYYY`
(syslog timestamps carry no year), `--json`.

**How it works:** failed logins are grouped per source IP and checked with a sliding time window.
An IP that reaches the threshold becomes a finding. If a *successful* login from the same IP
occurs after the burst began, the finding is marked `CRITICAL`, which is the classic sign of a
successful brute-force attack. Slow attacks spread over hours are intentionally not flagged;
pair this tool with a tool like fail2ban for that.

### 2. File integrity monitoring

```bash
# 1) record a trusted state
python3 -m secsentinel integrity init /etc/myapp --baseline baseline.json --exclude "*.log"

# 2) later: verify
python3 -m secsentinel integrity check /etc/myapp --baseline baseline.json
```

```text
SecSentinel - integrity report
[MODIFIED] config.yaml
[ADDED   ] backdoor.sh
[REMOVED ] audit.conf
```

Symlinks are never followed. The baseline stores the exclusion patterns, so `check` applies the
same rules automatically. Store the baseline somewhere an attacker cannot write to (read-only
media, another host), otherwise changes can be hidden.

### 3. Password auditing

```bash
python3 -m secsentinel passwords --file samples/passwords.txt   # one password per line
python3 -m secsentinel passwords --prompt                        # hidden interactive input
```

Passwords are masked in all output, only the line number and a star mask are shown.
`--min-rating` (default `good`) controls what counts as a finding.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | nothing found |
| 1 | findings reported (brute force, changed files, weak passwords) |
| 2 | usage or I/O error |

This makes SecSentinel easy to use in cron jobs and CI pipelines, and every command supports
`--json` for further processing.

## Project structure

```text
secsentinel/
├── secsentinel/
│   ├── cli.py          # argument parsing and output
│   ├── logdetect.py    # SSH log parsing + sliding-window detection
│   ├── integrity.py    # SHA-256 baseline and comparison
│   └── passaudit.py    # password strength heuristics
├── tests/              # unittest suite (29 tests)
├── samples/            # example auth.log and password list
├── .github/workflows/  # CI for Python 3.9 - 3.13
├── SECURITY.md
├── LICENSE
└── pyproject.toml
```

## Development

```bash
python3 -m unittest discover -s tests -t . -v
```

## Limitations

- The log analyzer understands classic syslog `sshd` lines only (not `journalctl -o json`).
- The password estimate is a heuristic based on character pools, capped at 100 bits. It cannot
  recognise arbitrary dictionary words, so long word-based passphrases may be rated too generously.
  It is a quick policy check, not a replacement for a breach-database lookup.
- The integrity monitor detects content changes (hash), not permission or ownership changes.

## Roadmap

- [ ] `journalctl` JSON input and Apache/nginx access log rules
- [ ] Optional Have I Been Pwned k-anonymity check for passwords
- [ ] Permission and ownership tracking in the integrity monitor
- [ ] Output formats: CSV and SARIF

## Responsible use

SecSentinel is for monitoring systems and accounts **you own or are authorised to assess**.

## License

MIT, see [LICENSE](LICENSE).
