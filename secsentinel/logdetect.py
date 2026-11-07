"""SSH auth-log analyzer.

Parses classic syslog-style ``sshd`` lines (e.g. ``/var/log/auth.log``) and
flags source IPs that produce a burst of failed logins inside a sliding time
window. If the same IP later logs in successfully, the finding is escalated,
because that pattern is a typical sign of a successful brute-force attack.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)


@dataclass
class Event:
    time: datetime
    kind: str  # "fail" | "invalid" | "success"
    user: str
    ip: str


@dataclass
class Finding:
    ip: str
    total_failures: int
    peak_in_window: int
    first_seen: str
    last_seen: str
    users: List[str] = field(default_factory=list)
    login_after_burst: bool = False


@dataclass
class Report:
    threshold: int
    window_seconds: int
    total_events: int
    failed_logins: int
    accepted_logins: int
    findings: List[Finding] = field(default_factory=list)


def parse_line(line: str, year: int) -> Optional[Event]:
    """Parse one syslog line into an Event, or return None if irrelevant."""
    match = SYSLOG_RE.match(line.strip())
    if not match:
        return None
    stamp = " ".join(match["ts"].split())
    try:
        when = datetime.strptime(f"{year} {stamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    msg = match["msg"]
    for kind, regex in (
        ("fail", FAILED_RE),
        ("invalid", INVALID_RE),
        ("success", ACCEPTED_RE),
    ):
        found = regex.search(msg)
        if found:
            return Event(when, kind, found["user"], found["ip"])
    return None


def parse_lines(lines: Iterable[str], year: Optional[int] = None) -> List[Event]:
    year = year or datetime.now().year
    events = []
    for line in lines:
        event = parse_line(line, year)
        if event:
            events.append(event)
    return events


def analyze(events: List[Event], threshold: int = 5, window: int = 60) -> Report:
    """Find IPs with >= ``threshold`` failed logins within ``window`` seconds."""
    if threshold < 1 or window < 1:
        raise ValueError("threshold and window must be positive")

    fails: Dict[str, List[datetime]] = defaultdict(list)
    successes: Dict[str, List[datetime]] = defaultdict(list)
    users: Dict[str, set] = defaultdict(set)

    for event in events:
        if event.kind == "success":
            successes[event.ip].append(event.time)
            continue
        users[event.ip].add(event.user)
        if event.kind == "fail":
            fails[event.ip].append(event.time)

    span = timedelta(seconds=window)
    findings: List[Finding] = []

    for ip, times in fails.items():
        times.sort()
        start = 0
        peak = 0
        burst_start: Optional[datetime] = None
        for end, current in enumerate(times):
            while current - times[start] > span:
                start += 1
            count = end - start + 1
            peak = max(peak, count)
            if count >= threshold and burst_start is None:
                burst_start = times[start]
        if burst_start is None:
            continue
        later_login = any(t >= burst_start for t in successes.get(ip, []))
        findings.append(
            Finding(
                ip=ip,
                total_failures=len(times),
                peak_in_window=peak,
                first_seen=times[0].isoformat(sep=" "),
                last_seen=times[-1].isoformat(sep=" "),
                users=sorted(users[ip]),
                login_after_burst=later_login,
            )
        )

    findings.sort(key=lambda f: (not f.login_after_burst, -f.total_failures, f.ip))
    return Report(
        threshold=threshold,
        window_seconds=window,
        total_events=len(events),
        failed_logins=sum(len(v) for v in fails.values()),
        accepted_logins=sum(len(v) for v in successes.values()),
        findings=findings,
    )


def format_report(report: Report) -> str:
    lines = [
        "SecSentinel - SSH log report",
        f"Events parsed : {report.total_events} "
        f"(failed: {report.failed_logins}, accepted: {report.accepted_logins})",
        f"Rule          : >= {report.threshold} failures within "
        f"{report.window_seconds}s",
        "",
    ]
    if not report.findings:
        lines.append("No brute-force activity detected.")
        return "\n".join(lines)
    for f in report.findings:
        tag = "[CRITICAL]" if f.login_after_burst else "[WARNING] "
        lines.append(
            f"{tag} {f.ip}  peak={f.peak_in_window}  total={f.total_failures}  "
            f"users={','.join(f.users)}"
        )
        lines.append(f"           first={f.first_seen}  last={f.last_seen}")
        if f.login_after_burst:
            lines.append(
                "           A successful login from this IP followed the burst - "
                "investigate the account."
            )
    return "\n".join(lines)
