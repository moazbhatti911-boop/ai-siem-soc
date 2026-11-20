"""Log line parser.

Understands auth/syslog-style lines such as::

    2026-11-20T10:02:11Z kali sshd[1234]: Failed password for invalid user admin from 192.168.56.10 port 22 ssh2
    2026-11-20T10:00:01Z kali sshd[1234]: Accepted password for luffy from 192.168.56.20 port 22 ssh2
    2026-11-20T10:05:40Z kali sudo: luffy : TTY=pts/0 ; PWD=/home/luffy ; USER=root ; COMMAND=/usr/bin/apt update

Lines that do not match the expected shape return ``None`` and are skipped.
"""

import re
from typing import Optional

from shared.schemas import LogEvent

# <timestamp> <host> <service>[pid]: <message>
_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+([A-Za-z0-9_.\-]+)(?:\[\d+\])?:\s+(.*)$")
_FAILED_RE = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")
_SUDO_RE = re.compile(r"^(?:sudo:\s+)?(\S+)\s*:.*COMMAND=(.*)$")


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse one log line into a LogEvent, or return None if unparseable."""
    line = line.strip()
    if not line:
        return None
    match = _LINE_RE.match(line)
    if not match:
        return None
    timestamp, host, service, message = match.groups()

    event_type = "other"
    user: Optional[str] = None
    source_ip: Optional[str] = None

    failed = _FAILED_RE.search(message)
    accepted = _ACCEPTED_RE.search(message)
    sudo = _SUDO_RE.search(message)
    if failed:
        event_type = "failed_login"
        user, source_ip = failed.groups()
    elif accepted:
        event_type = "login_success"
        user, source_ip = accepted.groups()
    elif service == "sudo" or sudo:
        event_type = "sudo"
        if sudo:
            user = sudo.group(1)

    return LogEvent(
        timestamp=timestamp,
        host=host,
        service=service,
        user=user,
        source_ip=source_ip,
        event_type=event_type,
        message=message,
        raw=line,
    )


def parse_file(path: str) -> list[LogEvent]:
    """Parse every line of a log file, skipping lines that do not parse."""
    events: list[LogEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    return events
