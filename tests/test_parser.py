"""Tests for the log parser."""

from ingestor.parser import parse_file, parse_line


def test_failed_login_line():
    event = parse_line(
        "2026-11-20T10:02:11Z kali sshd[1236]: Failed password for invalid user"
        " admin from 192.168.56.10 port 22 ssh2"
    )
    assert event is not None
    assert event.event_type == "failed_login"
    assert event.user == "admin"
    assert event.source_ip == "192.168.56.10"
    assert event.host == "kali"
    assert event.service == "sshd"


def test_accepted_login_line():
    event = parse_line(
        "2026-11-20T10:00:01Z kali sshd[1234]: Accepted password for luffy"
        " from 192.168.56.20 port 22 ssh2"
    )
    assert event is not None
    assert event.event_type == "login_success"
    assert event.user == "luffy"
    assert event.source_ip == "192.168.56.20"


def test_root_login_line():
    event = parse_line(
        "2026-11-20T10:03:05Z kali sshd[1241]: Accepted password for root"
        " from 192.168.56.10 port 22 ssh2"
    )
    assert event is not None
    assert event.event_type == "login_success"
    assert event.user == "root"


def test_sudo_line():
    event = parse_line(
        "2026-11-20T10:05:40Z kali sudo: luffy : TTY=pts/0 ; PWD=/home/luffy ;"
        " USER=root ; COMMAND=/usr/bin/apt update"
    )
    assert event is not None
    assert event.event_type == "sudo"
    assert event.user == "luffy"


def test_unparseable_line_returns_none():
    assert parse_line("") is None
    assert parse_line("not a log line at all") is None


def test_sample_log_parses_all_lines(tmp_path):
    events = parse_file("samples/sample_auth.log")
    assert len(events) == 12
    types = [e.event_type for e in events]
    assert types.count("failed_login") == 5
    assert types.count("login_success") == 4
    assert types.count("sudo") == 1
    assert types.count("other") == 2
