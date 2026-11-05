"""Log satırlarını olaylara (Event) çeviren ayrıştırıcılar.

Desteklenen biçimler:
- nginx / Apache "combined" erişim logu
- OpenSSH (sshd) auth.log satırları: klasik syslog ("Nov  5 10:00:01 ...")
  ya da ISO zaman damgalı ("2026-11-05T10:00:01+03:00 ...")
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus

MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}


@dataclass
class Event:
    ts: datetime
    source: str            # "web" | "ssh"
    ip: str
    kind: str              # web: "request"; ssh: "failed" | "invalid_user" | "accepted"
    line_no: int
    raw: str
    user: str | None = None
    invalid: bool = False  # ssh: var olmayan kullanıcı adı
    method: str = ""
    target: str = ""       # web: URL-çözülmüş yol + sorgu
    status: int = 0
    ua: str = ""


# ---------------------------------------------------------------- web

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) \S+(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')


def decode_target(s: str) -> str:
    """URL kodlamasını çöz; çift kodlamaya karşı en fazla 3 tur."""
    for _ in range(3):
        d = unquote_plus(s)
        if d == s:
            break
        s = d
    return s


def parse_web(line: str, line_no: int) -> Event | None:
    m = _COMBINED.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    parts = m["req"].split(" ")
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        # kodlanmamış boşluklu hedef: yöntem ile HTTP/x arasındaki her şey
        method, path = parts[0], " ".join(parts[1:-1])
    elif len(parts) == 2:
        method, path = parts
    else:
        method, path = "", m["req"]
    return Event(ts=ts, source="web", ip=m["ip"], kind="request", line_no=line_no,
                 raw=line, method=method, target=decode_target(path),
                 status=int(m["status"]), ua=m["ua"] or "")


# ---------------------------------------------------------------- ssh

_SYSLOG_PREFIX = re.compile(
    r'^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d\d:\d\d:\d\d) \S+ sshd\[\d+\]: (?P<msg>.*)$')
_ISO_PREFIX = re.compile(
    r'^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) \S+ sshd\[\d+\]: (?P<msg>.*)$')

_REPEATED = re.compile(r'^message repeated (?P<n>\d+) times: \[ ?(?P<msg>.*?) ?\]$')
MAX_REPEAT = 1000
# Kullanıcı adı saldırganın kontrolündedir ve boşluk içerebilir
# ("x from 8.8.8.8 port 1"). Bu yüzden IP satırın SONUNDAN alınır.
_FAILED = re.compile(
    r'^Failed \S+ for (?P<inv>invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+(?: ssh\d)?$')
_INVALID = re.compile(r'^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port \d+)?$')
_ACCEPTED = re.compile(
    r'^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh\d(?:: .*)?$')


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _ssh_time(line: str, year: int) -> tuple[datetime, str] | None:
    m = _ISO_PREFIX.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        except ValueError:
            return None
        return (ts if ts.tzinfo else ts.astimezone()), m["msg"]
    m = _SYSLOG_PREFIX.match(line)
    if m and m["mon"] in MONTHS:
        h, mi, s = map(int, m["time"].split(":"))
        try:
            ts = datetime(year, MONTHS[m["mon"]], int(m["day"]), h, mi, s)
        except ValueError:
            return None
        # syslog satırında saat dilimi yok: yerel saat kabul edilir
        return ts.astimezone(), m["msg"]
    return None


def parse_ssh(line: str, line_no: int, year: int) -> list[Event] | None:
    """sshd satırı değilse None; ilgisiz sshd satırıysa boş liste döner."""
    got = _ssh_time(line, year)
    if got is None:
        return None
    ts, msg = got
    repeat = 1
    r = _REPEATED.match(msg)
    if r:
        repeat, msg = min(int(r["n"]), MAX_REPEAT), r["msg"]

    def ev(kind: str, m: re.Match, invalid: bool = False) -> list[Event]:
        if not _valid_ip(m["ip"]):
            return []
        e = dict(ts=ts, source="ssh", ip=m["ip"], kind=kind, line_no=line_no,
                 raw=line, user=m["user"], invalid=invalid)
        return [Event(**e) for _ in range(repeat)]

    if m := _FAILED.match(msg):
        return ev("failed", m, invalid=bool(m["inv"]))
    if m := _INVALID.match(msg):
        return ev("invalid_user", m, invalid=True)
    if m := _ACCEPTED.match(msg):
        return ev("accepted", m)
    return []


# ---------------------------------------------------------------- dosya

@dataclass
class ParseStats:
    lines: int = 0
    events: int = 0
    ignored: int = 0   # tanınan ama ilgisiz (ör. sshd "Connection closed")
    unknown: int = 0   # hiçbir biçime uymayan satır


def parse_lines(lines, year: int, stats: ParseStats | None = None) -> list[Event]:
    stats = stats if stats is not None else ParseStats()
    events: list[Event] = []
    for no, line in enumerate(lines, start=1):
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        stats.lines += 1
        if (e := parse_web(line, no)) is not None:
            events.append(e)
            continue
        got = parse_ssh(line, no, year)
        if got is None:
            stats.unknown += 1
        elif not got:
            stats.ignored += 1
        else:
            events.extend(got)
    stats.events += len(events)
    return events


def parse_file(path, year: int, stats: ParseStats | None = None) -> list[Event]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return parse_lines(f, year, stats)
