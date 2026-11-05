"""TOML kural dosyasını yükler ve olaylara uygular.

Kural tipleri:
- pattern     : tek satırda regex eşleşmesi (ör. SQLi yükü, tarayıcı User-Agent)
- threshold   : aynı IP'den `window` saniye içinde en az `count` olay
- distinct    : aynı IP'den `window` saniye içinde en az `count` farklı değer (ör. kullanıcı adı)
- followed_by : `window` içinde en az `count` "önce" olayından sonra bir "sonra" olayı
"""

from __future__ import annotations

import re
import tomllib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .parsers import Event

DEFAULT_RULES = Path(__file__).with_name("default_rules.toml")
SEVERITIES = ["low", "medium", "high", "critical"]
TYPES = {"pattern", "threshold", "distinct", "followed_by"}
FIELDS = {"web": {"target", "ua", "method"}, "ssh": {"user"}}
MAX_FIELD = 4096   # regex'e verilen alan bu uzunlukta kırpılır (aşırı uzun satırlara karşı)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    ip: str
    first: datetime
    last: datetime
    count: int = 1
    detail: str = ""
    examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"rule": self.rule_id, "title": self.title, "severity": self.severity,
                "ip": self.ip, "first": self.first.isoformat(), "last": self.last.isoformat(),
                "count": self.count, "detail": self.detail, "examples": self.examples}


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    source: str
    kinds: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    invalid_only: bool = False
    attr: str = ""
    patterns: list[re.Pattern] = field(default_factory=list)
    count: int = 1
    window: int = 60
    then_kinds: list[str] = field(default_factory=list)

    def selects(self, e: Event) -> bool:
        if e.source != self.source:
            return False
        if self.kinds and e.kind not in self.kinds:
            return False
        if self.status and e.status not in self.status:
            return False
        if self.invalid_only and not e.invalid:
            return False
        return True


def load_rules(path: Path | str = DEFAULT_RULES) -> list[Rule]:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    rules = []
    for r in data.get("rule", []):
        rid = r.get("id", "?")
        if r.get("type") not in TYPES:
            raise ValueError(f"{rid}: bilinmeyen kural tipi {r.get('type')!r}")
        if r.get("severity") not in SEVERITIES:
            raise ValueError(f"{rid}: geçersiz önem {r.get('severity')!r}")
        if r.get("source") not in FIELDS:
            raise ValueError(f"{rid}: geçersiz kaynak {r.get('source')!r}")
        if r["type"] in ("pattern", "distinct") and r.get("field") not in FIELDS[r["source"]]:
            raise ValueError(f"{rid}: {r['source']} için geçersiz alan {r.get('field')!r}")
        try:
            patterns = [re.compile(p, re.IGNORECASE) for p in r.get("patterns", [])]
            rules.append(Rule(
                id=rid, title=r["title"], severity=r["severity"], type=r["type"],
                source=r["source"], kinds=r.get("kinds", []), status=r.get("status", []),
                invalid_only=r.get("invalid_only", False), attr=r.get("field", ""),
                patterns=patterns, count=r.get("count", 1), window=r.get("window", 60),
                then_kinds=r.get("then_kinds", []),
            ))
        except re.error as exc:
            raise ValueError(f"{rid}: geçersiz regex: {exc}") from None
        except KeyError as exc:
            raise ValueError(f"{rid}: eksik alan {exc}") from None
    return rules


def _add_example(f: Finding, raw: str, limit: int = 3) -> None:
    if len(f.examples) < limit:
        f.examples.append(raw)


# --------------------------------------------------------------- tipler

def _pattern(rule: Rule, events: list[Event]) -> list[Finding]:
    """IP başına tek bulgu: kaç satır eşleşti, ilk/son zaman, birkaç örnek."""
    by_ip: dict[str, Finding] = {}
    for e in events:
        value = (getattr(e, rule.attr) or "")[:MAX_FIELD]
        hit = next((p for p in rule.patterns if p.search(value)), None)
        if hit is None:
            continue
        f = by_ip.get(e.ip)
        if f is None:
            f = by_ip[e.ip] = Finding(rule.id, rule.title, rule.severity, e.ip,
                                      e.ts, e.ts, 0, f"desen: {hit.pattern}")
        f.count += 1
        f.last = e.ts
        _add_example(f, e.raw)
    return list(by_ip.values())


def _burst(rule: Rule, events: list[Event], value_of=None) -> list[Finding]:
    """Kayan pencere. Eşik aşılınca bir "patlama" açılır; olaylar arasında
    `window` saniyeden uzun boşluk olunca kapanır. Patlama başına tek bulgu."""
    win = timedelta(seconds=rule.window)
    out: list[Finding] = []
    recent: dict[str, deque] = defaultdict(deque)
    active: dict[str, Finding] = {}
    values: dict[str, set] = {}

    for e in events:
        f = active.get(e.ip)
        if f is not None and e.ts - f.last > win:
            out.append(active.pop(e.ip))
            recent[e.ip].clear()
            f = None
        if f is not None:
            f.last = e.ts
            if value_of:
                values[e.ip].add(value_of(e))
                f.count = len(values[e.ip])
                f.detail = "değerler: " + ", ".join(sorted(values[e.ip]))
            else:
                f.count += 1
            _add_example(f, e.raw)
            continue

        dq = recent[e.ip]
        dq.append(e)
        while dq[0].ts < e.ts - win:
            dq.popleft()
        if value_of:
            seen = {value_of(x) for x in dq}
            reached = len(seen) >= rule.count
        else:
            reached = len(dq) >= rule.count
        if reached:
            f = Finding(rule.id, rule.title, rule.severity, e.ip, dq[0].ts, e.ts, len(dq))
            if value_of:
                values[e.ip] = seen
                f.count = len(seen)
                f.detail = "değerler: " + ", ".join(sorted(seen))
            else:
                f.detail = f"{rule.window} sn içinde ≥{rule.count} olay"
            for x in list(dq)[:3]:
                _add_example(f, x.raw)
            active[e.ip] = f
            dq.clear()
    out.extend(active.values())
    return out


def _followed_by(rule: Rule, events: list[Event]) -> list[Finding]:
    win = timedelta(seconds=rule.window)
    before: dict[str, deque] = defaultdict(deque)
    out = []
    for e in events:
        dq = before[e.ip]
        while dq and dq[0].ts < e.ts - win:
            dq.popleft()
        if e.kind in rule.kinds:
            dq.append(e)
        elif e.kind in rule.then_kinds and len(dq) >= rule.count:
            f = Finding(rule.id, rule.title, rule.severity, e.ip, dq[0].ts, e.ts,
                        len(dq) + 1, f"{len(dq)} başarısız denemeden sonra giriş: {e.user}")
            _add_example(f, dq[-1].raw)
            _add_example(f, e.raw)
            out.append(f)
            dq.clear()
    return out


def run_rules(rules: list[Rule], events: list[Event]) -> list[Finding]:
    events = sorted(events, key=lambda e: e.ts)
    findings: list[Finding] = []
    for rule in rules:
        if rule.type == "followed_by":
            sel = [e for e in events if e.source == rule.source
                   and e.kind in rule.kinds + rule.then_kinds]
            findings += _followed_by(rule, sel)
            continue
        sel = [e for e in events if rule.selects(e)]
        if rule.type == "pattern":
            findings += _pattern(rule, sel)
        elif rule.type == "threshold":
            findings += _burst(rule, sel)
        elif rule.type == "distinct":
            findings += _burst(rule, sel, value_of=lambda e, a=rule.attr: getattr(e, a))
    findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.first, f.rule_id))
    return findings
