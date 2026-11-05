"""Bulguları metin, JSON ya da HTML olarak biçimlendirir.

Log içeriği saldırganın kontrolündedir. Bu yüzden:
- metin çıktısında kontrol/ANSI karakterleri temizlenir (terminal kaçış enjeksiyonu),
- HTML çıktısında her alan html.escape ile kaçışlanır (raporun kendisinde XSS olmasın).
"""

from __future__ import annotations

import html
import json
import re

from .parsers import ParseStats
from .rules import Finding

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(s: str) -> str:
    return _CONTROL.sub("?", s)


def _when(f: Finding) -> str:
    a, b = f.first.strftime("%Y-%m-%d %H:%M:%S"), f.last.strftime("%H:%M:%S")
    return a if f.first == f.last else f"{a} → {b}"


def to_text(findings: list[Finding], stats: ParseStats) -> str:
    out = [f"{stats.lines} satır, {stats.events} olay "
           f"({stats.ignored} ilgisiz, {stats.unknown} tanınmayan satır)",
           f"{len(findings)} bulgu", ""]
    for f in findings:
        out.append(f"[{f.severity.upper():8}] {f.rule_id:28} {clean(f.ip):16} "
                   f"x{f.count:<4} {_when(f)}")
        if f.detail:
            out.append(f"           {clean(f.detail)}")
        for ex in f.examples[:1]:
            out.append(f"           örnek: {clean(ex)[:160]}")
    return "\n".join(out)


def to_json(findings: list[Finding], stats: ParseStats) -> str:
    return json.dumps({"stats": vars(stats), "findings": [f.to_dict() for f in findings]},
                      ensure_ascii=False, indent=2)


_CSS = """
:root{--bg:#fff;--fg:#1d2128;--mut:#646b76;--line:#e3e6ea;--chip:#f2f4f6}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e8eb;--mut:#9aa1ab;--line:#2a2f37;--chip:#1e232a}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:1000px;margin:auto}h1{font-size:22px;margin:0 0 4px}p.m{color:var(--mut);margin:0 0 20px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
code{font:12px/1.4 ui-monospace,monospace;background:var(--chip);padding:2px 4px;border-radius:4px;word-break:break-all;display:block;margin-top:4px}
.s{font-weight:600;font-size:12px;padding:2px 8px;border-radius:99px;white-space:nowrap}
.critical{background:#7a1020;color:#fff}.high{background:#c2410c;color:#fff}.medium{background:#b7791f;color:#fff}.low{background:#4b5563;color:#fff}
.wrap{overflow-x:auto}
"""


def to_html(findings: list[Finding], stats: ParseStats) -> str:
    e = html.escape
    rows = []
    for f in findings:
        ex = "".join(f"<code>{e(x)}</code>" for x in f.examples)
        rows.append(
            f"<tr><td><span class='s {e(f.severity)}'>{e(f.severity)}</span></td>"
            f"<td><b>{e(f.title)}</b><br><small>{e(f.rule_id)}</small></td>"
            f"<td>{e(f.ip)}</td><td>{f.count}</td><td>{e(_when(f))}</td>"
            f"<td>{e(f.detail)}{ex}</td></tr>")
    body = "".join(rows) or "<tr><td colspan='6'>Bulgu yok.</td></tr>"
    return (
        "<!doctype html><html lang='tr'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>loghound raporu</title><style>{_CSS}</style></head><body><main>"
        f"<h1>loghound raporu</h1><p class='m'>{stats.lines} satır, {stats.events} olay, "
        f"{len(findings)} bulgu</p><div class='wrap'><table><thead><tr><th>Önem</th><th>Kural</th>"
        f"<th>IP</th><th>Adet</th><th>Zaman</th><th>Ayrıntı</th></tr></thead>"
        f"<tbody>{body}</tbody></table></div></main></body></html>")
