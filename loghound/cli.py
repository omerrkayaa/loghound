from __future__ import annotations

import argparse
import sys
from datetime import date

from . import __version__
from .parsers import ParseStats, parse_file
from .report import to_html, to_json, to_text
from .rules import DEFAULT_RULES, SEVERITIES, load_rules, run_rules


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="loghound",
        description="nginx/Apache erişim loglarında ve sshd auth.log'da saldırı izleri arar.")
    p.add_argument("files", nargs="+", help="log dosyaları (biçim satır satır otomatik tanınır)")
    p.add_argument("--rules", default=DEFAULT_RULES, help="TOML kural dosyası")
    p.add_argument("--format", choices=["text", "json", "html"], default="text")
    p.add_argument("-o", "--output", help="çıktı dosyası (varsayılan: stdout)")
    p.add_argument("--year", type=int, default=date.today().year,
                   help="yılsız syslog satırları için yıl (varsayılan: bu yıl)")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--fail-on", choices=SEVERITIES,
                   help="bu önemde ya da üstünde bulgu varsa çıkış kodu 1")
    p.add_argument("--version", action="version", version=f"loghound {__version__}")
    a = p.parse_args(argv)

    try:
        rules = load_rules(a.rules)
    except (OSError, ValueError) as exc:
        print(f"kural dosyası okunamadı: {exc}", file=sys.stderr)
        return 2

    stats = ParseStats()
    events = []
    for path in a.files:
        try:
            events += parse_file(path, a.year, stats)
        except OSError as exc:
            print(f"okunamadı: {path}: {exc}", file=sys.stderr)
            return 2

    floor = SEVERITIES.index(a.min_severity)
    findings = [f for f in run_rules(rules, events) if SEVERITIES.index(f.severity) >= floor]
    out = {"text": to_text, "json": to_json, "html": to_html}[a.format](findings, stats)

    if a.output:
        try:
            with open(a.output, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
        except OSError as exc:
            print(f"yazılamadı: {a.output}: {exc}", file=sys.stderr)
            return 2
        print(f"{len(findings)} bulgu → {a.output}", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(out)

    if a.fail_on:
        limit = SEVERITIES.index(a.fail_on)
        if any(SEVERITIES.index(f.severity) >= limit for f in findings):
            return 1
    return 0
