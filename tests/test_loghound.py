import json
from pathlib import Path

import pytest

from loghound.cli import main
from loghound.parsers import ParseStats, decode_target, parse_file, parse_lines
from loghound.report import to_html, to_text
from loghound.rules import load_rules, run_rules

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
RULES = load_rules()


def ids(findings):
    return {(f.rule_id, f.ip) for f in findings}


def ssh_failed(n, ip="192.0.2.9", step=5, start=0):
    for i in range(n):
        s = start + i * step
        yield f"Nov  5 10:{s // 60:02d}:{s % 60:02d} h sshd[1]: Failed password for root from {ip} port {4000 + i} ssh2"


def web(ip, path, status=200, ua="Mozilla/5.0", sec=0):
    return f'{ip} - - [05/Nov/2026:10:00:{sec:02d} +0000] "GET {path} HTTP/1.1" {status} 10 "-" "{ua}"'


# ---------------------------------------------------------- örnek loglar

def test_samples_exact_findings():
    events = parse_file(SAMPLES / "access.log", 2026) + parse_file(SAMPLES / "auth.log", 2026)
    assert ids(run_rules(RULES, events)) == {
        ("web-sqli", "203.0.113.20"),
        ("web-scanner-ua", "203.0.113.20"),
        ("web-xss", "203.0.113.21"),
        ("web-path-traversal", "203.0.113.22"),
        ("web-404-burst", "203.0.113.23"),
        ("ssh-brute-force", "192.0.2.50"),
        ("ssh-brute-force", "192.0.2.52"),
        ("ssh-brute-force", "192.0.2.53"),
        ("ssh-user-enum", "192.0.2.51"),
        ("ssh-success-after-failures", "192.0.2.52"),
    }


def test_benign_ips_never_flagged():
    events = parse_file(SAMPLES / "access.log", 2026) + parse_file(SAMPLES / "auth.log", 2026)
    flagged = {f.ip for f in run_rules(RULES, events)}
    assert not flagged & {"198.51.100.10", "198.51.100.11"}


def test_benign_only_log_has_no_findings():
    lines = [web("198.51.100.1", p, sec=i) for i, p in enumerate(
        ["/", "/search?q=it%27s+fine", "/products?id=3", "/a/b/c.css", "/search?q=select+a+size"])]
    lines.append("Nov  5 10:00:00 h sshd[1]: Accepted publickey for alice from 198.51.100.1 port 1 ssh2")
    assert run_rules(RULES, parse_lines(lines, 2026)) == []


# ---------------------------------------------------------- eşikler

def test_brute_force_threshold_boundary():
    assert run_rules(RULES, parse_lines(list(ssh_failed(4)), 2026)) == []
    found = run_rules(RULES, parse_lines(list(ssh_failed(5)), 2026))
    assert ids(found) == {("ssh-brute-force", "192.0.2.9")}


def test_brute_force_window_is_respected():
    # 5 deneme, aralarında 20 sn: toplam 80 sn > 60 sn pencere
    assert run_rules(RULES, parse_lines(list(ssh_failed(5, step=20)), 2026)) == []


def test_one_finding_per_burst():
    lines = list(ssh_failed(30, step=2))                 # tek uzun patlama
    lines += list(ssh_failed(5, step=2, start=600))      # 10 dk sonra ikinci patlama
    found = [f for f in run_rules(RULES, parse_lines(lines, 2026)) if f.rule_id == "ssh-brute-force"]
    assert [f.count for f in found] == [30, 5]


def test_repeated_message_is_expanded():
    lines = ["Nov  5 10:00:00 h sshd[1]: message repeated 4 times: [ Failed password for root from 192.0.2.7 port 1 ssh2]",
             "Nov  5 10:00:05 h sshd[1]: Failed password for root from 192.0.2.7 port 2 ssh2"]
    assert ids(run_rules(RULES, parse_lines(lines, 2026))) == {("ssh-brute-force", "192.0.2.7")}


def test_user_enum_does_not_double_count():
    # aynı kullanıcı için "Invalid user" + "Failed ... invalid user" tek değer sayılır
    lines = []
    for i, u in enumerate(["a", "b", "c", "d"]):
        lines.append(f"Nov  5 10:00:{i * 10:02d} h sshd[1]: Invalid user {u} from 192.0.2.8 port 1")
        lines.append(f"Nov  5 10:00:{i * 10 + 1:02d} h sshd[1]: Failed password for invalid user {u} from 192.0.2.8 port 1 ssh2")
    assert run_rules(RULES, parse_lines(lines, 2026)) == []   # 4 farklı ad < 5


def test_iso_timestamps_supported():
    lines = [f"2026-11-05T10:00:0{i}.000000+03:00 h sshd[1]: Failed password for root from 192.0.2.6 port 1 ssh2"
             for i in range(5)]
    assert ids(run_rules(RULES, parse_lines(lines, 2026))) == {("ssh-brute-force", "192.0.2.6")}


# ---------------------------------------------------------- kod çözme

@pytest.mark.parametrize("raw,rule", [
    ("/p?id=1%27%20OR%201%3D1--", "web-sqli"),
    ("/p?id=1+UNION+SELECT+1", "web-sqli"),
    ("/f?x=%252e%252e%252fetc%252fpasswd", "web-path-traversal"),
    ("/s?q=%3CScRiPt%3E", "web-xss"),
])
def test_encoded_payloads_detected(raw, rule):
    found = run_rules(RULES, parse_lines([web("203.0.113.9", raw)], 2026))
    assert rule in {f.rule_id for f in found}


def test_decode_target_double_encoding():
    assert decode_target("%252e%252e%252f") == "../"


# ---------------------------------------------------------- rapor güvenliği

def test_html_report_escapes_attacker_input():
    line = web("203.0.113.9", "/s?q=<script>alert(1)</script>", ua="<img src=x onerror=alert(2)>")
    stats = ParseStats()
    findings = run_rules(RULES, parse_lines([line], 2026, stats))
    assert findings
    out = to_html(findings, stats)
    assert "<script>alert" not in out and "<img src=x" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out


def test_text_report_strips_terminal_escapes():
    line = web("203.0.113.9", "/s?q=<script>\x1b[2J\x1b]0;pwned\x07")
    stats = ParseStats()
    out = to_text(run_rules(RULES, parse_lines([line], 2026, stats)), stats)
    assert "\x1b" not in out and "\x07" not in out


def test_malformed_lines_are_counted_not_fatal():
    stats = ParseStats()
    parse_lines(["garbage", "\x00\xff", web("198.51.100.1", "/")], 2026, stats)
    assert stats.unknown == 2 and stats.events == 1


def test_username_cannot_spoof_source_ip():
    lines = [f"Nov  5 10:00:0{i} h sshd[1]: Failed password for invalid user x from 8.8.8.8 port 1 "
             f"from 192.0.2.66 port 22 ssh2" for i in range(5)]
    assert ids(run_rules(RULES, parse_lines(lines, 2026))) >= {("ssh-brute-force", "192.0.2.66")}
    assert "8.8.8.8" not in {f.ip for f in run_rules(RULES, parse_lines(lines, 2026))}


def test_invalid_iso_date_does_not_crash():
    stats = ParseStats()
    parse_lines(["2026-13-45T10:00:01+03:00 h sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2"],
                2026, stats)
    assert stats.unknown == 1


def test_no_catastrophic_backtracking():
    import time
    payloads = ["/?q=union" + "/**/" * 5000 + "x", "/?q=" + "'or " * 3000, "/?q=" + "." * 8000]
    lines = [web("203.0.113.9", p, sec=i) for i, p in enumerate(payloads)]
    t = time.perf_counter()
    run_rules(RULES, parse_lines(lines, 2026))
    assert time.perf_counter() - t < 1.0


def test_unencoded_space_in_request_target():
    found = run_rules(RULES, parse_lines([web("203.0.113.9", "/?q=1 union select 1")], 2026))
    assert "web-sqli" in {f.rule_id for f in found}


@pytest.mark.parametrize("body", [
    'patterns=["("]\nfield="target"',          # geçersiz regex
    'field="ua"\npatterns=["x"]\nsource2="x"',  # ssh kuralında web alanı (aşağıda source=ssh)
])
def test_rule_validation_errors(tmp_path, body):
    src = "ssh" if "source2" in body else "web"
    f = tmp_path / "r.toml"
    f.write_text(f'[[rule]]\nid="x"\ntitle="x"\nseverity="high"\ntype="pattern"\nsource="{src}"\n{body}\n')
    with pytest.raises(ValueError):
        load_rules(f)


# ---------------------------------------------------------- CLI

def test_cli_json_and_fail_on(tmp_path, capsys):
    out = tmp_path / "r.json"
    code = main([str(SAMPLES / "auth.log"), "--year", "2026", "--format", "json",
                 "-o", str(out), "--fail-on", "critical"])
    assert code == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert {f["rule"] for f in data["findings"]} >= {"ssh-brute-force", "ssh-success-after-failures"}


def test_cli_min_severity_filters(capsys):
    assert main([str(SAMPLES / "access.log"), "--min-severity", "high", "--fail-on", "high"]) == 1
    out = capsys.readouterr().out
    assert "web-sqli" in out and "web-xss" not in out


def test_bad_rule_file(tmp_path, capsys):
    bad = tmp_path / "r.toml"
    bad.write_text('[[rule]]\nid="x"\ntitle="x"\nseverity="high"\ntype="nope"\nsource="web"\n')
    assert main([str(SAMPLES / "access.log"), "--rules", str(bad)]) == 2
