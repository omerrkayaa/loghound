# loghound

Sunucu loglarında saldırı izi arayan küçük bir komut satırı aracı. nginx/Apache erişim loglarını ve OpenSSH `auth.log` dosyalarını okur. TOML dosyasında tanımlı kuralları uygular. Bulguları terminale, JSON'a ya da tek dosyalık bir HTML rapora yazar.

Savunma tarafına bakan bir proje. Saldırıları uygulamalı gösteren [owasp-mini-lab](https://github.com/omerrkayaa/owasp-mini-lab) ile birlikte okunabilir.

- Bağımlılık yok, yalnız Python standart kütüphanesi kullanılır (`tomllib`, `re`, `argparse`).
- Log biçimi satır satır otomatik tanınır, farklı türde dosyaları birlikte verebilirsiniz.
- Kurallar koddan ayrıdır. Yeni bir desen ya da eşik eklemek için Python yazmanız gerekmez.

## Kurulum

Python 3.11 ya da üstü gerekir (`tomllib` için).

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[test]"
```

Kurmadan da çalışır: depo kökünde `python -m loghound ...` yeterlidir.

## Çalıştırma

```bash
python -m loghound samples/access.log samples/auth.log --year 2026
```

Sık kullanılan seçenekler:

| Seçenek | Ne yapar |
|---|---|
| `--format text\|json\|html` | Çıktı biçimi (varsayılan `text`) |
| `-o rapor.html` | Çıktıyı dosyaya yazar |
| `--rules kurallar.toml` | Varsayılan yerine kendi kural dosyanızı kullanır |
| `--min-severity high` | Bu önemin altındaki bulguları gizler |
| `--fail-on high` | Bu önemde ya da üstünde bulgu varsa çıkış kodu `1` olur (CI ya da cron için) |
| `--year 2026` | Yılsız syslog satırları için yıl (varsayılan: bu yıl) |

HTML rapor:

```bash
python -m loghound samples/*.log --year 2026 --format html -o report.html
```

### Örnek çıktı

`samples/` içindeki loglarda normal trafik ve sekiz farklı saldırı senaryosu var. Beklenen sonuç 10 bulgudur:

```
89 satır, 87 olay (2 ilgisiz, 2 tanınmayan satır)
10 bulgu

[CRITICAL] ssh-success-after-failures   192.0.2.52       x6    2026-11-05 09:16:40 → 09:17:20
           5 başarısız denemeden sonra giriş: deploy
[HIGH    ] ssh-brute-force              192.0.2.50       x8    2026-11-05 09:05:00 → 09:05:35
[HIGH    ] web-sqli                     203.0.113.20     x4    2026-11-05 09:10:03 → 09:10:12
[HIGH    ] ssh-brute-force              192.0.2.52       x5    2026-11-05 09:16:40 → 09:17:04
[HIGH    ] web-path-traversal           203.0.113.22     x2    2026-11-05 09:20:00 → 09:20:05
[HIGH    ] ssh-brute-force              192.0.2.53       x5    2026-11-05 09:21:40 → 09:21:50
[MEDIUM  ] ssh-user-enum                192.0.2.51       x6    2026-11-05 09:10:00 → 09:13:21
           değerler: admin, guest, oracle, pi, test, ubuntu
[MEDIUM  ] web-scanner-ua               203.0.113.20     x5    2026-11-05 09:10:00 → 09:10:12
[MEDIUM  ] web-xss                      203.0.113.21     x2    2026-11-05 09:15:00 → 09:15:10
[MEDIUM  ] web-404-burst                203.0.113.23     x25   2026-11-05 09:25:00 → 09:25:28
```

(Kısaltılmıştır. Gerçek çıktıda her bulgunun altında bir örnek log satırı da yer alır. Saatler logda yazdığı gibi gösterilir.)

Örnek loglardaki IP adresleri belgeleme için ayrılmış bloklardandır (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Gerçek bir sisteme ait değildir.

Testler:

```bash
pytest
```

## Kurallar

Varsayılan kurallar [`loghound/default_rules.toml`](loghound/default_rules.toml) dosyasındadır.

| Kural | Tip | Neyi yakalar | Önem |
|---|---|---|---|
| `web-sqli` | pattern | `UNION SELECT`, `' OR 1=1`, `SLEEP(`, `; DROP` gibi yükler | high |
| `web-xss` | pattern | `<script`, `javascript:`, `onerror=` | medium |
| `web-path-traversal` | pattern | `../`, `/etc/passwd`, `win.ini` | high |
| `web-scanner-ua` | pattern | sqlmap, nikto, nmap, gobuster, nuclei vb. User-Agent | medium |
| `web-404-burst` | threshold | Bir IP'den 60 sn içinde ≥20 adet 404 (dizin taraması) | medium |
| `ssh-brute-force` | threshold | Bir IP'den 60 sn içinde ≥5 başarısız giriş | high |
| `ssh-user-enum` | distinct | Bir IP'den 5 dk içinde ≥5 farklı geçersiz kullanıcı adı | medium |
| `ssh-success-after-failures` | followed_by | 10 dk içinde ≥5 başarısız denemenin ardından başarılı giriş | critical |

Kural tipleri:

- **pattern**: Tek satırda regex eşleşmesi. IP başına tek bulgu üretilir: kaç satır eşleşti, ilk ve son zaman, birkaç örnek.
- **threshold**: Kayan zaman penceresi. Eşik aşıldığında bir "patlama" başlar. Olaylar arasında pencereden uzun bir boşluk olunca patlama kapanır. Her patlama için tek bulgu üretilir, her satır için ayrı bulgu üretilmez.
- **distinct**: threshold gibi çalışır, ancak olay sayısı yerine farklı değer sayısına bakar (ör. kullanıcı adı).
- **followed_by**: Penceredeki "önce" olayları eşiği aştıysa, ardından gelen "sonra" olayı bulgu olur.

Yeni bir kural eklemek için dosyaya bir `[[rule]]` bloğu yazmanız yeterli:

```toml
[[rule]]
id = "web-env-probe"
title = ".env / .git dosyası yoklaması"
severity = "medium"
type = "pattern"
source = "web"
field = "target"
patterns = ['''/\.(env|git)(/|$)''']
```

## Nasıl çalışır

1. **Ayrıştırma** ([`parsers.py`](loghound/parsers.py)): Her satır önce "combined" erişim logu biçimiyle, olmazsa sshd biçimiyle denenir. İkisine de uymayan satırlar sayılır ve atlanır. Dosyalar `errors="replace"` ile açılır, yani bozuk bayt içeren bir satır aracı durdurmaz.
2. **URL kod çözme**: Desenler, kodlaması çözülmüş hedefe uygulanır. Çözme işlemi değişiklik kalmayana kadar en fazla 3 tur sürer. Böylece `%27%20OR%201%3D1` ve çift kodlanmış `%252e%252e%252f` de yakalanır.
3. **Kurallar** ([`rules.py`](loghound/rules.py)): Olaylar zamana göre sıralanır ve her kural kendi kaynağına (`web`/`ssh`) uygulanır.
4. **Rapor** ([`report.py`](loghound/report.py)): Log içeriğini saldırgan belirler. Bu yüzden HTML raporda her alan `html.escape` ile kaçışlanır, böylece raporun kendisi XSS taşımaz. Terminal çıktısında da kontrol ve ANSI karakterleri temizlenir (terminal kaçış enjeksiyonu). İkisinin de testi var.

sshd satırlarıyla ilgili ayrıntılar:

- `Invalid user X` ve `Failed password for invalid user X` aynı denemedir. Kaba kuvvet sayımına yalnız `Failed` satırları girer. Kullanıcı adı taramasında da aynı ad bir kez sayılır.
- Kullanıcı adını saldırgan seçer ve ad boşluk içerebilir. Örneğin `x from 8.8.8.8 port 1` gibi bir adla suç başka bir IP'ye yıkılmaya çalışılabilir. Bu yüzden IP satırın sonundan okunur ve `ipaddress` ile doğrulanır.
- rsyslog'un `message repeated N times: [ ... ]` satırı N ayrı olay olarak sayılır (en fazla 1000).
- Regex'e verilen alanlar 4096 karakterde kırpılır. Varsayılan desenler felaket geri izlemeye (ReDoS) karşı testlidir.
- Hem klasik syslog (`Nov  5 10:00:01`) hem ISO zaman damgası (`2026-11-05T10:00:01+03:00`, journald/rsyslog yeni biçim) desteklenir.

## Sınırlamalar

- Klasik syslog satırında yıl ve saat dilimi yoktur. Yıl `--year` ile verilir, saat dilimi olarak yerel saat kabul edilir. Aralık'tan Ocak'a geçen bir log dosyası tek yılla doğru okunmaz.
- İmza (desen) tabanlı tespit, kodlanmış ya da bölünmüş yükleri kaçırabilir. Bu bir WAF ya da SIEM yerine geçmez, öğrenme ve hızlı triyaj için tasarlanmıştır.
- Yalnız URL yolu ve sorgu dizesi incelenir. POST gövdesi erişim loguna düşmediği için görünmez.
- Dosyalar baştan sona okunur, canlı izleme (`tail -f`) yoktur.

## Lisans

MIT
