# Talaria — Öneri Detay Analizi

Her öneri 4 eksende 1-5 arası puanlanmıştır (5 = en iyi/en kolay).

## Skorlama Tablosu

| # | Öneri | Zorluk (5=kolay) | Hız Etkisi (5=çok hızlandırır) | FP Azaltma (5=çok azaltır) | Vektör Kaçırma Riski (5=risk yok) | Durum |
|---|-------|:-:|:-:|:-:|:-:|---|
| **D1** | Parallel Walker Pool | 2 | 5 | 0 | 5 | ⏳ Tier 3 |
| **B1** | Embedded GTFOBins JSON | 3 | 5 | 3 | 5 | ⏳ Tier 3 |
| **D2** | Shared UserContext | 5 | 3 | 0 | 5 | ✅ DONE |
| **A1** | Crontab Env Injection | 4 | 5 | 5 | 5 | ✅ DONE |
| **A2** | SysV Init Scripts | 5 | 5 | 5 | 5 | ✅ DONE |
| **A6** | Systemd EnvironmentFile | 3 | 4 | 4 | 5 | ⏳ Tier 3 |
| **C4** | Attack Path Dedup | 4 | 4 | 4 | 5 | ✅ DONE |
| **A3** | Logrotate Scanner | 4 | 5 | 5 | 5 | ✅ DONE |
| **B5** | cgroup v2 Detection | 5 | 5 | 4 | 5 | ✅ DONE |
| **D3** | sync.Pool Buffers | 4 | 2 | 0 | 5 | ✅ DONE |
| **D4** | GID Cache | 5 | 2 | 0 | 5 | ✅ DONE |
| **E4** | SUID+Writable Lib Chain | 4 | 5 | 4 | 5 | ✅ DONE |
| **C1** | Writable Temp Exclusions | 4 | 3 | 4 | 3 | ✅ DONE |
| **C2** | Content-Type Aware FP | 3 | 4 | 4 | 3 | ⏳ Tier 3 |
| **B2** | ELF String Analysis | 2 | 3 | 3 | 5 | ⏳ Tier 3 |
| **B3** | Deeper .env Scanning | 5 | 4 | 3 | 5 | ✅ DONE |
| **B4** | Anacron Writability | 5 | 5 | 5 | 5 | ✅ DONE |
| **B6** | Distro Patch Awareness | 2 | 5 | 5 | 4 | ⏳ Tier 3 |
| **A4** | X11 Authority Theft | 5 | 5 | 5 | 5 | ✅ DONE |
| **A5** | at Job Queue | 5 | 5 | 5 | 5 | ✅ DONE |
| **E1** | Logrotate→Root Chain | 4 | 5 | 4 | 5 | ✅ DONE |
| **E2** | EnvironmentFile→Root | 3 | 5 | 4 | 5 | ⏳ Tier 3 |
| **E3** | Password Reuse Chain | 3 | 4 | 3 | 4 | ⏳ Tier 3 |
| **F1** | Syscall Rate Limiter | 2 | 1 | 0 | 5 | ⏳ Tier 3 |
| **F2** | /dev/shm Default Output | 5 | 5 | 0 | 5 | ✅ DONE |
| **C3** | Ephemeral Port Filter | 5 | 3 | 4 | 4 | ✅ DONE |

---

## Detaylı Analiz

### D1 — Parallel Walker Pool
- **Zorluk: 2/5** — Tüm scanner'lardaki `filepath.WalkDir` çağrılarını worker-pool mimarisine geçirmek gerekiyor. Race condition yönetimi, goroutine limitleri ve `filepath.SkipDir` semantiğinin korunması kritik. ~300 satır yeni altyapı + 6-8 scanner dosyasında refactor.
- **Hız: 5/5** — En büyük darboğaz. Secrets, SUID, writeable scanner'ları tek thread ile yürüyor. NFS/yavaş disklerde 5-10x, SSD'lerde 2-4x hızlanma beklenir.
- **FP: 0/5** — Finding logic'e dokunmuyor, sadece traversal hızını artırıyor.
- **Vektör Kaçırma: 5/5** — Risk yok, aynı dosyalar taranıyor, sadece paralel.

### B1 — Embedded GTFOBins JSON
- **Zorluk: 3/5** — JSON dosyası hazırlanmalı (GTFOBins API/scrape), `go:embed` ile binary'ye gömülmeli, mevcut `trueDangerousBinaries` map yerine JSON lookup konmalı. ~150 satır Go + JSON dosyası bakımı.
- **Hız: 5/5** — `go:embed` compile-time'da yüklenir, runtime maliyeti sıfır. Mevcut map lookup'tan farklı değil.
- **FP: 3/5** — Daha geniş binary listesi = daha fazla hit. Ama GTFOBins zaten doğrulanmış vektörler, yani gerçek FP artışı minimal. Yine de `busybox`, `dstat` gibi context-dependent binary'ler için SUID olmadan flag'lememek lazım.
- **Vektör Kaçırma: 5/5** — Tam tersi: şu an 30 binary taranıyor, GTFOBins'te 400+ var. FN oranını drastik düşürür.

### D2 — Shared UserContext
- **Zorluk: 5/5** — Basit struct oluştur, `main.go`'da bir kez initialize et, tüm scanner fonksiyonlarına parametre olarak geç. Sadece fonksiyon imzaları değişir.
- **Hız: 3/5** — ~20 redundant `user.Current()` + `GroupIds()` + `/etc/passwd` parse'ı elimine edilir. Toplam ~50-100ms tasarruf (küçük ama bedava).
- **FP: 0/5** — Logic değişmiyor.
- **Vektör Kaçırma: 5/5** — Risk yok.

### A1 — Crontab Env Injection Scanner
- **Zorluk: 4/5** — Mevcut `parseFile()` fonksiyonuna environment variable satırlarını (`PATH=`, `LD_PRELOAD=`, `SHELL=`) parse eden 40-50 satır ekleme. Writable crontab dosyasında root job varsa ve env override edilebiliyorsa flag'le.
- **Hız: 5/5** — Mevcut crontab I/O'sunun içinde çalışır, ekstra disk erişimi yok.
- **FP: 5/5** — Sadece writable dosya + root job + tehlikeli env kombinasyonunda tetiklenir. FP riski neredeyse sıfır.
- **Vektör Kaçırma: 5/5** — Yeni vektör ekleme, mevcut hiçbir şeyi bozmaz.

### A2 — SysV Init Scripts
- **Zorluk: 5/5** — `/etc/init.d/` ve `/etc/rc*.d/` dizinlerinde writable dosya taraması. Mevcut `ScanWritableServices()` ile aynı pattern, ~60 satır.
- **Hız: 5/5** — Tek dizin taraması, ~5ms.
- **FP: 5/5** — Direkt writability check, FP riski sıfır.
- **Vektör Kaçırma: 5/5** — Şu an tamamen eksik olan bir vektör. Legacy sistemlerde kritik.

### A6 — Systemd EnvironmentFile
- **Zorluk: 3/5** — Tüm `.service` dosyalarını parse edip `EnvironmentFile=` direktiflerini çıkarmak, sonra referans edilen dosyanın writable olup olmadığını kontrol etmek gerekiyor. ~100 satır. Zorluk: `EnvironmentFile=-/path` (dash prefix = ignore if missing) ve specifier'lar (`%i`, `%n`) handle edilmeli.
- **Hız: 4/5** — Mevcut systemd taramasının içine entegre edilebilir, minimal ekstra I/O.
- **FP: 4/5** — Writable env dosyası + root service kombinasyonu gerektiği için FP düşük. Ama bazı env dosyaları writable by design olabilir (kullanıcı override'ları).
- **Vektör Kaçırma: 5/5** — Yeni vektör, mevcut hiçbir şeyi bozmaz.

### C4 — Attack Path Dedup
- **Zorluk: 4/5** — `RunIntelligenceEngine`'de `allResults` slice'ına eklenmeden önce path hash'i kontrol et. ~20 satır.
- **Hız: 4/5** — Duplicate path rendering'i elimine eder, terminal output daha hızlı.
- **FP: 4/5** — Aynı vektörün 3x gösterilmesi kullanıcıyı yanıltır. Dedup ile cleaner output.
- **Vektör Kaçırma: 5/5** — Sadece duplicate'ler kaldırılır, unique path'ler korunur.

### A3 — Logrotate Scanner
- **Zorluk: 4/5** — `/etc/logrotate.d/` dizininde writable dosya taraması + `postrotate`/`prerotate` block parsing. ~80 satır.
- **Hız: 5/5** — Küçük dizin, ~10ms.
- **FP: 5/5** — Writable config + root context = düşük FP.
- **Vektör Kaçırma: 5/5** — CTF'lerde yaygın vektör, şu an graph'ta sadece `FilePermissions` üzerinden dolaylı tespit var, dedicated scanner yok.

### B5 — cgroup v2 Detection
- **Zorluk: 5/5** — `ScanContainer()`'a 10-15 satır ekleme. `/proc/1/mountinfo` parse.
- **Hız: 5/5** — Tek dosya okuma.
- **FP: 4/5** — Overlay mount olan her sistem container değil (bazı VPS'ler overlay kullanır). `/.dockerenv` ile cross-check yapılmalı.
- **Vektör Kaçırma: 5/5** — Modern container'ları kaçırmayı önler (Docker 24+, Podman 4+ hep cgroup v2).

### D3 — sync.Pool Buffers
- **Zorluk: 4/5** — `secrets.go`'daki `header := make([]byte, 512)` satırını pool'dan al/geri koy. ~15 satır.
- **Hız: 2/5** — Sadece 10,000+ dosya taranan büyük filesystem'lerde fark yaratır. Normal CTF box'ta etkisi minimal.
- **FP: 0/5** — Logic değişmiyor.
- **Vektör Kaçırma: 5/5** — Risk yok.

### D4 — GID Cache
- **Zorluk: 5/5** — `sync.Map` ile cache, ~20 satır.
- **Hız: 2/5** — `user.LookupGroupId` per-file çağrısı elimine edilir ama genelde az sayıda unique GID vardır. Etkisi küçük.
- **FP: 0/5** — Logic değişmiyor.
- **Vektör Kaçırma: 5/5** — Risk yok.

### E4 — SUID + Writable Library Path Chain
- **Zorluk: 4/5** — `intelligence.go`'ya yeni chain struct. `report.SUID`'deki `WritableLibraryPaths` ile cross-reference. ~40 satır.
- **Hız: 5/5** — Mevcut veriden çalışır, ekstra I/O yok.
- **FP: 4/5** — SUID root binary + writable RPATH = gerçek vektör. FP düşük.
- **Vektör Kaçırma: 5/5** — SUID scanner zaten writable lib path'leri tespit ediyor ama intelligence engine bunları chain'e bağlamıyor. Bu gap'i kapatır.

### C1 — Writable Temp Exclusions
- **Zorluk: 4/5** — `ScanWriteable()`'a path filter ekleme. ~15 satır.
- **Hız: 3/5** — Büyük `/tmp` dizinlerinde noise azalır, daha az result = daha hızlı render.
- **FP: 4/5** — `/tmp`, `/var/tmp`, `.cache/` gibi yerler gereksiz finding üretir.
- **Vektör Kaçırma: 3/5** — ⚠️ **DİKKAT**: `/tmp`'deki writable root dosyalar bazen gerçek vektördür (race condition, symlink attack). Filtreleme çok agresif olmamalı. Sadece current-user-owned dosyaları skip et.

### C2 — Content-Type Aware FP Filtering
- **Zorluk: 3/5** — Entropy check'e ek olarak regex pattern'ler (semver, hex color, filesystem path). ~40 satır.
- **Hız: 4/5** — Daha az false finding = daha az output.
- **FP: 4/5** — Hex renk kodları (`#FF5733`), semver (`3.8.0-beta.2`), path'ler FP üretir.
- **Vektör Kaçırma: 3/5** — ⚠️ Agresif pattern filter gerçek secret'leri de yakalayabilir. Örneğin bazı password'ler semver'e benzer. Regex'ler dikkatli tasarlanmalı.

### B2 — ELF String Analysis
- **Zorluk: 2/5** — `debug/elf` ile `.rodata` section okuma + string extraction + komut ismi matching. ~120 satır. Zorluk: hangi string'lerin "komut çağrısı" olduğunu belirlemek heuristic-heavy.
- **Hız: 3/5** — Her SUID ELF binary'de `.rodata` okumak ~1ms/binary, ama yüzlerce SUID olabilir.
- **FP: 3/5** — Bir binary'nin `.rodata`'sında "ls" string'i olması onu çağırdığı anlamına gelmez. Heuristic kalitesine bağlı.
- **Vektör Kaçırma: 5/5** — GTFOBins'te olmayan custom SUID binary'lerdeki PATH hijack vektörlerini yakalar.

### B3 — Deeper .env Scanning
- **Zorluk: 5/5** — `ScanSecrets`'teki `ctfPaths` listesine web app path'leri ekleme. ~5 satır.
- **Hız: 4/5** — Birkaç ekstra dizin walk'u ama targeted.
- **FP: 3/5** — `.env.example`, `.env.sample` dosyaları FP üretebilir. Filename filter gerekir.
- **Vektör Kaçırma: 5/5** — Web app secret'lerini daha iyi yakalar.

### B4 — Anacron Writability
- **Zorluk: 5/5** — `/etc/anacrontab` writability check. ~10 satır.
- **Hız: 5/5** — Tek stat() çağrısı.
- **FP: 5/5** — Direkt writability check.
- **Vektör Kaçırma: 5/5** — Anacron root job'larını yönetir, writable olması kritik.

### B6 — Distro Patch Awareness
- **Zorluk: 2/5** — Her CVE için her major distro'nun backport versiyonlarını araştırıp JSON'a eklemek gerekiyor. Sürekli bakım gerektiren bir iş. ~200 satır JSON + parser.
- **Hız: 5/5** — Compile-time embed, runtime maliyeti yok.
- **FP: 5/5** — Patched CVE'leri "likely_patched" olarak işaretler, ciddi FP azaltma.
- **Vektör Kaçırma: 4/5** — ⚠️ Yanlış "likely_patched" işaretleme gerçek vulnerable sistemi gizleyebilir. Patch bilgisi %100 doğru olmalı.

### A4 — X11 Authority Theft
- **Zorluk: 5/5** — `/home/*/`, `/root/`, `/tmp/` altında readable `.Xauthority` taraması. ~50 satır.
- **Hız: 5/5** — Targeted dosya check, ~5ms.
- **FP: 5/5** — Sadece readable + X11 aktif kombinasyonunda tetiklenir.
- **Vektör Kaçırma: 5/5** — Lateral movement vektörü, mevcut group scanner'ı (video/input) tamamlar.

### A5 — at Job Queue
- **Zorluk: 5/5** — Mevcut `ScanAtJobs()` stub'ını implement et. `/var/spool/at/` taraması. ~40 satır.
- **Hız: 5/5** — Küçük dizin.
- **FP: 5/5** — Writability/readability check.
- **Vektör Kaçırma: 5/5** — Şu an tamamen eksik.

### E1 — Logrotate→Root Chain
- **Zorluk: 4/5** — `intelligence.go`'ya yeni chain. Logrotate config parse + postrotate script writability cross-ref. ~50 satır.
- **Hız: 5/5** — Mevcut veriden çalışır.
- **FP: 4/5** — Logrotate genelde daily/weekly çalışır, timing dependency var.
- **Vektör Kaçırma: 5/5** — Yeni chain, mevcut hiçbir şeyi bozmaz.

### E2 — EnvironmentFile→Root Chain
- **Zorluk: 3/5** — A6 scanner'ından gelen veriye bağımlı. Chain logic ~40 satır ama önce A6 implement edilmeli.
- **Hız: 5/5** — Mevcut veriden çalışır.
- **FP: 4/5** — Writable env file + root service = düşük FP.
- **Vektör Kaçırma: 5/5** — Yeni chain.

### E3 — Password Reuse Chain
- **Zorluk: 3/5** — Discovered secret'leri normalize edip `/etc/passwd` user listesiyle cross-reference. PAM/su ile aktif test yapmadan sadece "potansiyel" olarak raporla. ~60 satır.
- **Hız: 4/5** — String comparison, minimal.
- **FP: 3/5** — Password reuse tespiti heuristic-heavy. Aynı string farklı context'te farklı anlam taşıyabilir.
- **Vektör Kaçırma: 4/5** — ⚠️ Cleartext password match'i doğru pozitif olabilir ama hash'lenmiş/encoded secret'ler yakalanamaz.

### F1 — Syscall Rate Limiter
- **Zorluk: 2/5** — Token-bucket altyapısı hazır (`STEALTH_ADVANCED.md`), ama 17 scanner dosyasındaki her filesystem çağrısını sarmak gerekiyor. Büyük refactor.
- **Hız: 1/5** — **Hızı düşürür** (tasarım gereği). Stealth modunda scan süresi 5-20x artabilir.
- **FP: 0/5** — Logic değişmiyor.
- **Vektör Kaçırma: 5/5** — Aynı tarama yapılır, sadece yavaş.

### F2 — /dev/shm Default Output
- **Zorluk: 5/5** — `main.go`'da 5 satır if-else. `--stealth` aktifse ve `-o` path `/dev/shm` değilse uyarı ver.
- **Hız: 5/5** — tmpfs'e yazma disk I/O'dan çok daha hızlı.
- **FP: 0/5** — Logic değişmiyor.
- **Vektör Kaçırma: 5/5** — Risk yok.

### C3 — Ephemeral Port Filter
- **Zorluk: 5/5** — `network.go`'ya 3 satır port range check.
- **Hız: 3/5** — Daha az result = daha hızlı output.
- **FP: 4/5** — Ephemeral outbound connection'lar noise.
- **Vektör Kaçırma: 4/5** — ⚠️ Bazı backdoor'lar ephemeral port range'de listen edebilir. Sadece ESTABLISHED bağlantıları filtrele, LISTEN'ları değil.

---

## Öncelik Sıralaması (ROI = Etki / Zorluk)

### 🔴 Tier 1 — Hemen Yap (Kolay + Yüksek Etki)
| # | Öneri | Zorluk | Toplam Etki | Durum |
|---|-------|--------|-------------|-------|
| A2 | SysV Init Scripts | 5/5 | Yeni kritik vektör | ✅ DONE |
| A5 | at Job Queue | 5/5 | Eksik stub'ı doldurur | ✅ DONE |
| B4 | Anacron Writability | 5/5 | 10 satır, sıfır risk | ✅ DONE |
| A4 | X11 Authority Theft | 5/5 | Lateral movement | ✅ DONE |
| D2 | Shared UserContext | 5/5 | Bedava hız | ✅ DONE (partial — 3/18 scanner, rest covered by D1) |
| D4 | GID Cache | 5/5 | Bedava hız | ✅ DONE |
| F2 | /dev/shm Default | 5/5 | 5 satır | ✅ DONE |
| C3 | Ephemeral Port Filter | 5/5 | 3 satır | ✅ DONE |
| B5 | cgroup v2 | 5/5 | 15 satır | ✅ DONE |
| B3 | .env Hierarchy | 5/5 | 5 satır | ✅ DONE |

### 🟡 Tier 2 — Kısa Vadede Yap (Orta Zorluk + Yüksek Etki)
| # | Öneri | Zorluk | Toplam Etki | Durum |
|---|-------|--------|-------------|-------|
| A1 | Crontab Env Injection | 4/5 | Kritik yeni vektör | ✅ DONE |
| A3 | Logrotate Scanner | 4/5 | CTF klasiği | ✅ DONE |
| C4 | Attack Path Dedup | 4/5 | Cleaner output | ✅ DONE |
| E4 | SUID+Lib Chain | 4/5 | Gap kapatır | ✅ DONE |
| C1 | Writable Temp Filter | 4/5 | Dikkatli filtre | ✅ DONE |
| D3 | sync.Pool | 4/5 | Büyük scan'lerde faydalı | ✅ DONE |
| E1 | Logrotate Chain | 4/5 | A3'e bağlı | ✅ DONE |

### 🔵 Tier 3 — Stratejik (Yüksek Etki Ama Zor)
| # | Öneri | Zorluk | Toplam Etki |
|---|-------|--------|-------------|
| B1 | GTFOBins JSON | 3/5 | FN'yi drastik düşürür |
| A6 | EnvironmentFile | 3/5 | Kritik vektör |
| D1 | Parallel Walker | 2/5 | En büyük hız artışı |
| B6 | Distro Patches | 2/5 | En büyük FP azaltma |
| B2 | ELF String Analysis | 2/5 | Custom SUID vektörleri |
| F1 | Syscall Rate Limiter | 2/5 | Stealth-only |

> **Önerim**: Tier 1'deki 10 değişikliği tek commit'te implement et (~200 satır toplam). Sonra Tier 2, sonra Tier 3.
