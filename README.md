# Kalkan

**ATT&CK + ATLAS haritalı, kapsam (scope) ve denetim (audit) zorlamalı güvenlik orkestrasyon çekirdeği.**

> 📖 Kurulum adımları için: [`docs/KURULUM.md`](docs/KURULUM.md).

Kalkan bir "otomatik hacker" değil; **yetkilendirilmiş testleri disipline eden bir çalıştırma katmanı**.
Model (E2B / Qwen3 4B) yalnızca *niyeti* yapılandırır. Komutu, kapsamı ve denetimi kod belirler.

```
"10.10.10.20'de portları tara, sonra zafiyet bak"
        │
        ▼
   Router (LLM)  ──►  Intent { targets, techniques }   ← sadece JSON, komut yok
        │
        ▼
   Planner       ──►  Playbook (T1046 → nmap, nmap)    ← statik tablo, model değiştiremez
        │
        ▼
   ScopeGuard    ──►  hedef yetkili mi? süre geçti mi? risk tavanı?
        │
        ▼
   Policy        ──►  intrusive ise onay var mı? destructive kapalı mı?
        │
        ▼
   Executor      ──►  adaptör.run()  ──►  AuditLog (hash zinciri)
```

---

## 1. Neden bu tasarım

LLM'e "şu komutu çalıştır" dedirtmek üç sorun üretir: **halüsinasyon**, **kapsam ihlali**, **iz sürülemezlik**.
Kalkan bu üçünü yapısal olarak keser:

| Risk | Çözüm |
|---|---|
| Model olmayan komut uydurur | Model yalnızca `objective`, `targets`, `techniques` döndürür (JSON şeması zorunlu). Teknik → araç eşlemesi `knowledge/mapping.py` içinde sabittir. |
| Kapsam dışına çıkar | Her aksiyon `ScopeGuard.check()`'ten geçer: CIDR/domain allowlist, deny listesi, port listesi, son kullanma tarihi, risk tavanı. |
| Onaysız intrusive işlem | `Policy`: `intrusive` ve üstü varsayılan olarak onay ister; `destructive` varsayılan **kapalı**. |
| "Ne yaptığı belli değil" | Her adım hash zincirli `AuditLog`'a yazılır; `audit verify` tek satır değişikliğini yakalar. |
| Araç yoksa çöker | Adaptörler `dry-run` / `unavailable` durumuna düşer; iskelet araç kurmadan da çalışır. |

**Model hiçbir zaman `subprocess` çağırmaz.** `Router` sınıfı sadece HTTP ile modele soru sorar ve dönen JSON'u doğrular.

---

## 2. Kurulum

Çekirdeğin dış bağımlılığı **yok** (yalnızca Python 3.11+ standart kütüphanesi). Harici tarama araçları (nmap, nuclei…) isteğe bağlıdır — bkz. §4.

```powershell
cd C:\Users\<kullanici>\kalkan
pip install -e .        # 'kalkan' komutunu PATH'e kurar (önerilir)
kalkan --help
```

> Kurmadan da çalışır: proje kökünden `python -m kalkan.cli ...`.

### Masaüstü kısayolu (cd/komut ezberlemeden)

`Kalkan.bat` çift tıklanınca menü arayüzünü açar; kendi klasörüne geçip
araç yollarını ve API anahtarlarını (registry'den) otomatik yükler, yani
"stale terminal" sorunundan etkilenmez. Masaüstüne `Kalkan.lnk` kısayolu
oluşturup bu `.bat`'i hedef gösterebilirsin.

### Üç kullanım biçimi

| Biçim | Komut | Ne zaman |
|---|---|---|
| **Menü arayüzü** | `kalkan` (argümansız) | Ne yaptığını görüp seçerek ilerlemek |
| **Sohbet (REPL)** | `kalkan chat --target <hedef>` | Modelle konuşarak tarama/plan |
| **Tek komut** | `kalkan run --technique … --target …` | Betik/otomasyon |

---

## 3. Hızlı başlangıç (5 dakika)

### 3.0 Sohbetle kullanım (önerilen)

```powershell
kalkan chat --target example.com
```

```
kalkan(example.com)> web uygulamasını tara
   ... model düşünüyor → plan → passive/active OTOMATIK çalışır
   🗒  (Türkçe özet + "Sonraki adım:" önerisi)
   rapor: reports\example.com_20261031-152033.md
```

Risk modeli: **passive/active otomatik**, **intrusive/destructive satır-içi onay** ister.
Slash komutları: `/target`, `/risk`, `/auto`, `/ozet`, `/plan`, `/feed`, `/scope [add <hedef>]`, `/help`, `/quit`.
Başlatma bayrakları: `--from-feed` (canlı CVE önerileri), `--dry-run`, `--max-risk`, `--no-summary`, `--no-report`.

### 3.1 Kapsam dosyası

`examples/scope.json` dosyasını kopyala (`scope.json` olarak), kendi laboratuvarına göre düzenle.
Hedef eklemenin hızlı yolu — elle JSON açmadan:

```powershell
kalkan scope add example.com        # domain/ip/cidr otomatik ayrılır
kalkan scope show
```

> `scope add`, o hedefi test etmeye **yetkili olduğun beyanıdır**; Kalkan bu beyana güvenir.

Örnek kapsam:

```json
{
  "name": "Lab",
  "authorized_by": "Yetkili Test Sorumlusu",
  "ticket": "LAB-2026-001",
  "expires": "2027-12-31T23:59:59Z",
  "allow_cidrs": ["127.0.0.1/32", "10.10.10.0/24"],
  "allow_domains": ["example.com", "localhost"],
  "allow_ports": [80, 443, 8080, 8443, 11434],
  "deny_cidrs": ["10.10.10.1/32"],
  "max_risk": "intrusive"
}
```

* `expires` geçmişse **hiçbir şey çalışmaz**.
* `deny_cidrs` her zaman kazanır (allow içinde olsa bile).
* `allow_ports` boş bırakılırsa tüm portlar serbest; doluysa yalnızca listedekiler.
  LLM probu `http://localhost:11434` hedeflediği için **11434'ü eklemeyi unutma**.
* `max_risk`: `passive` < `active` < `intrusive` < `destructive`.

### 3.2 Durumu gör

```powershell
python -m kalkan.cli --scope examples/scope.json tools
python -m kalkan.cli coverage
python -m kalkan.cli knowledge atlas
```

`tools` hangi adaptörün hazır olduğunu, `coverage` hangi tekniğin uçtan uca çalışabildiğini söyler.

### 3.3 Plan üret (hiçbir şey çalışmaz)

```powershell
python -m kalkan.cli --scope examples/scope.json plan --technique T1046 --target 10.10.10.20
python -m kalkan.cli --scope examples/scope.json plan --tactic reconnaissance --target 10.10.10.20
```

### 3.4 Kuru çalıştırma (komutları göster, çalıştırma)

```powershell
python -m kalkan.cli --scope examples/scope.json run --dry-run --yes `
  --technique T1046 --target 10.10.10.20
```

### 3.5 Gerçek çalıştırma

```powershell
python -m kalkan.cli --scope examples/scope.json run --technique T1046 --target 10.10.10.20
```

Intrusive adım geldiğinde terminalde onay ister. `--yes` ile atlanır (**dikkat**).

### 3.6 Denetim kaydını doğrula

```powershell
python -m kalkan.cli audit verify --audit .kalkan/audit.jsonl
python -m kalkan.cli audit tail --count 5
```

### 3.7 Tarama raporları (otomatik)

Her **gerçek** çalıştırmadan sonra (sohbet, `run`, menü "Web uygulama taraması")
bir Markdown rapor yazılır:

```
reports/<hedef>_<YYYYAAGG-SSDDSS>.md
```

İçerik: plan adımları tablosu · adım sonuçları · keşifler (açık portlar, WAF,
bulgular) · (sohbette) model özeti · plan notları. Hedef+tarih isimlendirme
geçmişe dönük arşiv verir. `--dry-run`'da yazılmaz, `--no-report` ile kapatılır.
`reports/` git'e girmez (hedef bilgisi içerir).

### 3.8 Canlı besleme — CVE/CVSS + ATT&CK/ATLAS akışı

NVD + CISA KEV + FIRST EPSS'i birleştirip 0–100 öncelik skoruyla izler;
CVE'yi CWE→ATT&CK tekniği→playbook'a köprüler.

```powershell
kalkan feed run --once          # tek senkron (NVD_API_KEY ile hız limiti açılır)
kalkan feed start               # arka plan daemon
kalkan feed stream              # canlı NDJSON olay akışı (tail -f)
kalkan feed tail                # son olaylar
kalkan feed status              # depo/daemon durumu
```

Plan/sohbette `--from-feed`: hedefe/ürüne dair trend KEV/kritik CVE'leri
tekniklere çevirip plana önerir; eşleşen CVE'yi nuclei `-id` ve (varsa) MSF
`module=` argümanına bağlar.

---

## 4. Araçları devreye alma

Hiçbiri zorunlu değil; kurdukça `kalkan tools` / `coverage` yeşile döner. Araç yoksa adım `unavailable`/`dry-run`'a düşer — sessizce yanlış sonuç üretmez.

| Araç | Kurulum (Windows) | Ne açar |
|---|---|---|
| **nmap** | `winget install Insecure.Nmap` (Npcap dahil) | T1046, T1595, T1592 — port/servis |
| **nuclei** | GitHub release `.zip` → PATH; sonra `nuclei -update-templates` | T1595.002, T1190 — şablon tarama |
| **httpx** | ProjectDiscovery GitHub release `.zip` → PATH | T1592 — tech-detect/probe |
| **ffuf** | `winget install ffuf.ffuf` ya da GitHub release | içerik/parametre keşfi |
| **dalfox** | GitHub release `.zip` → PATH | XSS (intrusive, opt-in) |
| **sqlmap** | `pip install sqlmap` | SQLi (intrusive, opt-in) |
| **wafw00f** | `pip install wafw00f` | WAF/CDN tespiti |
| **arjun** | `pip install arjun` | parametre keşfi |
| **nikto** | StrawberryPerl + `sullo/nikto` klonu + `nikto` sarmalayıcısı | web yanlış-yapılandırma |
| **Metasploit** | [resmi installer](https://windows.metasploit.com/metasploitframework-latest.msi) (Defender istisnası gerekebilir) | T1190, T1203 |
| **Shodan** | `setx SHODAN_API_KEY "..."` (yeni terminal) | T1590, T1596 — pasif OSINT |
| **NVD** | `setx NVD_API_KEY "..."` | feed CVE senkron hız limiti |
| **Ollama** | `winget install Ollama.Ollama` | Router + Türkçe özet |

> **Go araçları (nuclei/httpx/ffuf/dalfox):** Go kuruluysa `go install …@latest`;
> değilse resmi GitHub release'inden `windows_amd64.zip` indirip içindeki `.exe`'yi
> PATH'teki bir klasöre (ör. `%USERPROFILE%\tools\bin`) koy.
> **nuclei** ilk kullanımda şablon ister: `nuclei -update-templates` (GitHub API
> limiti yerse `git clone https://github.com/projectdiscovery/nuclei-templates`
> → `%USERPROFILE%\nuclei-templates`).

Doğrulama: `kalkan tools` (hepsini tek bakışta), ya da `nmap --version`, `nuclei -version`, `echo $env:SHODAN_API_KEY`, `ollama list`.

> **API anahtarları koda/`scope.json`'a değil, ortam değişkenine girer.** `.env`
> okunmaz; `setx` ile User ortamına yazılır ve **yeni** terminal/kısayol görür.
> `Kalkan.bat` bunları registry'den kendisi yükler.

---

## 5. Metasploit kullanımı

Varsayılan mod **`check`**: modül hedefe uygulanabilir mi diye sorar, exploit çalıştırmaz.

```powershell
# 1) modülü doğrula (intrusive → onay ister)
python -m kalkan.cli --scope examples/scope.json run --yes `
  --technique T1190 --target 10.10.10.20 `
  --module auxiliary/scanner/smb/smb_version

# 2) exploit (yalnızca açıkça istersen)
python -m kalkan.cli --scope examples/scope.json run `
  --technique T1190 --target 10.10.10.20 `
  --module exploit/windows/smb/ms17_010_eternalblue `
  --mode run --allow-intrusive
```

Üretilen `.rc` dosyası sonuç içinde `rc_script` olarak döner; denetim için saklanabilir.
`--allow-destructive` verilmedikçe `destructive` seviyesindeki hiçbir aksiyon geçmez.

---

## 6. LLM / ajan testleri (ATLAS + ATT&CK AI teknikleri)

Kalkan kendi modelini/ajanını da test eder. Hedef bir Ollama ya da OpenAI uyumlu uç nokta:

```powershell
# Jailbreak (AML.T0054)
python -m kalkan.cli --scope examples/scope.json run --yes `
  --technique AML.T0054 --target http://localhost:11434

# Prompt injection (AML.T0051 / ATT&CK T1699, T1698)
python -m kalkan.cli --scope examples/scope.json run --yes `
  --technique AML.T0051 --target http://localhost:11434

# Sistem promptu sızıntısı (AML.T0057) — canary işaretçisi ile
python -m kalkan.cli --scope examples/scope.json run --yes `
  --technique AML.T0057 --target http://localhost:11434
```

Çıktıda `complied / refused / canary_leaks` sayıları ve her probun yanıtı bulunur.
Sistem promptuna `KALKAN-CANARY-7f3a` yerleştirilir; yanıtta görünürse sızıntı vardır.

Farklı uç nokta/model:

```powershell
python -m kalkan.cli run --dry-run --yes --technique AML.T0054 `
  --target http://localhost:11434 `
  --endpoint http://localhost:11434 --model qwen3:4b
```

> `llmprobe` adaptörünün `endpoint`, `model`, `api` (`ollama` | `openai`), `canary`, `system`
> argümanları vardır. OpenAI uyumlu sunucu için plan üretirken `args` üzerinden `api: openai` geçilmelidir.

### Bilgi tabanını güncellemek (ATT&CK + ATLAS)

Kalkan iki bilgi tabanını da **resmi STIX dağıtımlarından** besler; API anahtarı gerekmez:

```powershell
# ATT&CK enterprise (~55 MB): tum teknikler, aciklama + tespit notlariyla
python -m kalkan.cli knowledge fetch
python -m kalkan.cli knowledge show --technique T1046
python -m kalkan.cli knowledge search -q "port scan"

# ATLAS tam katalog (~1.6 MB): teknik + mitigation + case study
python -m kalkan.cli knowledge fetch --domain atlas
python -m kalkan.cli knowledge show --domain atlas --technique AML.T0051
python -m kalkan.cli knowledge search -q "jailbreak" --domain atlas

# kuretilmis test-edilebilir cekirdek (cok kucuk, ag parcaksi, cevrimdisi)
python -m kalkan.cli knowledge atlas
```

- Kaynak: `mitre-attack/attack-stix-data` ve `mitre-atlas/atlas-data` GitHub depoları (resmi).
- Önbellek: `~/.kalkan/attack/` ve `~/.kalkan/atlas/`; `--force` ile yeniden indirir.
- `knowledge show --domain atlas` çıktısında tekniğin açıklaması, tüm
  mitigasyonları (AML.M…), onu kullanan case study'ler ve kuretilmiş
  çekirdeğdeki test yöntemi gösterilir.
- Diğer ATT&CK domain'leri: `--domain mobile`, `--domain ics`.
- Arama boşlukla ayrılan kelimeleri VE olarak değerlendirir; isim
  eşleşmeleri önce, açıklama eşleşmeleri sonra gelir.

---

## 7. Modeli orkestratör olarak bağlamak

Router üç adımda devreye girer:

1. `Router.available()` → `GET /api/tags` ile Ollama'yı yoklar.
2. Varsa `POST /api/chat` + **JSON şeması** (`format`) ile niyet ister.
3. Şema dışı / katalog dışı teknik dönerse reddeder; uç nokta yoksa **kural tabanlı yedek** çalışır.

```powershell
# Model olmadan da çalışır (fallback)
python -m kalkan.cli router "10.10.10.20 portlarini tara ve zafiyet bak"

# Model ile
ollama pull qwen3:4b
python -m kalkan.cli router "10.10.10.20 portlarini tara" --model qwen3:4b
```

### 8 GB RAM için model seçimi

| Model | Yaklaşık bellek (Q4) | Not |
|---|---|---|
| `gemma3n:e2b` / E2B sınıfı | ~5–6 GB | 8 GB'ta dar; diğer uygulamaları kapat |
| `qwen3:4b` (Q4_K_M) | ~2.8–3.5 GB | **önerilen**: router için yeterli, yer bırakır |
| `qwen2.5:3b-instruct` | ~2 GB | en hızlı, kalite biraz düşük |

Router'ın işi yaratıcılık değil **sınıflandırma**; küçük ve deterministik model yeterlidir.
`temperature=0.0` ve `num_predict=400` sabittir.

### İsteğe bağlı: sistem promptunu gömmek

```
# Modelfile
FROM qwen3:4b
PARAMETER temperature 0
PARAMETER num_ctx 4096
SYSTEM """
Sen bir güvenlik orkestrasyon yönlendiricisisin.
Sadece verilen katalogdan teknik seç, hedef çıkar, JSON döndür.
Komut yazma. Emin değilsen techniques boş olsun.
"""
```

```powershell
ollama create kalkan-router -f Modelfile
python -m kalkan.cli router "10.10.10.20 port tara" --model kalkan-router
```

**Varsayılan model/uç nokta.** Kodun varsayılanı artık `kalkan-router:latest`
ve `http://localhost:11434`. Her seferinde `--model` yazmamak için ortam
değişkeni ile de ayarlayabilirsin:

```powershell
$env:KALKAN_MODEL = "kalkan-router:latest"   # veya qwen3:4b
$env:KALKAN_ENDPOINT = "http://localhost:11434"
```

Yapılandırılan model Ollama'da kurulu değilse, router kurulu ilk modele düşer
ve bunu `notes` içinde bildirir. "Thinking" modelleri (Qwen3.5 vb.) için
router isteği `think: false` ile gönderir; yoksa model tüm bütçeyi düşünmeye
harcayıp boş JSON döndürür.

---

## 8. Mimari

```
kalkan/
├─ models.py            Action, ActionResult, Plan, Intent, Risk
├─ scope.py             Scope, ScopeGuard, parse_target, ScopeViolation
├─ policy.py            Policy, PolicyDenied (onay eşiği)
├─ audit.py             AuditLog (SHA-256 hash zinciri, verify/tail)
├─ registry.py          ToolSpec, Registry (yetenek → adaptör)
├─ report.py            tarama → Markdown rapor (reports/<hedef>_<tarih>.md)
├─ adapters/
│  ├─ base.py           Adapter: command()/parse()/run()/dry_run()
│  ├─ nmap.py           port_scan (-sT), service_version, vuln_script, host_discovery
│  ├─ nuclei.py         vuln_scan, web_template (cve_id→-id), misconfig_scan
│  ├─ httpx.py          http_probe, tech_detect
│  ├─ ffuf.py / arjun.py / dalfox.py / nikto.py / wafw00f.py
│  ├─ webprobe.py       security_headers, cors_check, http_methods, tls_inspect…
│  ├─ sqlmap.py         sqli_check (opt-in: verify)
│  ├─ shodan.py         passive_osint (domain→IP), host_lookup, exposure_lookup
│  ├─ msf.py            exploit_check, auxiliary_scan, exploit_run (.rc üretimi)
│  └─ llmprobe.py       llm_jailbreak_probe, llm_injection_probe, llm_leak_probe…
├─ knowledge/
│  ├─ attack.py         ATT&CK STIX 2.1 yükleyici + önbellek (~/.kalkan/attack)
│  ├─ atlas.py          ATLAS kataloğu (otomatik / manuel ayrımı)
│  ├─ mapping.py        ★ teknik → playbook → adım tablosu
│  ├─ bridge.py         CVE(CWE) → ATT&CK/ATLAS tekniği + CVE→MSF modülü
│  ├─ vuln.py / cvss.py CVE/CVSS/EPSS/KEV istihbaratı, öncelik skoru
│  ├─ rules.py          tespit kuralı kimlikleri
│  └─ payloads.py       LLM prob korpusu
├─ feeds/
│  ├─ events.py         FeedEvent + JSONL/stdout/webhook sinkleri, tail -f
│  ├─ scheduler.py      FeedDaemon (vuln/attack/atlas bağımsız periyot)
│  └─ suggest.py        canlı CVE → teknik/MSF önerisi (router/planner)
├─ orchestrator/
│  ├─ router.py         LLM → Intent (JSON şeması + kural yedeği) + Türkçe özet
│  ├─ planner.py        Intent → Plan (deterministik)
│  └─ executor.py       Plan → sonuç (scope → policy → audit → adaptör)
├─ cli.py               argparse: home, chat, plan, run, scope, feed, vuln, knowledge, …
├─ Kalkan.bat           masaüstü başlatıcı (menü)
└─ examples/scope.json
```

### Kapsanan teknikler

**ATT&CK:** T1595, T1595.001, T1595.002, T1590, T1596, T1046, T1592, T1190, T1203, T1698, T1699
**ATLAS:** AML.T0051, AML.T0054, AML.T0057 (otomatik) + 5 teknik manuel olarak belgelenmiş

`knowledge fetch` ile güncel ATT&CK STIX verisi iner (enterprise/mobile/ics); `knowledge show --technique T1046`
açıklama, taktik, platform ve varsa playbook'u gösterir.

---

## 9. Genişletme

### 9.1 Yeni araç adaptörü

```python
# kalkan/adapters/ffuf.py
from ..models import Action, Risk
from ..registry import ToolSpec
from .base import Adapter

class FfufAdapter(Adapter):
    spec = ToolSpec(
        name="ffuf",
        capabilities=("content_discovery",),
        risk=Risk.ACTIVE,
        binary="ffuf",
        description="Dizin/içerik keşfi",
    )

    def command(self, action: Action) -> list[str]:
        return ["ffuf", "-u", f"{action.target}/FUZZ",
                "-w", action.args.get("wordlist", "wordlist.txt"),
                "-of", "json", "-o", "-"]

    def parse(self, stdout: str, action: Action) -> dict:
        import json
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return {}
        return {"found": [r.get("url") for r in data.get("results", [])]}
```

Sonra `kalkan/adapters/__init__.py` içindeki `_ADAPTERS` demetine ekle.

### 9.2 Yeni playbook

```python
# kalkan/knowledge/mapping.py içindeki _PLAYBOOKS demetine
Playbook(
    technique="T1083",
    name="File and Directory Discovery",
    tactic="discovery",
    framework="attack",
    steps=(Step("content_discovery", "ffuf", Risk.ACTIVE, {"wordlist": "common.txt"}),),
    detection="Web sunucu loglarında 404 patlaması",
    evidence=("found",),
),
```

Kurallar:
* `Step.capability` mutlaka adaptörün `spec.capabilities` içinde olmalı (test bunu zorlar).
* `Step.required` doldurulmamışsa adım **atlanır** ve plan notuna yazılır (ör. `module`).
* Bir adımın çıktısını sonrakine `"$open_ports"` gibi bağlayabilirsin; `Executor` çözer.

---

## 10. Testler

```powershell
python -m pytest tests/ -q          # veya: python -m unittest discover -s tests -t .
```

104 test: kapsam kuralları (CIDR/domain/port/süre/risk + `scope add`), denetim zinciri
(değiştirme/silme tespiti), planlayıcı (risk sıralaması, eksik argüman, deduplikasyon,
playbook tutarlılığı), executor (scope ihlali, onay reddi, destructive bloğu, bağımlılık
çözümü), CVE→ATT&CK köprüsü, feed daemon/olay akışı, rapor üretimi, nuclei `cve_id`/nmap
`-sT`/shodan domain→IP, ve CLI varsayılan-komut/chat-shim davranışı.

---

## 11. Sınırlar ve etik

* Kalkan **yalnızca yetkilendirilmiş** hedeflerde kullanılmak üzere tasarlandı. `scope.json` bir yetki belgesidir;
  gerçek bir imza/onay sürecinin yerine geçmez.
* `--yes` ve `--allow-destructive` üretim ortamlarında kullanılmamalı.
* LLM prob korpusu kendi modelini ölçmek içindir; üçüncü taraf modellere izinsiz uygulanmamalı.
* Denetim kaydı hash zinciriyle **değiştirilemezlik kanıtı** verir, ancak dosyayı tamamen silen bir saldırgana karşı
  koruma sağlamaz. Üretimde kaydı ayrı bir makineye/SIEM'e gönder ve periyodik olarak `audit verify` çalıştır.

---

## 12. Yol haritası

- [x] `ffuf`, `httpx`, `dalfox`, `sqlmap`, `wafw00f`, `arjun`, `nikto`, `webprobe` adaptörleri
- [x] Canlı CVE/CVSS/KEV/EPSS beslemesi + CWE→ATT&CK köprüsü (`feeds/`, `bridge.py`)
- [x] Sohbet (REPL) + menü arayüzü + masaüstü başlatıcı + Türkçe özet
- [x] Tarama sonrası otomatik Markdown rapor (`report.py`)
- [ ] nikto Windows checkout sorunu (symlink/`ö`-profil) kalıcı çözümü
- [ ] Playbook'ları YAML'dan yükleme (kod değiştirmeden genişletme)
- [ ] Sonuçları STIX 2.1 bundle olarak dışa aktarma (MISP/OpenCTI)
- [ ] `audit` kaydını GPG/HSM ile imzalama
- [ ] Çoklu hedef için paralel yürütme (şu an sıralı)
