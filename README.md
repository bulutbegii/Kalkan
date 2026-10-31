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

Dış bağımlılık **yok** (yalnızca Python 3.11+ standart kütüphanesi).

```powershell
cd C:\Projects\kalkan
python -m kalkan.cli --help
```

Kalıcı komut istiyorsan:

```powershell
pip install -e .
kalkan --help
```

> `kalkan` paketi kurulmadan da çalışır; komutları **proje kökünden** `python -m kalkan.cli ...` şeklinde çalıştır.

---

## 3. Hızlı başlangıç (5 dakika)

### 3.1 Kapsam dosyası

`examples/scope.json` dosyasını kopyala, kendi laboratuvarına göre düzenle:

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

---

## 4. Araçları devreye alma

Hiçbiri zorunlu değil; kurdukça `coverage` yeşile döner.

| Araç | Kurulum (Windows) | Ne açar |
|---|---|---|
| **nmap** | `winget install Insecure.Nmap` veya [nmap.org/download](https://nmap.org/download) | T1046, T1595, T1592 |
| **nuclei** | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | T1595.002, T1190 |
| **Metasploit** | [rapid7.com/products/metasploit/download](https://www.rapid7.com/products/metasploit/download/) (Windows installer) | T1190, T1203 |
| **Shodan** | `setx SHODAN_API_KEY "..."` (yeni terminal gerekir) | T1590, T1596 |
| **Ollama** | `winget install Ollama.Ollama` | Router |

Doğrulama:

```powershell
nmap --version
nuclei -version
msfconsole -v
echo $env:SHODAN_API_KEY
ollama list
```

Kurulmayan araç `coverage` çıktısında **eksik** görünür ve `run` sırasında `unavailable` döner — sessizce yanlış sonuç üretmez.

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
├─ adapters/
│  ├─ base.py           Adapter: command()/parse()/run()/dry_run()
│  ├─ nmap.py           port_scan, service_version, vuln_script, host_discovery
│  ├─ nuclei.py         vuln_scan, web_template, misconfig_scan
│  ├─ shodan.py         passive_osint, host_lookup, exposure_lookup
│  ├─ msf.py            exploit_check, auxiliary_scan, exploit_run (.rc üretimi)
│  └─ llmprobe.py       llm_jailbreak_probe, llm_injection_probe, llm_leak_probe
├─ knowledge/
│  ├─ attack.py         STIX 2.1 yükleyici + yerel önbellek (~/.kalkan/attack)
│  ├─ atlas.py          ATLAS kataloğu (otomatik / manuel ayrımı)
│  ├─ mapping.py        ★ teknik → playbook → adım tablosu
│  └─ payloads.py       LLM prob korpusu
├─ orchestrator/
│  ├─ router.py         LLM → Intent (JSON şeması + kural yedeği)
│  ├─ planner.py        Intent → Plan (deterministik)
│  └─ executor.py       Plan → sonuç (scope → policy → audit → adaptör)
├─ cli.py               argparse arayüzü
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
cd C:\Projects\kalkan
python -m unittest discover -s tests -t . -v
```

43 test: kapsam kuralları (CIDR/domain/port/süre/risk), denetim zinciri (değiştirme/silme tespiti),
planlayıcı (risk sıralaması, eksik argüman, deduplikasyon, playbook tutarlılığı) ve executor
(scope ihlalinde durma, onay reddi, destructive bloğu, bağımlılık çözümü).

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

- [ ] `ffuf`, `httpx`, `amass` adaptörleri
- [ ] Playbook'ları YAML'dan yükleme (kod değiştirmeden genişletme)
- [ ] Sonuçları STIX 2.1 bundle olarak dışa aktarma (MISP/OpenCTI)
- [ ] `audit` kaydını GPG/HSM ile imzalama
- [ ] Router için yerel değerlendirme seti (niyet doğruluğu ölçümü)
- [ ] Çoklu hedef için paralel yürütme (şu an sıralı)
