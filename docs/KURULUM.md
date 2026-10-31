# Kurulum

> Bu dosya yalnızca **kurulum adımlarını** kapsar. Komut komut kullanım örnekleri için README'deki "Hızlı başlangıç" bölümüne bakın.

---

## 1. Ön koşullar

| Gereksinim | Kontrol komutu | Zorunlu mu |
|---|---|---|
| Python 3.11+ | `python --version` | Evet |
| Ollama | `ollama --version` | Router için (amaç sınıflandırıcı) |
| git | `git --version` | Depoyu indirmek için (ZIP de olur) |

Dış Python bağımlılığı **yoktur** — yalnızca standart kütüphane kullanılır.

---

## 2. Depoyu indirip çalıştırmak

```powershell
git clone https://github.com/bulutbegii/Kalkan.git
cd Kalkan

# Hızlı doğrulama
python -m kalkan.cli --help
```

Kalıcı `kalkan` komutu istersen (isteğe bağlı):

```powershell
pip install -e .
kalkan --help
```

> Her iki yöntemde de komutlar **proje kökünden** çalışır.
> `pip install` yapılmadan da `python -m kalkan.cli ...` şeklinde çalıştırılabilir.

---

## 3. Router modelini kurmak (Ollama)

Kalkan, kullanıcı niyetini yapılandırmak için yerel bir LLM router kullanır. Model tanımı `Modelfile` içinde hazır gelir:

```powershell
# 1) Ollama kurulu değilse:
winget install Ollama.Ollama

# 2) Temel modeli indir:
ollama pull qwen3:4b

# 3) Kalkan router modelini yarat:
ollama create kalkan-router -f Modelfile

# 4) Doğrula:
ollama list
```

Çıktıda `kalkan-router:latest` görülmelidir. Varsayılan endpoint `http://localhost:11434`'tur;
her komutta `--model` ve `--endpoint` ile geçersiz kılınabilir.

---

## 3.5 Metasploit (saldırı katmanı) — WSL2 önerilir

Gerçek istismar adımları (`exploit_run`, `exploit_check`, `auxiliary_scan`)
Metasploit gerektirir. Windows'ta Defender/MDM kurulumu sık sık engeller
(msf dosyaları HackTool imzası taşır); **en dertsiz yol WSL2'dir** ve Kalkan
bunu otomatik kullanır.

```powershell
# 1) WSL + Ubuntu (bir kez; sonra yeniden başlatma gerekebilir)
wsl --install -d Ubuntu
```
```bash
# 2) Ubuntu içinde Metasploit (resmi omnibus)
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall && sudo ./msfinstall
msfconsole        # ilk açılışta veritabanı sorar → "yes"; açılınca "exit"
```
```powershell
# 3) Windows tarafında doğrula (yeni terminal)
kalkan tools      # msf artık "hazır" görünmeli
```

Kalkan `msfconsole`'u önce **Windows PATH**'inde arar; bulamazsa **WSL
dağıtımlarını** tarar (docker-desktop gibi özel dağıtımları atlar) ve
msfconsole'u olan ilk gerçek dağıtımı seçip `wsl -d <distro> -e msfconsole`
ile çalıştırır; rc/spool yollarını `wslpath` ile çevirir. Hiçbir ayar
gerekmez.

> **Reverse shell ağı:** WSL2'nin kendi IP'si vardır. Win11 22H2+ için
> `C:\Users\<kullanıcı>\.wslconfig` içine `[wsl2]` + `networkingMode=mirrored`
> koyup `wsl --shutdown` yaparsan `lhost` = Windows makinenin IP'si olur.

> Windows'a native kurmakta ısrar edersen: Defender → Koruma geçmişi'nden
> Metasploit tespitine "Cihazda izin ver" + `C:\metasploit-framework` ve
> `%TEMP%` klasör istisnaları gerekir; MDM yönetilen cihazda bu çoğu zaman
> mümkün olmaz → WSL2'ye dön.

---

## 4. Kurulumdan sonra ilk kontrol

```powershell
python -m kalkan.cli --scope examples/scope.json tools
```

`tools`, hangi adaptörün hazır olduğunu listeler. Kurulmamış araçlar `unavailable` görünür — bu bir hata değil, beklenen davranıştır.

### Bilgi tabanını indirmek (isteğe bağlı ama önerilen)

Kalkan ATT&CK ve ATLAS bilgi tabanlarını resmi STIX dağıtımlarından indirip `~/.kalkan/` altına önbellekler:

```powershell
# ATT&CK enterprise (~55 MB): TAM icerik — 227 teknik + 479 alt, 15 taktik,
# 268 mitigasyon, ~17.600 prosedur ornegi (aciklama/nasil-yapildigi + tespit)
python -m kalkan.cli knowledge fetch

# Diger ATT&CK matrisleri (istege bagli)
python -m kalkan.cli knowledge fetch --domain mobile   # 78+47 teknik
python -m kalkan.cli knowledge fetch --domain ics      # 78+26 teknik

# ATLAS tam katalog (~1.6 MB): teknik + mitigation + case study
python -m kalkan.cli knowledge fetch --domain atlas

# kontrol: bir teknigin TAM icerigini goster (mitigasyon + prosedur ornekleri)
python -m kalkan.cli knowledge show --technique T1190
python -m kalkan.cli knowledge show --domain atlas --technique AML.T0051
```

Bu adım istenirse atlanabilir; temel komutlar (`tools`, `coverage`, `knowledge atlas`)
önbellek olmadan da çalışır.

### Test suite (isteğe bağlı):

```powershell
python -m unittest discover -s tests -v
```

---

## 5. Sık rastlanan sorunlar

| Belirti | Neden | Çözüm |
|---|---|---|
| `python` bulunamıyor | Python PATH'te değil | Kurulumda "Add to PATH" işaretle ya da PATH'e elle ekle |
| Router bağlanamıyor | Ollama servisi çalışmıyor | Ollama'yı başlat ya da `ollama serve` çalıştır |
| Araç `unavailable` | İlgili araç PATH'te değil | README "Araçları devreye alma" tablosundan kur |
| `expires geçti` uyarısı | Kapsam dosyası süresi dolmuş | `examples/scope.json` içindeki `expires` alanını gelecekte bir tarhe yap |

---

## 6. Kaldırma

```powershell
pip uninstall kalkan            # editable kurulumu geri al
ollama rm kalkan-router         # router modelini sil
Remove-Item -Recurse Kalkan     # kaynak kodu sil
```

Ollama kurulumunun kendisi sistemde kalabilir; başka araç tarafından kullanılmıyorsa kaldır.
