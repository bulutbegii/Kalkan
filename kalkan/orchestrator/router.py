"""LLM router - modelin tek isi niyeti yapisal hale getirmek.

Model serbest metin yazmaz, serbest komut uretmez. Sadece su soruyu
cevaplar: "hangi hedef, hangi teknikler?" Cevap JSON semasina zorlanir
(Ollama `format` alani), semaya uymayan cikti reddedilir.

Model yoksa/yanit vermezse kural tabanli yedek devreye girer; sistem
modelsiz de calisir.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from ..knowledge import mapping
from ..models import Intent


def _normalize_endpoint(raw: str) -> str:
    """OLLAMA_HOST 'host:port' seması olmadan gelebilir; http:// ekle."""
    raw = raw.strip().rstrip("/")
    if raw and not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    return raw or "http://localhost:11434"


DEFAULT_ENDPOINT = _normalize_endpoint(
    os.environ.get("KALKAN_ENDPOINT") or os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
)
DEFAULT_MODEL = os.environ.get("KALKAN_MODEL", "kalkan-router:latest")

INTENT_SCHEMA = {
    "type": "object",
    "properties": {
        "objective": {"type": "string"},
        "targets": {"type": "array", "items": {"type": "string"}},
        "techniques": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
    },
    "required": ["objective", "targets", "techniques"],
    "additionalProperties": False,
}

SUMMARY_SYSTEM = """Sen bir sizma testi asistanisin. Sana bir plan ve
calisma bulgularinin dokumu verilir. SADECE verilen bulgulara dayanarak,
somut ve bulgu-odakli bir TURKCE ozet yaz. Su yapiyi kullan:

Bulgular:
- Madde madde ne bulundu: acik port/servis, tespit edilen teknoloji/surum,
  zafiyet, eksik guvenlik basligi vb. Her maddenin basina onem derecesini
  koy: [kritik]/[yuksek]/[orta]/[dusuk]/[bilgi].

Gecilebilir (exploitable):
- Dogrulanmis/istismar edilebilir olanlari ACIKCA yaz: hangi parametre veya
  uc nokta, varsa hangi CVE. Boyle bir bulgu yoksa "dogrulanmis gecis yok" de.

Eksik / zayif:
- Eksik veya zayif noktalar (orn. eksik CSP/HSTS basligi, WAF yok, zayif TLS).

Sonraki adim: <tek satir, mantikli oneri>

KRITIK - durum kodlarini dogru yorumla:
- "unavailable" = ARAC KURULU DEGIL / API anahtari yok (orn. nmap PATH'te yok,
  SHODAN_API_KEY yok). Bu HEDEFLE ILGISIZDIR. "sunucu yanit vermedi",
  "erisilemez", "kapali" gibi sonuc CIKARMA; dogru yorum: "araci kurmak gerek".
- "dry-run" = komut uretildi ama CALISTIRILMADI (simulasyon).
- "ok" = gercekten calisti; bulgulari ozetle.
- "denied" = politika/kapsam reddetti.

Kurallar: uydurma, SADECE verilen bulgulara dayan; komut satiri yazma;
teknik kimliklerini (T1190, CVE-...) gerekiyorsa an. Kisa ve net; bulgu yoksa
"belirgin bulgu yok" de."""

SYSTEM_PROMPT = """Sen bir guvenlik orkestrasyon yonlendiricisisin.
Gorevin: kullanicinin istegini analiz edip SADECE asagidaki katalogdan
teknik secmek ve hedefleri cikarmak.

Kurallar:
- Katalogda olmayan teknik uydurma.
- Hicbir komut, komut satiri veya arac argumani yazma.
- Emin degilsen techniques bos dizi olsun.
- Sadece JSON dondur.

KATALOG:
{catalog}
"""

_KEYWORDS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("port", "tara", "scan", "servis", "servisler"), "T1046"),
    (("web", "http", "https", "uygulama", "site", "başlık", "header", "cms"), "T1190"),
    (("web", "uygulama", "teknoloji", "parmak izi", "fingerprint", "tech"), "T1592"),
    (("zafiyet", "vuln", "cve", "zayıflık"), "T1595.002"),
    (("exploit", "sömür", "istismar", "msf", "metasploit"), "T1190"),
    (("idor", "bola", "erişim kontrol", "erisim kontrol", "access control",
      "yetkisiz", "nesne referans", "broken access"), "T1190"),
    (("shodan", "pasif", "osint", "dışarıdan"), "T1596"),
    (("jailbreak", "prompt injection", "enjeksiyon"), "AML.T0051"),
    (("jailbreak", "kır", "bypass", "kandır"), "AML.T0054"),
    (("sızıntı", "leak", "sistem promptu", "system prompt"), "AML.T0057"),
    (("llm", "model", "agent", "ajan"), "AML.T0054"),
)

_TARGET_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
    r"|https?://[^\s\"']+"
    r"|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)


class Router:
    def __init__(
        self,
        endpoint: str = DEFAULT_ENDPOINT,
        model: str = DEFAULT_MODEL,
        timeout: int = 120,
    ):
        self.endpoint = _normalize_endpoint(endpoint)
        self.model = model
        self.timeout = timeout

    def models(self) -> list[str]:
        """Ollama'da kurulu model adları; ulaşılamazsa boş liste."""
        try:
            with urllib.request.urlopen(f"{self.endpoint}/api/tags", timeout=5) as resp:
                if resp.status != 200:
                    return []
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            return []
        return [m.get("name", "") for m in data.get("models", []) if m.get("name")]

    def available(self) -> bool:
        return bool(self.models())

    def resolve_model(self) -> tuple[str, str | None]:
        """Yapılandırılan model kuruluysa onu, değilse kurulu ilk modeli seç.

        İkinci değer, kullanıcıya gösterilecek bir uyarı (yoksa None)."""
        installed = self.models()
        if not installed:
            return self.model, None
        wanted = {self.model, self.model.split(":")[0]}
        for name in installed:
            if name in wanted or name.split(":")[0] in wanted:
                return name, None
        chosen = installed[0]
        return chosen, (
            f"yapılandırılan model '{self.model}' kurulu değil; '{chosen}' kullanıldı "
            f"(kurulu: {', '.join(installed)})"
        )

    def route(self, text: str) -> Intent:
        if self.available():
            try:
                return self._route_llm(text)
            except (urllib.error.URLError, OSError, TimeoutError, ValueError, KeyError) as exc:
                installed = self.models()
                hint = f" (kurulu modeller: {', '.join(installed)})" if installed else ""
                intent = self._route_rules(text)
                return Intent(
                    objective=intent.objective,
                    targets=intent.targets,
                    techniques=intent.techniques,
                    rationale=intent.rationale,
                    source="fallback",
                    notes=(f"LLM yönlendirmesi başarısız ({exc}){hint}; kural tabanlı yedek kullanıldı",),
                )
        intent = self._route_rules(text)
        return Intent(
            objective=intent.objective,
            targets=intent.targets,
            techniques=intent.techniques,
            rationale=intent.rationale,
            source="fallback",
            notes=(
                f"LLM uç noktası ({self.endpoint}) erişilemez; kural tabanlı yedek kullanıldı",
            ),
        )

    def summarize(self, prompt: str, timeout: int | None = None) -> str:
        """Plan/sonuc dokumunden serbest TURKCE ozet uret (JSON degil).

        Model yoksa/yanit vermezse bos string doner; cagiran taraf bunu
        sessizce atlar (ozet katmani REPL'i asla dusurmemeli)."""
        if not self.available():
            return ""
        model, _ = self.resolve_model()
        body = {
            "model": model,
            "stream": False,
            "think": False,
            "options": {"temperature": 0.3, "num_predict": 512},
            "messages": [
                {"role": "system", "content": SUMMARY_SYSTEM},
                {"role": "user", "content": prompt},
            ],
        }
        req = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            return ""
        return (payload.get("message", {}).get("content") or "").strip()

    def _route_llm(self, text: str) -> Intent:
        model, warn = self.resolve_model()
        catalog = "\n".join(
            f"- {tid}: {mapping.get(tid).name} ({mapping.get(tid).tactic})" for tid in mapping.techniques()
        )
        body = {
            "model": model,
            "stream": False,
            "think": False,
            "format": INTENT_SCHEMA,
            "options": {"temperature": 0.0, "num_predict": 512},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT.format(catalog=catalog)},
                {"role": "user", "content": text},
            ],
        }
        req = urllib.request.Request(
            f"{self.endpoint}/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        content = (payload.get("message", {}).get("content") or "").strip()
        if not content:
            raise ValueError("model boş yanıt döndürdü (num_predict/think ayarını kontrol et)")
        data = json.loads(content)
        intent = self._validate(data, source_text=text)
        if warn:
            intent = Intent(
                objective=intent.objective,
                targets=intent.targets,
                techniques=intent.techniques,
                rationale=intent.rationale,
                source=intent.source,
                notes=(warn, *intent.notes),
            )
        return intent

    def _validate(self, data: dict, source_text: str = "") -> Intent:
        known = set(mapping.techniques())
        notes: list[str] = []
        accepted: list[str] = []
        for raw in data.get("techniques", []):
            token = str(raw).strip().replace("ATT&CK:", "").replace("ATLAS:", "").strip()
            m = re.match(r"[A-Za-z]+\.?T\d+(?:\.\d+)?|T\d+(?:\.\d+)?", token)
            tid = (m.group(0) if m else token).upper()
            if tid in known:
                if tid not in accepted:
                    accepted.append(tid)
            else:
                notes.append(f"katalog dışı teknik reddedildi: {raw}")
        targets: list[str] = []
        for t in data.get("targets", []):
            t = str(t).strip()
            if not t:
                continue
            m = _TARGET_RE.search(t)
            if m:
                targets.append(m.group(0))
        if not targets and source_text:
            targets = [m.group(0) for m in _TARGET_RE.finditer(source_text)]
        targets = list(dict.fromkeys(targets))
        if not targets:
            notes.append("hedef çıkarılamadı")
        return Intent(
            objective=str(data.get("objective", "")).strip(),
            targets=tuple(targets),
            techniques=tuple(accepted),
            rationale=str(data.get("rationale", "")).strip(),
            source="llm",
            notes=tuple(notes),
        )

    def _route_rules(self, text: str) -> Intent:
        lowered = text.lower()
        techniques: list[str] = []
        for keywords, tid in _KEYWORDS:
            if any(k in lowered for k in keywords) and tid not in techniques:
                techniques.append(tid)
        targets = [m.group(0) for m in _TARGET_RE.finditer(text)]
        targets = [t for t in dict.fromkeys(targets) if not t.lower().endswith((".json", ".yaml", ".txt"))]
        return Intent(
            objective=text.strip()[:200],
            targets=tuple(targets),
            techniques=tuple(techniques),
            rationale="kural tabanlı eşleştirme",
            source="fallback",
        )
        return Intent(
            objective=text.strip()[:200],
            targets=tuple(targets),
            techniques=tuple(techniques),
            rationale="kural tabanlı eşleştirme",
            source="fallback",
        )
