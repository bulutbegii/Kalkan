"""Kurulu Metasploit'in modul katalogundan CVE -> modul indeksi.

msf, `modules_metadata_base.json` icinde TUM modullerin meta verisini
(referanslar dahil) tutar. Bunu bir kez okuyup CVE -> modul tersine
indeksini kurar ve `~/.kalkan/msf/cve_modules.json` altina onbellekler.
Boylece canli besleme/korelasyon, kurasyonlu 15 CVE yerine msf'in
destekledidigi BINLERCE CVE icin gercek modul onerebilir.

msf WSL'de kuruluysa dosya `wsl -d <distro> -e cat ...` ile okunur
(distro tespiti msf adaptorunden gelir). msf yoksa indeks bostur ve
onbelleklenmez (sonra kurulunca tekrar denenir).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

_WSL_ENV = {**os.environ, "WSL_UTF8": "1"}
_CACHE = Path.home() / ".kalkan" / "msf" / "cve_modules.json"

_METADATA_PATHS = (
    "/opt/metasploit-framework/embedded/framework/db/modules_metadata_base.json",
    "/usr/share/metasploit-framework/db/modules_metadata_base.json",
    "/usr/lib/metasploit-framework/db/modules_metadata_base.json",
    "$HOME/.msf4/store/modules_metadata.json",
)

_INDEX: dict[str, list[str]] | None = None


def _read_metadata_raw() -> str | None:
    """modules_metadata_base.json icerigini (ham JSON) dondur; yoksa None."""
    from ..adapters.msf import MetasploitAdapter

    msf = MetasploitAdapter()
    runner = msf._runner()
    if runner == "wsl":
        distro = msf._wsl_distro
        for path in _METADATA_PATHS:
            try:
                r = subprocess.run(
                    ["wsl", "-d", distro, "-e", "sh", "-lc", f"cat {path} 2>/dev/null"],
                    capture_output=True, text=True, timeout=90, env=_WSL_ENV,
                )
                if r.returncode == 0 and r.stdout.strip().startswith("{"):
                    return r.stdout
            except (OSError, subprocess.SubprocessError):
                continue
    elif runner == "native":
        import shutil
        exe = shutil.which("msfconsole")
        if exe:
            base = Path(exe).resolve().parent.parent
            cand = base / "embedded" / "framework" / "db" / "modules_metadata_base.json"
            if cand.exists():
                try:
                    return cand.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
    return None


def _parse_references(meta: dict) -> list[str]:
    """Bir modulun referanslarindan CVE kimliklerini cikar (format toleransli)."""
    cves: list[str] = []
    for ref in meta.get("references", []) or []:
        if isinstance(ref, str):
            s = ref.strip().upper()
            if s.startswith("CVE-"):
                cves.append(s)
            elif s.startswith("CVE,"):
                cves.append("CVE-" + s.split(",", 1)[1].strip())
        elif isinstance(ref, (list, tuple)) and len(ref) == 2:
            kind, val = str(ref[0]).upper(), str(ref[1]).strip()
            if kind == "CVE":
                cves.append("CVE-" + val)
    return cves


def _build_from_raw(raw: str) -> dict[str, list[str]]:
    """Ham metadata JSON'dan CVE -> [modul yolu] indeksi kur (exploit once)."""
    data = json.loads(raw)
    index: dict[str, list[str]] = {}
    for fullname, meta in data.items():
        if not isinstance(meta, dict):
            continue
        mtype = meta.get("type", "")
        path = fullname if "/" in fullname else f"{mtype}/{fullname}"
        is_exploit = mtype == "exploit" or path.startswith("exploit/")
        for cve in _parse_references(meta):
            bucket = index.setdefault(cve, [])
            if path in bucket:
                continue
            if is_exploit:
                bucket.insert(0, path)
            else:
                bucket.append(path)
    return index


def build_index(force: bool = False) -> dict[str, list[str]]:
    """CVE -> [modul] indeksini dondur (bellek/onbellek/msf sirasiyla)."""
    global _INDEX
    if _INDEX is not None and not force:
        return _INDEX
    if _CACHE.exists() and not force:
        try:
            _INDEX = json.loads(_CACHE.read_text(encoding="utf-8"))
            return _INDEX
        except (OSError, ValueError):
            pass
    raw = _read_metadata_raw()
    if not raw:
        _INDEX = {}
        return _INDEX
    index = _build_from_raw(raw)
    try:
        _CACHE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE.write_text(json.dumps(index), encoding="utf-8")
    except OSError:
        pass
    _INDEX = index
    return index


def modules_for_cve(cve_id: str) -> list[str]:
    return build_index().get(str(cve_id).strip().upper(), [])


def module_for_cve(cve_id: str) -> str | None:
    mods = modules_for_cve(cve_id)
    return mods[0] if mods else None
