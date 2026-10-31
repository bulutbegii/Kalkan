"""Adaptorler arasi kucuk yardimcilar."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
TMP_DIR = Path.home() / ".kalkan" / "tmp"


def wordlist(name: str) -> str:
    path = DATA_DIR / "wordlists" / name
    if not path.exists():
        raise FileNotFoundError(f"gömülü wordlist yok: {path}")
    return str(path)


def temp_file(prefix: str, suffix: str = ".json") -> Path:
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=str(TMP_DIR))
    import os

    os.close(handle)
    return Path(name)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def extract_json(text: str) -> Any | None:
    """Metnin icinden ilk gecerli JSON nesnesini/dizisini cikar."""
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = stripped.find(opener)
        if start < 0:
            continue
        end = stripped.rfind(closer)
        if end <= start:
            continue
        try:
            return json.loads(stripped[start : end + 1])
        except json.JSONDecodeError:
            continue
    return None


def json_lines(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def host_of(target: str) -> str:
    if "://" in target:
        return (urlsplit(target).hostname or target).lower()
    return target.split("/")[0].split(":")[0].lower()


def origin(target: str) -> str:
    """'https://a.b/x' -> 'https://a.b' ; sema yoksa http varsay."""
    if "://" not in target:
        target = "http://" + target
    parts = urlsplit(target)
    return f"{parts.scheme}://{parts.netloc}"


def base_url(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    return target.rstrip("/")


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
