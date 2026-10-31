"""Terminal gorsel katmani: renk, kalkan (shield) grafigi, durum simgeleri.

Tasarim ilkeleri:
- Renk SADECE destekleniyorsa acilir (TTY + NO_COLOR ayarli degil). Boru/
  dosyaya yazarken ya da NO_COLOR varsa duz metne duser.
- Windows'ta sanal terminal (VT) modu aktif edilir; cp65001 konsollar ANSI
  anlar. Beceremezsek sessizce renksiz devam ederiz.
- UTF yoksa (dar kodlama) simgeler ASCII'ye duser; cizim asla cokmez.

Hicbir sey import aninda cikti basmaz; bu modul saf yardimcidir.
"""

from __future__ import annotations

import os
import sys

_CODES = {
    "reset": "0",
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "white": "37",
    "grey": "90",
    "bred": "91",
    "bgreen": "92",
    "byellow": "93",
    "bcyan": "96",
}


def _enable_windows_vt() -> bool:
    """Windows konsolunda ANSI islemeyi ac. Basarili/zaten acik -> True."""
    if os.name != "nt":
        return True
    try:
        import ctypes

        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        k.SetConsoleMode(h, mode.value | 0x0004)
        return True
    except Exception:  # noqa: BLE001 - renk olmazsa olmaz degil
        return False


def _detect_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("KALKAN_FORCE_COLOR"):
        return True
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return _enable_windows_vt()


def _detect_utf() -> bool:
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return "utf" in enc


COLOR = _detect_color()
UTF = _detect_utf()

_SYM_UTF = {
    "ok": "✓", "fail": "✗", "run": "▶", "skip": "–", "warn": "⚠",
    "arrow": "→", "dot": "·", "note": "•", "shield": "🛡",
}
_SYM_ASCII = {
    "ok": "+", "fail": "x", "run": ">", "skip": "-", "warn": "!",
    "arrow": "->", "dot": ".", "note": "*", "shield": "[]",
}
SYM = _SYM_UTF if UTF else _SYM_ASCII


def style(text: str, *names: str) -> str:
    """Metni verilen ANSI stilleriyle sar (renk kapaliysa oldugu gibi birak)."""
    if not COLOR or not names:
        return text
    seq = ";".join(_CODES[n] for n in names if n in _CODES)
    if not seq:
        return text
    return f"\033[{seq}m{text}\033[0m"


def bold(t: str) -> str: return style(t, "bold")
def dim(t: str) -> str: return style(t, "dim")
def red(t: str) -> str: return style(t, "red")
def green(t: str) -> str: return style(t, "green")
def yellow(t: str) -> str: return style(t, "yellow")
def blue(t: str) -> str: return style(t, "blue")
def cyan(t: str) -> str: return style(t, "cyan")
def grey(t: str) -> str: return style(t, "grey")


def is_tty() -> bool:
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


_RISK_STYLE = {
    "passive": ("green",),
    "active": ("cyan",),
    "intrusive": ("yellow", "bold"),
    "destructive": ("bred", "bold"),
}
_STATUS_STYLE = {
    "ok": ("bgreen", "bold"),
    "dry-run": ("blue",),
    "unavailable": ("grey",),
    "denied": ("byellow",),
    "error": ("bred", "bold"),
    "skipped": ("grey",),
}
_STATUS_SYM = {
    "ok": "ok", "dry-run": "arrow", "unavailable": "skip",
    "denied": "warn", "error": "fail", "skipped": "skip",
}


def risk(label: str) -> str:
    return style(label, *_RISK_STYLE.get(label, ("white",)))


def status(label: str) -> str:
    return style(label, *_STATUS_STYLE.get(label, ("white",)))


def status_symbol(label: str) -> str:
    key = _STATUS_SYM.get(label, "dot")
    sym = SYM[key]
    return style(sym, *_STATUS_STYLE.get(label, ("white",)))


_SHIELD_UTF = [
    "▟██████▙",
    "████████",
    "███  ███",
    "████████",
    "▜██████▛",
    " ▜████▛ ",
    "  ▜██▛  ",
    "   ▜▛   ",
]
_SHIELD_ASCII = [
    " ______ ",
    "|######|",
    "|##  ##|",
    "|######|",
    "\\######/",
    " \\####/ ",
    "  \\##/  ",
    "   \\/   ",
]


def shield_lines() -> list[str]:
    art = _SHIELD_UTF if UTF else _SHIELD_ASCII
    return [cyan(line) for line in art]


def banner(version: str, model: str, online: bool, scope_ok: bool) -> str:
    """Kalkan grafigi + baslik bloku (yan yana) tek string dondurur."""
    shield = shield_lines()
    on = green("çevrimiçi") if online else grey("çevrimdışı")
    sc = green("var") if scope_ok else red("YOK")
    info = [
        bold(cyan("K A L K A N")),
        grey("yetkili güvenlik orkestrasyon çekirdeği"),
        "",
        f"{grey('sürüm')} {version}    {grey('model')} {model} [{on}]",
        f"{grey('kapsam')} {sc}",
    ]
    out: list[str] = []
    rows = max(len(shield), len(info))
    for i in range(rows):
        left = shield[i] if i < len(shield) else " " * 8
        right = info[i] if i < len(info) else ""
        out.append(f"  {left}   {right}")
    return "\n".join(out)


def rule(width: int = 56) -> str:
    ch = "═" if UTF else "="
    return cyan(ch * width)
