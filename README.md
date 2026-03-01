<p align="center">
  <img src="https://raw.githubusercontent.com/ayush585/ButterFence/main/assets/logo.png" alt="ButterFence Logo" width="200">
</p>

<h1 align="center">ButterFence Pro</h1>

<p align="center">
  <strong>AI-native security harness</strong> that intercepts, red-teams, and auto-patches destructive AI coding agent behavior — powered by multi-model adversarial testing (Claude + Gemini) with optional AMD Ryzen AI NPU edge inference.
</p>

<p align="center">
  <a href="https://pypi.org/project/butterfence/"><img src="https://img.shields.io/pypi/v/butterfence.svg" alt="PyPI"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/tests-480%2B%20passing-brightgreen.svg" alt="Tests">
  <img src="https://img.shields.io/badge/CVSS-v3.1-orange.svg" alt="CVSS v3.1">
  <img src="https://img.shields.io/badge/AMD-Edge%20Ready-ED1C24.svg" alt="AMD Edge">
</p>

---

## What It Does

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Real-Time Interception** | Hooks into Claude Code and blocks dangerous tool calls before execution |
| 2 | **Red Team Audit** | 44 built-in scenarios across 11 threat categories |
| 3 | **Multi-Model Red Team** | Claude + Gemini attack simultaneously; finds cross-model blind spots |
| 4 | **Supply Chain Scanner** | Detects typosquatting and malicious packages in dependencies |
| 5 | **CVSS v3.1 Scoring** | Industry-standard severity scoring with attack vector breakdowns |
| 6 | **Whitelist Engine** | Glob-pattern false-positive suppression via `.butterfence.yaml` |
| 7 | **Web Dashboard** | 6-page dark-theme SPA with live threat monitoring |
| 8 | **REST API** | 10 endpoints with API key auth and Swagger docs |
| 9 | **AMD Edge Runtime** | ONNX classifier targeting Ryzen AI NPU — zero cloud dependency |
| 10 | **Auto-Patch** | AI analyzes defense gaps and generates regex patterns to close them |
| 11 | **Repo Scanner** | Proactive secret detection with Shannon entropy analysis |
| 12 | **Tamper-Evident Audit Log** | SQLite with SHA-256 chain checksums |
| 13 | **CI/CD Integration** | GitHub Actions, SARIF, JUnit, pass/fail exit codes |

---

## Quickstart

```bash
# Install
pip install butterfence

# Initialize in your project
butterfence init

# Run the 44-scenario security audit
butterfence audit

# CVSS v3.1 scoring
butterfence audit --cvss

# Scan dependencies for typosquatting
butterfence supply-chain

# Save your Gemini API key (for AI red team)
butterfence auth-gemini --key "your-key"

# AI Red Team: Gemini attacks, ButterFence defends
butterfence redteam --model gemini --count 10

# Launch the web dashboard
butterfence dashboard

# Run fully offline (AMD edge mode)
butterfence audit --edge-mode
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  USER ENTRY POINTS                  │
│   [CLI]        [Web Dashboard]       [REST API]     │
│  butterfence    localhost:8000       /api/* + /docs  │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                    CORE ENGINE                       │
│  Interceptor → Rule Matcher → CVSS Scorer            │
│  Whitelist Engine → Explainability Layer              │
└──────┬────────────────┬──────────────────┬──────────┘
       │                │                  │
┌──────▼──────┐  ┌──────▼──────┐  ┌───────▼────────┐
│  AI RED TEAM │  │SUPPLY CHAIN │  │  EDGE RUNTIME  │
│ Claude +     │  │ Typosquat + │  │  ONNX + AMD    │
│ Gemini       │  │ Malicious DB│  │  NPU / CPU     │
│ (concurrent) │  │ (offline)   │  │  (zero cloud)  │
└──────┬───────┘  └──────┬──────┘  └───────┬────────┘
       │                 │                  │
┌──────▼─────────────────▼──────────────────▼────────┐
│                   STORAGE LAYER                     │
│  SQLite (6 tables) + SHA-256 Audit Chain + JSONL    │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│                     EXPORTERS                        │
│   [PDF]    [HTML]    [SARIF]    [JSON]    [JUnit]    │
└─────────────────────────────────────────────────────┘
```

**Data Flow:**
```
AI Agent Command → Interceptor → [Edge Mode?] → ONNX Classifier → Decision
                               → [Normal Mode] → Regex Rules + Whitelist
                                                → CVSS Score + Explainability
                                                → Block / Allow / Warn
                                                → SQLite + Dashboard + API
```

---

## AI Red Team (Multi-Model)

The `butterfence redteam` command turns AI models into adversaries. They scan your repo's structure, tech stack, and sensitive files, then generate creative attacks targeting YOUR specific codebase.

```bash
# Gemini as attacker
butterfence redteam --model gemini --count 10

# Claude as attacker
butterfence redteam --model claude --count 10

# Both models simultaneously (finds cross-model blind spots)
butterfence redteam --models claude,gemini --count 10

# Auto-fix: AI attacks, finds gaps, patches the defense
butterfence redteam --model gemini --fix

# Full loop: attack → patch → re-attack → show improvement
butterfence redteam --model gemini --verify
```

**What makes it powerful:**
- Attacks **tailored to your repo** (uses your file tree, tech stack, languages)
- Tries obfuscation, variable indirection, base64 encoding, creative evasion
- **Cross-model blind spots**: one model catches what the other misses
- **`--fix` mode**: AI analyzes gaps and generates exact regex patterns to close them
- **`--verify` mode**: Full closed loop — attack, patch, re-attack, measure improvement
- Results saved to SQLite database and visible on the dashboard

---

## Supply Chain Scanner

```bash
# Scan all dependency files
butterfence supply-chain

# JSON output for CI
butterfence supply-chain --format json

# Show safe alternatives
butterfence supply-chain --fix
```

Parses `requirements.txt`, `package.json`, `go.mod`, and `Gemfile`. Detects:
- **Typosquatting** — Levenshtein distance against top-1000 PyPI/npm packages (e.g. `requets` → `requests`)
- **Known malicious packages** — bundled database of flagged packages
- **Dependency confusion** — suspicious package sources

---

## Web Dashboard

```bash
butterfence dashboard
```

Opens a 6-page web UI at `http://localhost:8000/dashboard`:

| Page | Purpose |
|------|---------|
| **Overview** | Stats cards, security gauge, recent activity |
| **Threats** | Full threat log with severity/decision filtering |
| **Red Team** | Launch AI scans from browser, select model |
| **Supply Chain** | One-click dependency scanning |
| **Audit Log** | SHA-256 chain viewer with integrity verification |
| **Settings** | API keys, whitelist config, custom rules, report export |

Modern dark theme with glassmorphism effects. Served by FastAPI — no Node.js or npm required.

---

## REST API

```bash
# Start the API server
butterfence serve

# With custom port
butterfence serve --port 9000
```

Swagger docs at `http://localhost:8000/docs`. All endpoints require API key (`X-API-Key` header).

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/intercept` | Evaluate a command before execution |
| POST | `/api/redteam/start` | Launch multi-model red team scan |
| GET | `/api/redteam/{scan_id}` | Poll scan results |
| POST | `/api/supply-chain/scan` | Scan dependency files |
| GET | `/api/threats` | List threats (filterable by category, CVSS) |
| POST | `/api/patch/generate` | Auto-generate fix patches |
| GET | `/api/audit-log` | Tamper-evident audit log |
| PUT | `/api/rules/whitelist` | Add whitelist pattern |
| GET | `/api/report/export` | Export PDF/Markdown report |
| POST | `/api/rules/custom` | Upload custom YAML rule pack |

---

## AMD Edge Runtime

Run the entire detection pipeline offline on AMD Ryzen AI NPU with **zero cloud dependency**.

```bash
# Check NPU status
butterfence edge-info

# Train and export the ONNX classifier
butterfence edge-export

# Export with INT8 quantization (faster on NPU)
butterfence edge-export --quantize

# Run audit fully offline
butterfence audit --edge-mode
```

**Provider fallback chain:** AMD Ryzen AI NPU (VitisAI) → DirectML GPU → CPU ONNX Runtime → Heuristic Engine

The heuristic fallback works **out-of-the-box** without any model file or extra dependencies — keyword-based classification that runs in <30ms.

---

## API Key Management

```bash
# Anthropic (for Claude red team)
butterfence auth
butterfence auth --key sk-ant-your-key
butterfence auth --status
butterfence auth --remove

# Google Gemini (for Gemini red team)
butterfence auth-gemini --key "your-gemini-key"
butterfence auth-gemini --status
butterfence auth-gemini --remove
```

**Security:** Keys stored at `~/.butterfence/` with owner-only permissions (0600 on Unix, restricted ACL on Windows). Secure deletion overwrites with null bytes before unlinking. Never stored in repo.

**Lookup order:** Environment variable (`ANTHROPIC_API_KEY` / `GEMINI_API_KEY`) > Stored key file

---

## CVSS v3.1 Scoring

```bash
# Audit with industry-standard CVSS scores
butterfence audit --cvss

# Report with CVSS breakdown
butterfence report --cvss
```

Maps each of the 11 threat categories to CVSS v3.1 vectors (AV, AC, PR, UI, S, C, I, A). Produces 0.0–10.0 severity scores alongside the legacy 0–100 grading:

| Legacy Score | Grade | CVSS Equivalent |
|---|---|---|
| 100/100 (A) | Hardened | All threats < 4.0 |
| 70-89 (B) | Mostly safe | Some threats 4.0–7.0 |
| 50-69 (C) | Risky | Threats 7.0–9.0 |
| <50 (F) | Unsafe | Critical threats 9.0+ |

---

## Whitelist Engine

Create `.butterfence.yaml` in your project root:

```yaml
whitelist:
  - "*.md"
  - "docs/**"
  - "tests/fixtures/**"
  - "*.example"
```

Whitelisted files skip all rule matching and entropy checks. Eliminates false positives on documentation, test fixtures, and config examples.

---

## 11 Defense Categories

| Category | What It Catches |
|----------|----------------|
| `destructive_shell` | `rm -rf /`, `mkfs`, `chmod 777`, disk wipe, shutdown |
| `secret_access` | Reading `.env`, SSH keys, AWS credentials, certificates |
| `secret_exfil` | Writing API keys, echoing secrets to logs |
| `risky_git` | Force push, hard reset, destructive clean |
| `network_exfil` | Posting files via curl, reverse shells, nc/socat |
| `python_dangerous` | `subprocess` shell=True, `eval()`, `exec()`, `pickle.loads()` |
| `sql_injection` | f-string SQL queries, `DROP TABLE`, `DROP DATABASE` |
| `docker_escape` | `--privileged`, mount root, `--pid=host`, docker.sock |
| `cloud_credentials` | Azure/GCP/AWS secrets, `gcloud`/`az` token extraction |
| `supply_chain` | pip HTTP registry, `curl\|sh`, dependency confusion |
| `privilege_escalation` | `sudo su`, chmod setuid, `chown root`, `nsenter` |

---

## Commands

| Command | Description |
|---------|-------------|
| `butterfence init` | Initialize ButterFence (create config, install hooks) |
| `butterfence audit` | Run 44 red-team scenarios |
| `butterfence audit --cvss` | Audit with CVSS v3.1 scoring |
| `butterfence audit --edge-mode` | Fully offline audit (ONNX/heuristic) |
| `butterfence audit --quick` | Critical scenarios only |
| `butterfence audit --report` | Audit + generate report |
| `butterfence report --format html` | HTML report (self-contained) |
| `butterfence report --format sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `butterfence report --format json` | Structured JSON export |
| `butterfence scan` | Scan repo for secrets and security issues |
| `butterfence supply-chain` | Scan dependencies for typosquatting |
| `butterfence redteam --model gemini` | AI red-team with Gemini |
| `butterfence redteam --models claude,gemini` | Multi-model simultaneous red team |
| `butterfence redteam --fix` | Auto-fix defense gaps |
| `butterfence redteam --verify` | Full loop: attack → patch → verify |
| `butterfence serve` | Start REST API server |
| `butterfence dashboard` | Launch web dashboard + auto-open browser |
| `butterfence edge-export` | Train and export ONNX model |
| `butterfence edge-info` | Show NPU/provider status |
| `butterfence auth` | Save Anthropic API key |
| `butterfence auth-gemini` | Save Gemini API key |
| `butterfence watch` | Live terminal monitoring dashboard |
| `butterfence ci --min-score 80` | CI mode with exit codes |
| `butterfence analytics` | Event log analytics and trends |
| `butterfence explain <id>` | Educational threat explanation |
| `butterfence pack list` | List available rule packs |
| `butterfence pack install <name>` | Install a rule pack |
| `butterfence status` | Show current state |
| `butterfence uninstall` | Remove hooks |

---

## CI/CD Integration

```bash
# Auto-generate GitHub Actions workflow
butterfence ci --generate-workflow

# CI with SARIF output
butterfence ci --min-score 80 --format sarif --output results.sarif

# Generate badge for README
butterfence ci --badge badge.svg
```

---

## Community Rule Packs

| Pack | Description |
|------|-------------|
| `owasp` | OWASP Top 10 patterns (XSS, command injection, path traversal) |
| `aws` | AWS credential and dangerous operation patterns |
| `cloud_security` | Multi-cloud security (Azure, GCP, AWS) |
| `nodejs` | Node.js security (eval, child_process, prototype pollution) |
| `python` | Python security (subprocess, pickle, eval, exec) |
| `docker` | Container escape and dangerous Docker patterns |
| `supply_chain` | Dependency confusion and script injection |

---

## Project Structure

```
src/butterfence/
    cli.py                  # Typer CLI (22+ commands)
    config.py               # Config loading, validation, defaults
    matcher.py              # Core matching engine (pure function, edge-mode support)
    hook_runner.py          # Claude Code hook entry point
    installer.py            # Hook installation into settings.local.json
    audit.py                # Red-team scenario runner (44 scenarios)
    redteam.py              # AI red-team (Claude + Gemini, multi-model)
    auth.py                 # Secure API key management (Anthropic + Gemini)
    scoring.py              # Legacy + CVSS v3.1 scoring
    cvss.py                 # CVSS v3.1 base score calculator
    whitelist.py            # False-positive whitelist engine
    supply_chain.py         # Dependency typosquatting scanner
    database.py             # SQLite storage layer (6 tables, SHA-256 audit chain)
    scanner.py              # Proactive repo secret scanner
    entropy.py              # Shannon entropy secret detection
    normalizer.py           # Command normalization
    obfuscation.py          # Base64/hex/variable obfuscation detection
    chain_detector.py       # Multi-step behavioral attack chain detection
    watcher.py              # Live terminal dashboard
    analytics.py            # Event log analytics
    report.py               # Markdown report generator
    ci.py                   # CI/CD integration
    cache.py                # Rule compilation cache
    policy.py               # Natural language policy evaluation
    models/
        __init__.py          # BaseAttacker abstraction
        claude_attacker.py   # Claude API integration
        gemini_attacker.py   # Gemini API integration
    api/
        __init__.py          # FastAPI application factory
        routes.py            # 10 REST endpoints
        schemas.py           # Pydantic request/response models
        auth_middleware.py   # API key authentication
    dashboard/
        index.html           # SPA shell
        styles.css           # Dark theme with glassmorphism
        app.js               # 6-page dashboard logic
    edge/
        __init__.py          # Edge runtime manager, NPU detection
        onnx_classifier.py   # ONNX threat classifier (NPU/CPU fallback)
        model_export.py      # Training data, ONNX export, INT8 quantization
    exporters/
        pdf_report.py        # PDF report with CVSS scores
        sarif.py             # SARIF 2.1.0 format
        junit.py             # JUnit XML format
        json_export.py       # JSON export
        html_report.py       # Self-contained HTML report
        badge.py             # SVG shield badge
assets/
    scenarios.yaml           # 44 red-team scenarios
    schema.sql               # SQLite DDL (6 tables)
    known_packages.json      # Top-1000 PyPI/npm packages
    packs/                   # 7 built-in rule packs
```

---

## Testing

```bash
# Run all tests
pytest tests/

# Run by phase
pytest tests/test_cvss.py tests/test_whitelist.py       # Phase 1
pytest tests/test_models.py                              # Phase 2
pytest tests/test_supply_chain.py                        # Phase 3
pytest tests/test_database.py                            # Phase 4
pytest tests/test_api.py                                 # Phase 5
pytest tests/test_edge.py                                # Phase 7

# Run with coverage
pytest tests/ --cov=butterfence --cov-report=term-missing
```

**480+ tests** across 32 test files covering: matcher, config, rules, audit, scoring, CVSS, whitelist, multi-model orchestrator, supply chain, database, API endpoints, dashboard, edge runtime, entropy, normalizer, obfuscation, chain detection, exporters, redteam, CLI, and more.

---

## Dependencies

### Core
| Dependency | Purpose |
|---|---|
| `typer>=0.12` | CLI framework |
| `rich>=13` | Terminal UI, tables, panels, live dashboard |
| `pyyaml>=6` | YAML scenario/pack loading |
| `pathspec>=0.11` | `.gitignore` pattern matching for scanner |
| `anthropic>=0.39` | Anthropic SDK for Claude red-team |

### Optional

```bash
pip install butterfence[gemini]   # Google Gemini red-team
pip install butterfence[api]      # REST API + Dashboard
pip install butterfence[edge]     # AMD NPU edge runtime
pip install butterfence[pdf]      # PDF report export
pip install butterfence[dev]      # Test dependencies
```

| Group | Packages |
|---|---|
| `gemini` | `google-generativeai>=0.5` |
| `api` | `fastapi>=0.109`, `uvicorn>=0.27`, `pydantic>=2` |
| `edge` | `numpy>=1.24`, `onnx>=1.14`, `onnxruntime>=1.16` |
| `pdf` | `reportlab>=4` |
| `dev` | `pytest>=8`, `httpx>=0.27` |

---

## License

MIT

---

## Built With

Built for the **AMD Slingshot** program. ButterFence Pro uses AI in three creative ways:

1. **Red-Team Attacker** — Claude + Gemini generate repo-specific attack scenarios
2. **Defense Patcher** — AI analyzes gaps and generates exact regex fixes
3. **Edge Classifier** — ONNX model trained on attack data, runs on AMD Ryzen AI NPU

Original ButterFence created during the Cerebral Valley hackathon (Feb 2026). Evolved to Pro with 7 phases: CVSS scoring, multi-model red team, supply chain scanning, SQLite storage, REST API, web dashboard, and AMD edge runtime.
