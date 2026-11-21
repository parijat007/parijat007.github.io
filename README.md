# Watchfloor

Personal profile site plus a public, source-checked threat service for defenders:
an **hourly watch** of newly exploited vulnerabilities and vendor advisories, and a **daily brief**
with a patch action and hunting focus per item. Published on GitHub Pages, delivered to WhatsApp and
Microsoft Teams. Runs on your local model; keeps running on free cloud models when the Mac is off.

Architecture and full flow: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## How it stays up without your laptop

| Situation | What happens |
|---|---|
| Mac on at 6:35 AM | Local llama-server (Qwen3.6-35B-A3B) writes the brief, pushes it, site deploys |
| Mac on but port busy (e.g. SEC545 batch) | Mac uses GitHub Models, then Gemini |
| Mac asleep/off | 7:20 AM ET: GitHub Actions writes it with GitHub Models, then Gemini |
| Every model fails or is rate-limited | Facts-only brief from KEV/NVD data, no commentary |
| Mac wakes later | launchd catch-up runs, sees today's brief exists, does nothing |
| Any hour | Hourly watch runs on GitHub, no model; KEV hit on your stack alerts WhatsApp + Teams |

Cost: $0 (public repo Actions + Pages, free model tiers). Optional custom domain.

## Trusted sources
`sources.yaml` is the only list of inputs. Each entry records operator, tier and why it is trusted.
Enforced in code:
- HTTPS only; feed links that point outside the source's own domains are dropped.
- Only **authority** (CISA, NIST, GitHub Advisory) or **vendor** PSIRTs, or a KEV listing, can mark
  exploitation *confirmed*. Press-only claims become *Exploitation reported*, confidence capped at medium.
- Every published item must cite a URL that was actually collected.
- Source health from the latest run is shown on `/method/`.
- Re-verify each source quarterly (`verified_on`); new sources go through the admission criteria at the top of the file.

## Setup

### 1. GitHub (15 min)
1. Create a **public** repo named `<username>.github.io` (gives you the clean root URL). Push this folder to `main`.
2. Settings → Pages → Source: **GitHub Actions**.
3. Settings → Secrets → Actions:
   | Secret | Needed for |
   |---|---|
   | `CALLMEBOT_PHONE`, `CALLMEBOT_APIKEY` | WhatsApp |
   | `TEAMS_WEBHOOK_URL` | Teams (see below) |
   | `GEMINI_API_KEY` | second cloud backup (free key at aistudio.google.com) |
   | `NVD_API_KEY` | higher NVD rate limits (optional) |
   | `HEALTHCHECK_URL_WATCH`, `HEALTHCHECK_URL_BRIEF` | missed-run alerts (optional, healthchecks.io) |
   GitHub Models needs no secret: workflows request `models: read` for the built-in token.
4. Actions → *Hourly watch* → Run workflow. Then *Cloud brief* → Run workflow.
5. Set `site.url` in `config.yaml`; fill the `[brackets]` in `site/profile.yaml`.

### 2. Microsoft Teams (5 min)
Office 365 connector webhooks are retired. In the target channel: **••• → Workflows →
"Post to a channel when a webhook request is received"** → copy the URL into `TEAMS_WEBHOOK_URL`
(and the Mac Keychain). Posts appear as an Adaptive Card from the Workflows bot.
Use a personal or community team; check your organisation's policy before posting into a corporate tenant.

### 3. Mac (15 min)
1. Clone to `~/watchfloor`; copy `mac/brief.env.example` → `mac/brief.env`, set `MODEL_PATH` and `GITHUB_REPO`.
2. Fine-grained GitHub token: repository *Contents: read/write* on this repo; account *Models: read*.
3. `zsh mac/setup.sh` — venv, secrets into Keychain, launchd job (6:35 AM + on login), 6:30 AM wake.
4. Test: `zsh mac/run_brief.sh && tail -50 ~/Library/Logs/watchfloor.log`

### 4. Before going public
- Check your employer's outside-activity and social media policy; `show_employers: false` hides names.
- Pin every `uses:` action to a commit SHA; enable Dependabot, branch protection, and a `correction` issue label.
- Verify the cloud model ids in `config.yaml` against the GitHub Models catalog and AI Studio.

## Local commands
```bash
python -m pytest -q tests                          # 14 offline tests
python -m digest.watch --no-alert                  # update hourly watch data
python -m digest.main --dry-run                    # full brief; print WhatsApp text and Teams card size
WF_LLM_CHAIN=github_models,gemini python -m digest.main --dry-run   # simulate Mac-off path
python site/build.py && python -m http.server -d _site 8000
```

## Layout
```
digest/        collectors, llm (provider chain), render (validate), notify, teams, watch, main
sources.yaml   trusted source registry          config.yaml   chain, watchlist, delivery
site/          templates, CSS, logo, fonts, profile.yaml, build.py
mac/           launchd runner + setup           .github/workflows/  watch, brief, pages, ci
data/          published JSON (git history = audit trail)          docs/ architecture
```
