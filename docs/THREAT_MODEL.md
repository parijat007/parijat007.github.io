# Watchfloor threat model

Design premise: assume breach. No control here makes compromise impossible. The goal is that
(1) the blast radius of any one stolen credential is small, (2) any tampering with what has been published
is provable from evidence the attacker cannot rewrite, and (3) the project can be rebuilt from a copy the
attacker cannot delete.

Reviewed 2026-11-24. Re-review after any new secret, workflow, provider or hosting change.

## Assets

| Asset | Why it matters |
|---|---|
| Published briefs and watch alerts (site, feed, API, Telegram) | Readers act on them. A falsified "not exploited" is the worst outcome. |
| Repository history (`main`, tags) | The source of truth for every brief, and for the site build. |
| The theparijat.com domain and DNS | Whoever controls DNS controls what readers see. |
| Secrets (LLM keys, Telegram, NVD, VulnCheck, AWS role, health-check URLs) | Abuse costs quota or lets someone post as Watchfloor. |
| The owner's accounts (GitHub, AWS, Cloudflare, Zoho, cron-job.org, Telegram) | Each is a route to the assets above. |

## Trust boundaries

1. **Untrusted input:** feed text (CISA, NVD, vendor advisories, news). It reaches an LLM prompt and then the site.
2. **Third-party compute:** GitHub Actions runners, the LLM providers, cron-job.org.
3. **The owner's Mac:** runs the local model and pushes with its own token.
4. **Publishing:** GitHub Pages, served on theparijat.com, with DNS at Route 53.

## Threats and controls

| # | Threat (ATT&CK where it fits) | Controls in place | Residual gap / owner action |
|---|---|---|---|
| T1 | Prompt injection through feed text makes the model write a false or hostile brief | `_clean` strips markup, control and format characters; `injection_suspect` logs; facts (KEV, EPSS, SSVC, CVSS) come from structured data, not the model; the payload cannot close its data block; the model returns structured JSON (grammar-constrained on the local model) | A persuasive but well-formed lie in an advisory still passes. The risk line is computed from data, so it cannot be argued with. |
| T2 | XSS or script injection on the site | Jinja autoescape; CSP `script-src 'self'` (inline script cannot run; the only inline block is JSON-LD data); no third-party scripts; the live-site check fails if the CSP disappears | None known. |
| T3 | Stolen GitHub token pushes a forged brief or rewrites history (T1565.001, data manipulation) | Hash-chained ledger of every brief; its head is put in build.json; each build.json is signed by Sigstore (public transparency log, cannot be edited); the hourly check fails if a brief, the chain, or the signature does not match; weekly bundle to S3 under Object Lock | **Owner:** add a ruleset on `main` and tags that blocks force-push and deletion (see checklist). Without it a force-push is detected but not prevented. |
| T4 | Malicious or compromised GitHub Action (supply chain, T1195.001) | Every action pinned to a full commit SHA; Dependabot proposes updates as reviewable PRs; actionlint; CodeQL; OpenSSF Scorecard; `persist-credentials: false` on read-only jobs; least-privilege `permissions:` per job | **Owner:** set the default workflow token to read-only in repo settings. |
| T5 | Malicious Python dependency | Every cloud install uses `requirements.lock`: exact versions with SHA-256 hashes (`--require-hashes`), so a hijacked or swapped release is refused; pip-audit checks the locked set on every push and daily | The lock changes only when re-generated, so a fix needs a deliberate re-lock (pip-audit flags when one is due). The Mac venv still installs from `requirements.txt`. **Owner:** turn on Dependabot security updates. |
| T6 | Secret leaked into the repository | gitleaks on full history; GitHub secret scanning with push protection (on); secrets live only in Actions secrets and the Mac keychain/env | Tokens pasted into chats or terminals are treated as exposed and rotated. |
| T7 | Stolen LLM or Telegram key | Each key is single-purpose and free tier (no billing to drain); the facts-only fallback still publishes if every model fails | A stolen Telegram bot token could post to the channel. Rotate on suspicion. |
| T8 | Mac compromised or its push token stolen | The token is sent as a header, not stored in the remote URL or reflog; publishing goes through `tools/publish.sh`, so every brief the Mac pushes is ledgered and visible | **Owner:** replace the Mac push token with a fine-grained one scoped to this repo, Contents: write only, 90-day expiry. FileVault on. |
| T9 | Pages deployment from a branch other than `main` | Deploy only runs from workflows on `main`; the attestation names the signing workflow | **Owner:** restrict the `github-pages` environment to `main`. |
| T10 | Domain or DNS hijack (T1584.002) | HTTPS enforced and checked daily; the live-site check compares every sampled file with the signed build | **Owner:** registrar lock, DNSSEC on the Route 53 zone, MFA on the AWS root and IAM users. |
| T11 | Email spoofing as parijat@theparijat.com | SPF and DKIM through Zoho; DMARC in monitoring mode | **Owner:** move DMARC to `p=reject` once reports are clean (around 6 Dec). |
| T12 | Account takeover of an owner account (T1078) | Not controllable from code | **Owner:** passkeys or hardware/app 2FA on GitHub, AWS, Cloudflare, Zoho, cron-job.org and Telegram; no SMS. |
| T13 | Loss of the repository or the account | Weekly git bundle as an Actions artifact (90 days); Mac bundle every Sunday (keeps 8); S3 copy under Object Lock compliance mode, 90 days, written by an OIDC role that can only put objects from `main` | **Owner:** deploy the S3 stack and add `AWS_BACKUP_ROLE_ARN`, `AWS_BACKUP_BUCKET`. Until then the S3 layer is not active. |
| T15 | A bad change reaches the live site through the unblock agent's auto-merge | Only PRs opened by the owner from this repo, not drafts, with every check green (tests, CodeQL, security, gitleaks); a one-hour window announced on the PR and on Telegram, stopped by a `hold` comment or label; new commits restart the hour; PRs that change workflow files, forks and Dependabot are never auto-merged; every deploy is still signed and ledgered | A change that passes every check and is not held in the hour goes live. **Owner:** set `WF_AUTOMERGE=off` (repository variable) to return to merge-by-hand. |
| T16 | A forged Telegram message publishes a LinkedIn post | The Mac acts only on `/post ID` or `/skip ID` from the owner's private chat id; publishing still runs the judge (facts against the source, then a second model) and refuses on FAIL or if no second model answers | A stolen Telegram account could approve a draft that already passed the judge. 2FA on Telegram (T12). |
| T18 | A pull request abuses the event notifier (pull_request_target runs with secrets) | The job checks out the default branch only (sparse: one script), never the PR; event text is read from the event file by Python and never placed in a shell command; the only secret is the Telegram bot token; job permissions are read-only | A PR title can put arbitrary text in a Telegram message to the owner (it is sent as plain text). |
| T17 | Comments become a channel for abuse or third-party tracking | giscus loads only after the reader clicks "Show comments" (no request to GitHub or giscus before that); the CSP allows giscus.app only on pages with comments and only once comments are configured; comments live in GitHub Discussions in an Announcement-type category, so the owner can hide, lock or delete them and readers cannot start unrelated threads | giscus's client script is third-party code loaded on click. **Owner:** moderate in GitHub Discussions; lock a thread if it attracts abuse. |
| T14 | Silent failure (jobs stop running and nobody notices) | Hourly health check re-runs missed jobs; dead-man's switch URLs; external cron-job.org triggers; Telegram alerts | cron-job.org's GitHub token expires 23 Dec (reminder set for 20 Dec). |

## How to prove the site was not tampered with

1. `gh attestation verify build.json -R parijat007/parijat007.github.io --signer-workflow parijat007/parijat007.github.io/.github/workflows/pages.yml`
   on the live `https://theparijat.com/build.json`. A pass means this exact file was produced by the pages workflow of this repository and logged publicly.
2. Every file hash in that build.json must match the live file (`tools/site_check.py` does this).
3. Its `ledger_head` must appear in `data/ledger.jsonl`, and `python -m digest.ledger verify` must pass.
   If someone rewrites history, the old head is still in the public Sigstore log and in the S3 locked copy, so the rewrite is provable.

`tools/integrity.sh` runs all three. The health workflow runs it every hour and alerts on Telegram after a confirmed failure.

## Incident playbook (short)

1. Treat the live site as untrusted; post a holding note in Telegram if readers may be affected.
2. Revoke the suspected credential first, then investigate.
3. Find the last good ledger head from the Sigstore log or the S3 copy; restore from the matching bundle (`mac/RESTORE.md`).
4. Re-deploy from the restored `main`; confirm `tools/integrity.sh` passes.
5. Publish a correction for any brief that was wrong while compromised.

## Owner checklist (settings code cannot change)

- [ ] Ruleset on `main` and all tags: block force-push and deletion, require the CI and Security checks. *(Settings → Rules → Rulesets)*
- [ ] Default workflow permissions: read-only; disallow Actions from approving PRs. *(Settings → Actions → General)*
- [ ] Dependabot security updates: on. *(Settings → Code security)*
- [ ] `github-pages` environment: deployment branches limited to `main`. *(Settings → Environments)*
- [ ] Passkey or app 2FA on GitHub, AWS (root and IAM), Cloudflare, Zoho, cron-job.org, Telegram.
- [ ] Route 53: DNSSEC signing on the zone; registrar transfer lock on.
- [ ] DMARC to `p=reject` around 6 Dec after checking reports.
- [ ] Replace the Mac push token (fine-grained, this repo only, Contents: write, 90 days).
- [ ] Deploy `aws/backup-bucket.yaml` and add the two backup secrets.
- [ ] Mac: FileVault on; keep "prevent sleep" for the brief window.
- [ ] Rotate the cron-job.org GitHub token before 23 Dec.
