# Restoring Watchfloor

Three independent copies exist:

| Copy | Where | How fresh |
|---|---|---|
| GitHub repo | github.com/parijat007/parijat007.github.io | live |
| Mac clone | `~/watchfloor` (pulled every morning by the brief run) | daily |
| Weekly bundles | GitHub: **Actions → Weekly backup → latest run → Artifacts** (90 days). Mac: `~/watchfloor-backups/` (last 8 Sundays) | weekly |

A bundle holds every branch, commit, brief, watch entry and state file. Secrets are **not** in it: they live in GitHub's
repository secrets and the Mac Keychain.

## Restore into a new or emptied repository

```
git clone ~/watchfloor-backups/watchfloor-YYYY-MM-DD.bundle watchfloor-restore
cd watchfloor-restore
git remote set-url origin https://github.com/parijat007/parijat007.github.io.git
git push origin --all
```

For a GitHub artifact, download the zip, unzip it, check `sha256sum -c watchfloor-*.bundle.sha256`, then clone the bundle as above.

## Then

1. Re-add the repository secrets (Settings → Secrets and variables → Actions): `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`,
   `GEMINI_API_KEY`, `GROQ_API_KEY`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `OPENROUTER_API_KEY`, `NVD_API_KEY`,
   and `VULNCHECK_API_KEY` if used.
2. Settings → Pages → Source: **GitHub Actions**; custom domain `theparijat.com`, Enforce HTTPS.
3. Run **Cloud brief** and **Hourly watch** once by hand (Actions → workflow → Run workflow) and check the site.
4. If the repository moved, update the three cron-job.org jobs' URLs and make a new fine-grained token for them.
