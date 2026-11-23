# External on-time trigger (cron-job.org)

GitHub's own schedule is best-effort and can run hours late. A free external
scheduler starts the workflows on time. Every workflow is safe to start twice:
the brief skips when an analyst brief exists, the watch only refreshes, and the
`data-writer` concurrency group stops two writers pushing at once.

## 1. Create a narrow GitHub token

GitHub → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token.

| Field | Value |
|---|---|
| Token name | `watchfloor-external-cron` |
| Expiration | 90 days (set a calendar reminder to rotate) |
| Repository access | **Only select repositories** → `parijat007/parijat007.github.io` |
| Permissions → Repository → **Actions** | **Read and write** |
| Everything else | No access (Metadata: read-only is added automatically) |

With this token, anyone holding it can start or cancel this repo's workflows.
It cannot read secrets, change code, or touch any other repo. If it leaks,
revoke it on the same page.

## 2. Create three jobs on cron-job.org

Free account at https://cron-job.org. Each job uses:

- **URL:** `https://api.github.com/repos/parijat007/parijat007.github.io/actions/workflows/<FILE>/dispatches`
- **Advanced → Request method:** `POST`
- **Advanced → Headers:**
  - `Authorization: Bearer <token from step 1>`
  - `Accept: application/vnd.github+json`
  - `X-GitHub-Api-Version: 2022-11-28`
  - `Content-Type: application/json`
- **Advanced → Request body:** `{"ref":"main"}`
- **Time zone:** UTC
- **Notifications:** on failure (a 401 means the token expired)

| Job | `<FILE>` | Schedule (UTC) |
|---|---|---|
| Watchfloor watch | `watch.yml` | every hour at minute 20 |
| Watchfloor brief | `brief.yml` | 11:25 and 12:25 daily |
| Watchfloor health | `health.yml` | every hour at minute 55 |

A successful call returns **HTTP 204** with an empty body. Use
cron-job.org's "Test run" on each job and confirm a new run appears under
the repo's **Actions** tab.

## Rotating the token

Generate a new token with the same settings, paste it into the three jobs'
`Authorization` header, then delete the old token.
