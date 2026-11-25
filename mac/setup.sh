#!/bin/zsh
# One-time Mac setup. Run from the repo root: zsh mac/setup.sh
set -euo pipefail
REPO_DIR="${0:A:h:h}"
cd "$REPO_DIR"
[[ -f mac/brief.env ]] || { cp mac/brief.env.example mac/brief.env; echo "Edit mac/brief.env, then re-run."; exit 1; }

echo "1/4 Python environment"
python3 -m venv .venv && .venv/bin/pip install -q --require-hashes -r requirements.lock && shasum -a 256 requirements.lock > .venv/.lock-sha

echo "2/4 Secrets -> macOS Keychain (input hidden; press Enter to skip optional ones)"
store() {
  # Re-runs keep existing keys: press Enter to keep (or skip), or paste a new value to replace
  local have=""; security find-generic-password -a watchfloor -s "$1" >/dev/null 2>&1 && have=" [saved; Enter keeps it]"
  local v; read -rs "?$2${have}: " v; echo
  if [[ -n "$v" ]]; then security add-generic-password -U -a watchfloor -s "$1" -w "$v"; fi
  return 0
}
store github-push-token   "GitHub token (optional: press Enter to use your gh sign-in instead)"
store gemini-apikey       "Gemini API key from aistudio.google.com (optional backup)"
store groq-apikey         "Groq API key from console.groq.com/keys (optional backup)"
store openrouter-apikey   "OpenRouter API key from openrouter.ai/keys (optional backup)"
store cloudflare-account  "Cloudflare account ID (optional backup)"
store cloudflare-token    "Cloudflare API token with Workers AI read (optional backup)"
store telegram-bot-token  "Telegram bot token from @BotFather (optional)"
store telegram-chat-id    "Telegram chat id (optional)"
store teams-webhook-url   "Teams Workflows webhook URL (optional)"
store callmebot-phone     "CallMeBot phone (+1...)"
store callmebot-apikey    "CallMeBot API key"
store nvd-apikey          "NVD API key (optional)"
store linkedin-client-id  "LinkedIn app Client ID (optional, for the LinkedIn agent; see mac/LINKEDIN.md)"
store linkedin-client-secret "LinkedIn app Client Secret (optional)"
store healthcheck-url-brief "Healthchecks.io ping URL (optional)"

echo "3/4 launchd job"
sed "s#__REPO_DIR__#${REPO_DIR}#" mac/com.watchfloor.daily.plist > ~/Library/LaunchAgents/com.watchfloor.daily.plist
launchctl bootout "gui/$(id -u)/com.watchfloor.daily" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.watchfloor.daily.plist
# Hourly-watch backstop: GitHub skips scheduled runs on quiet repos
sed "s#__REPO_DIR__#${REPO_DIR}#" mac/com.watchfloor.watch.plist > ~/Library/LaunchAgents/com.watchfloor.watch.plist
launchctl bootout "gui/$(id -u)/com.watchfloor.watch" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.watchfloor.watch.plist

echo "4/4 Wake the Mac at 6:30 daily (needs admin; Mac must be on power)"
sudo pmset repeat wakeorpoweron MTWRFSU 06:30:00
echo "Done. Test now with: zsh mac/run_brief.sh && tail -50 ~/Library/Logs/watchfloor.log"
