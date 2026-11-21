#!/bin/zsh
# One-time Mac setup. Run from the repo root: zsh mac/setup.sh
set -euo pipefail
REPO_DIR="${0:A:h:h}"
cd "$REPO_DIR"
[[ -f mac/brief.env ]] || { cp mac/brief.env.example mac/brief.env; echo "Edit mac/brief.env, then re-run."; exit 1; }

echo "1/4 Python environment"
python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt

echo "2/4 Secrets -> macOS Keychain (input hidden; press Enter to skip optional ones)"
store() { read -rs "?$2: " v; echo; [[ -n "$v" ]] && security add-generic-password -U -a watchfloor -s "$1" -w "$v"; }
store github-push-token   "GitHub fine-grained token (this repo: Contents read/write; account: Models read)"
store gemini-apikey       "Gemini API key from aistudio.google.com (optional backup)"
store teams-webhook-url   "Teams Workflows webhook URL (optional)"
store callmebot-phone     "CallMeBot phone (+1...)"
store callmebot-apikey    "CallMeBot API key"
store nvd-apikey          "NVD API key (optional)"
store healthcheck-url-brief "Healthchecks.io ping URL (optional)"

echo "3/4 launchd job"
sed "s#__REPO_DIR__#${REPO_DIR}#" mac/com.watchfloor.daily.plist > ~/Library/LaunchAgents/com.watchfloor.daily.plist
launchctl bootout "gui/$(id -u)/com.watchfloor.daily" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/com.watchfloor.daily.plist

echo "4/4 Wake the Mac at 6:30 daily (needs admin; Mac must be on power)"
sudo pmset repeat wakeorpoweron MTWRFSU 06:30:00
echo "Done. Test now with: zsh mac/run_brief.sh && tail -50 ~/Library/Logs/watchfloor.log"
