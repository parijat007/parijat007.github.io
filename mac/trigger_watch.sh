#!/bin/zsh
# Hourly backstop for the GitHub "Hourly watch" workflow.
# GitHub delays or skips scheduled runs on quiet repos; this asks GitHub to run it
# whenever the last run is older than 40 minutes. Uses your gh sign-in; no extra secrets.
# Started by launchd (com.watchfloor.watch.plist). Safe to run by hand.
set -u
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
REPO_DIR="${0:A:h:h}"
[[ -f "$REPO_DIR/mac/brief.env" ]] && source "$REPO_DIR/mac/brief.env"
REPO="${GITHUB_REPO:-parijat007/parijat007.github.io}"
LOG="$HOME/Library/Logs/watchfloor.log"
ts() { date "+%Y-%m-%d %H:%M:%S"; }

last=$(gh run list -R "$REPO" -w watch.yml -L 1 --json createdAt -q '.[0].createdAt' 2>/dev/null)
if [[ -n "$last" ]]; then
  last_s=$(date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$last" +%s 2>/dev/null || echo 0)
  age=$(( $(date -u +%s) - last_s ))
  if (( age < 2400 )); then
    echo "$(ts) watch-trigger: last run ${age}s ago, skipping" >> "$LOG"
    exit 0
  fi
fi

if gh workflow run watch.yml -R "$REPO" >/dev/null 2>&1; then
  echo "$(ts) watch-trigger: started Hourly watch on GitHub" >> "$LOG"
else
  echo "$(ts) watch-trigger: could not start workflow (offline or gh not signed in)" >> "$LOG"
fi
