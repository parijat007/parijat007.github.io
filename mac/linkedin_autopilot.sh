#!/bin/zsh
# launchd, every 10 minutes: pick up new notes from GitHub, draft them, act on /post and /skip replies in Telegram.
cd "${0:A:h:h}"
git fetch -q origin main 2>/dev/null && git merge --ff-only -q origin/main 2>/dev/null || true
exec /bin/zsh mac/linkedin.sh autopilot
