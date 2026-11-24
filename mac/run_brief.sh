#!/bin/zsh
# Watchfloor daily brief on the Mac: collect -> local model (cloud models if local fails) -> validate -> WhatsApp -> push data -> site deploys.
# Started by launchd (see com.threatbrief.daily.plist). Safe to run by hand.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
HERE="${0:A:h}"
source "$HERE/brief.env"
LOG="$HOME/Library/Logs/watchfloor.log"
exec >>"$LOG" 2>&1
echo "=== $(date '+%F %T') brief run start ==="

kc() { security find-generic-password -a watchfloor -s "$1" -w 2>/dev/null || true; }
export CALLMEBOT_PHONE="$(kc callmebot-phone)" CALLMEBOT_APIKEY="$(kc callmebot-apikey)"
export NVD_API_KEY="$(kc nvd-apikey)" TEAMS_WEBHOOK_URL="$(kc teams-webhook-url)"
export GEMINI_API_KEY="$(kc gemini-apikey)"
export TELEGRAM_BOT_TOKEN="$(kc telegram-bot-token)" TELEGRAM_CHAT_ID="$(kc telegram-chat-id)"
export WF_LOCAL_BASE_URL="http://127.0.0.1:${LLAMA_PORT}/v1"
GH_TOKEN="$(kc github-push-token)"
export GROQ_API_KEY="$(kc groq-apikey)" OPENROUTER_API_KEY="$(kc openrouter-apikey)" CLOUDFLARE_ACCOUNT_ID="$(kc cloudflare-account)" CLOUDFLARE_API_TOKEN="$(kc cloudflare-token)"
HC_URL="$(kc healthcheck-url-brief)"

cd "$REPO_DIR"
# Use a Keychain token if one was stored; otherwise the gh CLI sign-in (gh auth setup-git) handles auth.
# The token goes in an HTTP header through environment config, never in the URL: a URL with a token
# is written in plain text to .git/logs (the reflog) and shows in the process list.
REMOTE="origin"
if [[ -n "$GH_TOKEN" ]]; then
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
  export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
  REMOTE="https://github.com/${GITHUB_REPO}.git"
fi
SELF_SUM="$(shasum "$0")"
# A run interrupted mid-rebase would block every later run: clear it first.
[[ -d .git/rebase-merge || -d .git/rebase-apply ]] && { echo "clearing an unfinished rebase"; git rebase --abort || true; }
# -X ours: during a rebase "ours" is the published copy. When the cloud already published a brief or
# state file, the published version wins and the Mac's own copy of that file is dropped.
git pull --rebase --autostash -X ours --quiet "$REMOTE" main || {
  echo "pull failed; aborting the rebase and continuing on the published copy"
  git rebase --abort 2>/dev/null || true
}
# If the pull changed this script, run the new version (once) instead of finishing the old one.
if [[ -z "${WF_REEXEC:-}" && "$(shasum "$0")" != "$SELF_SUM" ]]; then
  echo "run_brief.sh was updated by the pull; restarting with the new version"
  export WF_REEXEC=1
  exec /bin/zsh "$0" "$@"
fi

STARTED=0
cleanup() { if [[ $STARTED == 1 ]]; then kill "$LLAMA_PID" 2>/dev/null || true; echo "llama-server stopped"; fi; }
trap cleanup EXIT

if pgrep -x llama-server >/dev/null && ! curl -fsS -m 3 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1; then
  # Another model is loaded (e.g. SEC545 generator or 70B judge). Two models can exceed 64 GB: use cloud.
  echo "another llama-server is running; not loading a second model. Using free cloud models."
  export WF_LLM_CHAIN="gemini,groq,cloudflare,openrouter"
elif curl -fsS -m 3 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1; then
  # Something is already serving (e.g. an overnight SEC545 batch). Don't hijack it.
  if ! curl -fsS -m 3 "http://127.0.0.1:${LLAMA_PORT}/v1/models" | grep -qi "$(basename "$MODEL_PATH" .gguf)"; then
    echo "port ${LLAMA_PORT} busy with another model (e.g. SEC545 batch); using free cloud models instead"
    export WF_LLM_CHAIN="gemini,groq,cloudflare,openrouter"
  fi
else
  echo "starting llama-server"
  # Same tuning as your existing setup: FlashAttention, Q8_0 KV cache, Jinja chat template (needed for JSON schema + no-think)
  "$LLAMA_SERVER" -m "$MODEL_PATH" --port "$LLAMA_PORT" -c "$LLAMA_CTX" -ngl 99 -fa on \
    -ctk q8_0 -ctv q8_0 --jinja --host 127.0.0.1 >>"$HOME/Library/Logs/watchfloor-llama.log" 2>&1 &
  LLAMA_PID=$!; STARTED=1
  for i in {1..90}; do curl -fsS -m 2 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 && break; sleep 2; done
  curl -fsS -m 2 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 || { echo "llama-server failed to start; using cloud models"; export WF_LLM_CHAIN="gemini,groq,cloudflare,openrouter"; }
fi

# caffeinate keeps the Mac awake for the duration of the run only
export WF_BRIEF_WINDOW_UTC="10-17"   # a run outside 5 AM-noon EST is not the morning brief
caffeinate -i "$REPO_DIR/.venv/bin/python" -m digest.main --skip-if-exists

git add data/ state/
if ! git diff --cached --quiet; then
  git -c user.name="watchfloor-bot" -c user.email="watchfloor-bot@users.noreply.github.com" commit -qm "brief: $(date +%F)"
  if ! git push --quiet "$REMOTE" HEAD:main; then
    # The cloud pushed first (e.g. the watch or a cloud brief): replay on top, published copy wins, retry once.
    git pull --rebase -X ours --quiet "$REMOTE" main || { git rebase --abort 2>/dev/null || true; }
    git push --quiet "$REMOTE" HEAD:main || echo "push failed twice; the cloud brief covers today"
  fi
  echo "pushed; GitHub Pages deploy starts automatically"
fi
[[ -n "$HC_URL" ]] && curl -fsS -m 10 "$HC_URL" >/dev/null || true
echo "=== $(date '+%F %T') brief run done ==="
