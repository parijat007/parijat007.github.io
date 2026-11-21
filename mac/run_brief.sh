#!/bin/zsh
# Watchfloor daily brief on the Mac: collect -> local model (cloud models if local fails) -> validate -> WhatsApp -> push data -> site deploys.
# Started by launchd (see com.threatbrief.daily.plist). Safe to run by hand.
set -euo pipefail
HERE="${0:A:h}"
source "$HERE/brief.env"
LOG="$HOME/Library/Logs/watchfloor.log"
exec >>"$LOG" 2>&1
echo "=== $(date '+%F %T') brief run start ==="

kc() { security find-generic-password -a watchfloor -s "$1" -w 2>/dev/null || true; }
export CALLMEBOT_PHONE="$(kc callmebot-phone)" CALLMEBOT_APIKEY="$(kc callmebot-apikey)"
export NVD_API_KEY="$(kc nvd-apikey)" TEAMS_WEBHOOK_URL="$(kc teams-webhook-url)"
export GEMINI_API_KEY="$(kc gemini-apikey)"
export WF_LOCAL_BASE_URL="http://127.0.0.1:${LLAMA_PORT}/v1"
GH_TOKEN="$(kc github-push-token)"
export GROQ_API_KEY="$(kc groq-apikey)" OPENROUTER_API_KEY="$(kc openrouter-apikey)"
HC_URL="$(kc healthcheck-url-brief)"

cd "$REPO_DIR"
git pull --rebase --autostash --quiet "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPO}.git" main

STARTED=0
cleanup() { if [[ $STARTED == 1 ]]; then kill "$LLAMA_PID" 2>/dev/null || true; echo "llama-server stopped"; fi; }
trap cleanup EXIT

if curl -fsS -m 3 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1; then
  # Something is already serving (e.g. an overnight SEC545 batch). Don't hijack it.
  if ! curl -fsS -m 3 "http://127.0.0.1:${LLAMA_PORT}/v1/models" | grep -qi "$(basename "$MODEL_PATH" .gguf)"; then
    echo "port ${LLAMA_PORT} busy with another model (e.g. SEC545 batch); using free cloud models instead"
    export WF_LLM_CHAIN="gemini,groq,openrouter"
  fi
else
  echo "starting llama-server"
  # Same tuning as your existing setup: FlashAttention, Q8_0 KV cache, Jinja chat template (needed for JSON schema + no-think)
  "$LLAMA_SERVER" -m "$MODEL_PATH" --port "$LLAMA_PORT" -c "$LLAMA_CTX" -ngl 99 -fa on \
    -ctk q8_0 -ctv q8_0 --jinja --host 127.0.0.1 >>"$HOME/Library/Logs/watchfloor-llama.log" 2>&1 &
  LLAMA_PID=$!; STARTED=1
  for i in {1..90}; do curl -fsS -m 2 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 && break; sleep 2; done
  curl -fsS -m 2 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 || { echo "llama-server failed to start; using cloud models"; export WF_LLM_CHAIN="gemini,groq,openrouter"; }
fi

# caffeinate keeps the Mac awake for the duration of the run only
caffeinate -i "$REPO_DIR/.venv/bin/python" -m digest.main --skip-if-exists

git add data/ state/
if ! git diff --cached --quiet; then
  git -c user.name="watchfloor-bot" -c user.email="watchfloor-bot@users.noreply.github.com" commit -qm "brief: $(date +%F)"
  git push --quiet "https://x-access-token:${GH_TOKEN}@github.com/${GITHUB_REPO}.git" HEAD:main
  echo "pushed; GitHub Pages deploy starts automatically"
fi
[[ -n "$HC_URL" ]] && curl -fsS -m 10 "$HC_URL" >/dev/null || true
echo "=== $(date '+%F %T') brief run done ==="
