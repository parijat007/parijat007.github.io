#!/bin/zsh
# Run the LinkedIn agent with your Keychain secrets and the local model.
#   ./mac/linkedin.sh draft --from note
#   ./mac/linkedin.sh publish <id>
set -e
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
cd "${0:A:h:h}"
[[ -f mac/brief.env ]] && source mac/brief.env
kc() { security find-generic-password -a watchfloor -s "$1" -w 2>/dev/null || true; }
export GEMINI_API_KEY="$(kc gemini-apikey)" GROQ_API_KEY="$(kc groq-apikey)" OPENROUTER_API_KEY="$(kc openrouter-apikey)" CLOUDFLARE_ACCOUNT_ID="$(kc cloudflare-account)" CLOUDFLARE_API_TOKEN="$(kc cloudflare-token)"
export TELEGRAM_BOT_TOKEN="$(kc telegram-bot-token)" TELEGRAM_CHAT_ID="$(kc telegram-chat-id)"
export WF_LOCAL_BASE_URL="http://127.0.0.1:${LLAMA_PORT:-8091}/v1"
exec .venv/bin/python -m "${WF_MODULE:-digest.linkedin}" "$@"
