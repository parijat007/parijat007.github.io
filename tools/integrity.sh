#!/usr/bin/env bash
# Integrity checks: ledger chain, live site == deployed build, live build.json signed by our pages workflow.
# Prints one line per failed check; exit 1 if any failed. Needs GH_TOKEN (attestation lookup) and full history.
set -uo pipefail
site="${WF_SITE_URL:-https://theparijat.com}"; repo="${GITHUB_REPOSITORY:-parijat007/parijat007.github.io}"
fail=0
python -m digest.ledger verify >/tmp/ledger.out 2>&1 || { echo "ledger: $(grep -m3 LEDGER /tmp/ledger.out | tr '\n' ' ')"; fail=1; }
python tools/site_check.py >/tmp/site.out 2>&1 || { echo "live site: $(grep -m3 -E '::error|differs|NOT|rewritten|missing' /tmp/site.out | tr '\n' ' ')"; fail=1; }
if curl -fsS --retry 3 "$site/build.json" -o /tmp/live-build.json; then
  gh attestation verify /tmp/live-build.json -R "$repo" --signer-workflow "$repo/.github/workflows/pages.yml" \
    >/tmp/att.out 2>&1 || { echo "signature: live build.json has no valid attestation from pages.yml"; fail=1; }
else
  echo "live site: build.json unreachable"; fail=1
fi
exit $fail
