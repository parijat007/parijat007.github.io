#!/usr/bin/env bash
# Commit and push a brief run's data, recording it in the tamper-evident ledger on top of origin's chain.
#   tools/publish.sh "<commit message>" [remote]     (remote defaults to origin; PYTHON overrides python)
# Each attempt: commit this run's data (not the ledger), rebase onto origin, then take origin's ledger and
# append entries for whatever the merged tree changed. The Mac and the cloud therefore never write
# competing ledger lines, and an entry always describes the file that is actually pushed.
# Exit 0 = pushed or nothing to push.
set -uo pipefail
msg="$1"; remote="${2:-origin}"; py="${PYTHON:-python}"
prefer="${PUBLISH_PREFER:-theirs}"   # on a data conflict: theirs = this run wins, ours = what is already published
L=data/ledger.jsonl
git config user.name  >/dev/null || git config user.name  "watchfloor-bot"
git config user.email >/dev/null || git config user.email "watchfloor-bot@users.noreply.github.com"

for attempt in 1 2 3; do
  git fetch -q "$remote" main || { sleep 5; continue; }
  base=$(git rev-parse FETCH_HEAD)
  git checkout -q HEAD -- "$L" 2>/dev/null || true          # the ledger is rebuilt below, never merged
  paths=(data/); [[ -d state ]] && paths+=(state/)
  git add -A -- "${paths[@]}" || { echo "git add failed" >&2; exit 1; }
  git reset -q -- "$L"
  git diff --cached --quiet || git commit -qm "$msg"
  if ! git rebase -q --autostash -X "$prefer" "$base"; then
    git rebase --abort 2>/dev/null || true; sleep 5; continue
  fi
  git show "$base:$L" > "$L" 2>/dev/null || : > "$L"
  "$py" -m digest.ledger sync
  if ! "$py" -m digest.ledger verify; then echo "ledger check failed; not publishing" >&2; exit 1; fi
  git add "$L"
  if git diff --cached --quiet; then
    [[ "$(git rev-parse HEAD)" == "$base" ]] && { echo "nothing to publish"; exit 0; }
  elif [[ "$(git rev-parse HEAD)" == "$base" ]]; then
    git commit -qm "$msg"
  else
    git commit -q --amend --no-edit
  fi
  if git push -q "$remote" HEAD:main; then echo "published (attempt $attempt)"; exit 0; fi
  git reset -q --soft "$base"; git reset -q          # someone pushed in between: keep our files, redo on top
  sleep $((attempt * 5))
done
echo "publish failed after 3 attempts" >&2
exit 1
