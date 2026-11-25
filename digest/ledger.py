"""Tamper-evident ledger of published briefs (data/ledger.jsonl).

Every time a brief is written or corrected, one line is appended: the file, its SHA-256 and the hash of
the previous line. Changing or deleting any past line breaks every hash after it, and a brief edited
without a new line no longer matches its latest entry. The ledger's head hash is put in the site's
build.json, which each deploy signs (Sigstore, public transparency log), and the weekly backup copies it to
S3 under a compliance lock. So a rewrite of history shows up even if an attacker controls the repository.

    python -m digest.ledger verify
    python -m digest.ledger sync          # record every new or changed brief (run at commit time)
    python -m digest.ledger add data/briefs/2026-11-22.json --reason correction

Writers record at commit time, on top of the chain just fetched from origin (see tools/publish.sh), so the
Mac and the cloud never append competing lines.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENESIS = "0" * 64


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entry_hash(e: dict) -> str:
    body = {k: e[k] for k in sorted(e) if k != "hash"}
    return _sha(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())


def ledger_path(root: Path = ROOT) -> Path:
    return root / "data" / "ledger.jsonl"


def read(root: Path = ROOT) -> list[dict]:
    p = ledger_path(root)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def head(root: Path = ROOT) -> str:
    entries = read(root)
    return entries[-1]["hash"] if entries else GENESIS


def add(file: Path, reason: str = "published", root: Path = ROOT, now: datetime | None = None) -> dict:
    entries = read(root)
    rel = str(file.resolve().relative_to(root.resolve()))
    e = {"seq": len(entries) + 1, "file": rel, "sha256": _sha(file.read_bytes()), "reason": reason,
         "at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
         "prev": entries[-1]["hash"] if entries else GENESIS}
    e["hash"] = _entry_hash(e)
    p = ledger_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as fh:
        fh.write(json.dumps(e, sort_keys=True) + "\n")
    return e


def verify(root: Path = ROOT) -> list[str]:
    """Problems found; an empty list means the chain and every recorded brief are intact."""
    problems, prev, latest = [], GENESIS, {}
    for i, e in enumerate(read(root), 1):
        if e.get("seq") != i:
            problems.append(f"line {i}: sequence {e.get('seq')} (a line was removed or reordered)")
        if e.get("prev") != prev:
            problems.append(f"line {i}: does not link to the line before it (history was rewritten)")
        if _entry_hash(e) != e.get("hash"):
            problems.append(f"line {i}: content does not match its hash (the line was edited)")
        prev = e.get("hash", "")
        latest[e["file"]] = e
    for rel, e in latest.items():
        f = root / rel
        if not f.exists():
            problems.append(f"{rel}: recorded in the ledger but missing")
        elif _sha(f.read_bytes()) != e["sha256"]:
            problems.append(f"{rel}: changed since its last ledger entry (edited without a record)")
    for f in sorted((root / "data" / "briefs").glob("*.json")):
        rel = str(f.relative_to(root))
        if rel not in latest:
            problems.append(f"{rel}: published brief with no ledger entry")
    return problems


def sync(root: Path = ROOT, now: datetime | None = None) -> list[dict]:
    """Append an entry for every brief that is new or differs from its latest entry. Returns what was added."""
    latest = {e["file"]: e for e in read(root)}
    first = not latest
    added = []
    for f in sorted((root / "data" / "briefs").glob("*.json")):
        rel = str(f.relative_to(root))
        e = latest.get(rel)
        if e is None or e["sha256"] != _sha(f.read_bytes()):
            reason = "baseline" if first else ("published" if e is None else "replaced")
            added.append(add(f, reason, root, now))
    return added


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify")
    a = sub.add_parser("add")
    a.add_argument("file")
    a.add_argument("--reason", default="published")
    sub.add_parser("sync", help="record every new or changed brief")
    args = ap.parse_args()
    if args.cmd == "verify":
        problems = verify()
        for p in problems:
            print(f"LEDGER: {p}")
        print(f"ledger head {head()} ({len(read())} entries): {'OK' if not problems else 'PROBLEMS'}")
        return 1 if problems else 0
    if args.cmd == "add":
        print(add(Path(args.file), args.reason)["hash"])
        return 0
    if args.cmd == "sync":
        for e in sync():
            print(f"recorded {e['file']} ({e['reason']}) -> {e['hash'][:12]}")
        print(f"ledger head {head()}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
