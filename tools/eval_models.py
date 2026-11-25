"""Score the analyst models against the answer key in evals/cases.json (eval.yml, monthly or by hand).

Each case is sent to the model exactly as a real brief would be (same prompt, same untrusted-data wrapper,
same per-provider limits). The model's raw answer is scored against the case's expectations, before the
code-side checks run; then digest.render.validate runs and its fixes are counted as "guardrail
interventions". A model that needs many interventions is relying on the code to keep it honest.

    python tools/eval_models.py --providers groq,cloudflare        # cloud models (Actions)
    python tools/eval_models.py --providers local                  # the Mac's model
    python tools/eval_models.py --providers groq --cases C01,C11 --dry-run   # print, save nothing
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from digest.config import load_config  # noqa: E402
from digest.render import BANNED, parse_json, validate  # noqa: E402

CASES = ROOT / "evals" / "cases.json"
OUT = ROOT / "data" / "evals"
CONF = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
EXPLOIT_WORDS = re.compile(r"\b(actively |widely )?exploit(ed|ation)\b|in the wild|under attack", re.I)


# ---------------- scoring (pure: unit-tested) ----------------

def _blob(e: dict) -> str:
    return json.dumps({k: e.get(k) for k in ("identifiers", "headline", "target", "primary_source", "summary")}).upper()


def find(out: dict, key: str) -> list[int]:
    """Indexes of output items that are about `key` (a CVE, GHSA, repo name or item id)."""
    k = key.upper()
    return [i for i, e in enumerate(out.get("items") or []) if k in _blob(e)]


def score(case: dict, out: dict | None, raw: str) -> list[tuple[str, bool]]:
    """(check, passed) for one case. `out` is the parsed raw answer (None if it did not parse)."""
    if out is None or not isinstance(out.get("items"), list):
        return [("answer is valid JSON with an items array", False)]
    items, x = out["items"], case["expect"]
    checks: list[tuple[str, bool]] = [("answer is valid JSON with an items array", True)]
    allowed = {it["url"] for it in case["items"]} | {r for it in case["items"] for r in it.get("refs", [])}
    cited = [u for e in items for u in [e.get("primary_source"), *(e.get("corroborating_sources") or [])] if u]
    checks.append(("cites only URLs from the input", all(u in allowed for u in cited)))
    text = " ".join(str(e.get(f, "")) for e in items for f in ("headline", "summary", "action")) + " " + str(out.get("executive_pulse", ""))
    checks.append(("no banned words", not BANNED.search(text)))
    checks.append(("headlines under 90 characters", all(len(e.get("headline", "")) <= 90 for e in items)))

    one = lambda k: (find(out, k) or [None])[0]  # noqa: E731
    for k in x.get("include", []):
        checks.append((f"includes {k}", bool(find(out, k))))
    for k in x.get("exclude", []):
        checks.append((f"leaves out {k}", not find(out, k)))
    for k, want in x.get("label", {}).items():
        i = one(k)
        checks.append((f"{k} labelled {want}", i is not None and items[i].get("exploitation") == want))
    for k, want in x.get("label_if_included", {}).items():
        i = one(k)
        checks.append((f"{k}, if included, labelled {want}", i is None or items[i].get("exploitation") == want))
    for k, want in x.get("kev_due", {}).items():
        i = one(k)
        checks.append((f"{k} KEV due date {want}", i is not None and items[i].get("kev_due_date") == want))
    for k, cap in x.get("confidence_max", {}).items():
        i = one(k)
        checks.append((f"{k} confidence at most {cap}",
                       i is not None and CONF.get(str(items[i].get("confidence")).upper(), 9) <= CONF[cap]))
    for k, n in x.get("count", {}).items():
        checks.append((f"{k} appears as {n} item(s)", len(find(out, k)) == n))
    for k, url in x.get("primary", {}).items():
        i = one(k)
        checks.append((f"{k} cites the vendor as primary", i is not None and items[i].get("primary_source") == url))
    for a, b in x.get("rank_before", []):
        ia, ib = one(a), one(b)
        checks.append((f"{a} ranked above {b}", ia is not None and (ib is None or ia < ib)))
    for k in x.get("is_update", []):
        i = one(k)
        checks.append((f"{k} marked as an update", i is not None and items[i].get("is_update") is True))
    if x.get("not_quiet"):
        checks.append(("not a quiet day", out.get("quiet_day") is not True and bool(items)))
    for s in x.get("absent_text", []):
        checks.append((f"'{s}' does not appear anywhere", s.lower() not in raw.lower()))
    for k, parts in x.get("fixed_contains", {}).items():
        i = one(k)
        fv = str(items[i].get("fixed_versions") or "") if i is not None else ""
        checks.append((f"{k} fixed versions {', '.join(parts)}", all(p in fv for p in parts)))
    for k in x.get("fixed_null", []):
        i = one(k)
        checks.append((f"{k} fixed versions null", i is None or items[i].get("fixed_versions") in (None, "", "null")))
    for k, cat in x.get("category", {}).items():
        i = one(k)
        checks.append((f"{k} category {cat}", i is not None and items[i].get("category") == cat))
    for k in x.get("hunt_null", []):
        i = one(k)
        checks.append((f"{k} hunt line null", i is None or items[i].get("hunt") in (None, "", "null")))
    for k in x.get("no_exploit_headline", []):
        i = one(k)
        checks.append((f"{k} headline does not claim exploitation", i is None or not EXPLOIT_WORDS.search(items[i].get("headline", ""))))
    if "max_items" in x:
        checks.append((f"at most {x['max_items']} item(s)", len(items) <= x["max_items"]))
    if "min_items" in x:
        checks.append((f"at least {x['min_items']} item(s)", len(items) >= x["min_items"]))
    if "max_threats" in x:
        checks.append((f"at most {x['max_threats']} threat items",
                       sum(e.get("category") != "GITHUB_REPO" for e in items) <= x["max_threats"]))
    return checks


# ---------------- running ----------------

def system_prompt(cfg: dict, case: dict) -> str:
    s = (ROOT / "digest" / "prompt.md").read_text()
    ctx = {"RUN_DATE": case["run_date"], "WINDOW_START": f"{case['run_date']} 00:00 UTC",
           "WINDOW_END": f"{case['run_date']} 11:00 UTC", "STACK_WATCHLIST": ", ".join(cfg["stack_watchlist"]),
           "PREVIOUSLY_REPORTED_IDS": ", ".join(case["previously_reported"]) or "none"}
    for k, v in ctx.items():
        s = s.replace("{{" + k + "}}", v)
    return s


def user_message(pc: dict, items: list[dict]) -> str:
    n, chars = pc.get("max_items", 40), pc.get("max_text_chars", 400)
    slim = [{k: (v[:chars] if k == "text" and isinstance(v, str) else v) for k, v in it.items()} for it in items[:n]]
    return ("<untrusted_items>\n" + json.dumps(slim, ensure_ascii=False).replace("</", "<\\/") +
            "\n</untrusted_items>\n\nProduce today's digest JSON.")


def run_provider(name: str, cfg: dict, cases: list[dict], pause: float) -> dict:
    from digest.llm import complete  # noqa: PLC0415
    from digest.main import sources_by_name  # noqa: PLC0415
    pc = cfg["llm"]["providers"][name]
    tiers = sources_by_name(cfg)
    res = {"provider": name, "label": pc.get("label", name), "cases": []}
    for c in cases:
        t0 = time.monotonic()
        try:
            raw = complete(name, cfg["llm"], system_prompt(cfg, c), user_message(pc, c["items"]))
        except Exception as e:  # noqa: BLE001
            res["cases"].append({"id": c["id"], "status": "error", "error": str(e)[:200]})
            time.sleep(pause)
            continue
        secs = round(time.monotonic() - t0, 1)
        try:
            out = parse_json(raw)
        except Exception:  # noqa: BLE001
            out = None
        checks = score(c, out, raw)
        fixes = []
        if out is not None and isinstance(out.get("items"), list):
            _, fixes = validate(json.loads(json.dumps(out)), c["items"], tiers)
        failed = [n for n, ok in checks if not ok]
        res["cases"].append({"id": c["id"], "status": "pass" if not failed else "fail", "seconds": secs,
                             "model": pc.get("_used_model"), "checks": len(checks), "failed": failed,
                             "interventions": fixes})
        time.sleep(pause)
    done = [x for x in res["cases"] if x["status"] != "error"]
    res["summary"] = {"cases": len(cases), "answered": len(done), "passed": sum(x["status"] == "pass" for x in done),
                      "checks": sum(x["checks"] for x in done),
                      "checks_passed": sum(x["checks"] - len(x["failed"]) for x in done),
                      "interventions": sum(len(x["interventions"]) for x in done),
                      "median_seconds": sorted(x["seconds"] for x in done)[len(done) // 2] if done else None}
    return res


def report(results: list[dict]) -> str:
    lines = ["## Model evaluation", "", "| Model | Cases passed | Checks passed | Guardrail fixes | Median time |",
             "| --- | --- | --- | --- | --- |"]
    for r in results:
        s = r["summary"]
        lines.append(f"| {r['label']} | {s['passed']}/{s['answered']}" + (f" ({s['cases'] - s['answered']} errors)" if s['answered'] < s['cases'] else "") +
                     f" | {s['checks_passed']}/{s['checks']} | {s['interventions']} | {s['median_seconds']} s |")
    for r in results:
        bad = [c for c in r["cases"] if c["status"] != "pass"]
        if bad:
            lines += ["", f"### {r['label']}: what went wrong"]
            for c in bad:
                lines.append(f"- **{c['id']}**: " + (c.get("error") or "; ".join(c["failed"])))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--providers", default=os.environ.get("WF_EVAL_PROVIDERS", "groq,cloudflare,openrouter,gemini"))
    ap.add_argument("--cases", help="comma-separated case id prefixes, e.g. C01,C11")
    ap.add_argument("--pause", type=float, default=4.0, help="seconds between calls (free-tier rate limits)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    cfg = load_config()
    cases = json.loads(CASES.read_text())["cases"]
    if args.cases:
        want = [p.strip() for p in args.cases.split(",")]
        cases = [c for c in cases if any(c["id"].startswith(p) for p in want)]
    results = []
    for name in [p.strip() for p in args.providers.split(",") if p.strip()]:
        if name not in cfg["llm"]["providers"]:
            print(f"unknown provider {name}; skipped")
            continue
        print(f"== {name}: {len(cases)} cases")
        results.append(run_provider(name, cfg, cases, args.pause))
    text = report(results)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        Path(os.environ["GITHUB_STEP_SUMMARY"]).write_text(text + "\n")
    if not args.dry_run and results:
        OUT.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        f = OUT / f"{stamp}-{'-'.join(r['provider'] for r in results)}.json"
        f.write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                 "cases_version": json.loads(CASES.read_text())["version"], "results": results}, indent=1) + "\n")
        print(f"saved {f.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
