"""LinkedIn MCP server: lets Claude draft, check and (with your approval) publish your LinkedIn posts.

Runs on your Mac over stdio, started by the Claude desktop app (mac/linkedin_mcp.sh, added by mac/setup.sh).
No new dependencies: the Model Context Protocol's stdio transport is newline-delimited JSON-RPC 2.0, which
this file speaks directly, so the hash-locked install stays as it is.

Every tool goes through the same code as ./mac/linkedin.sh, so the same rules hold:
- publish and edit run the judge first (facts against the source, then a second model) and refuse on FAIL
  or when no second model answers;
- publish and edit change your public profile, so they also require confirm=true, which Claude sets only
  after you have said yes in the chat; the desktop app asks you before each call as well;
- tokens stay in Keychain and are never returned by any tool.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import sys
import traceback

from . import linkedin as L
from . import post_judge
from .config import load_config

PROTOCOL = "2025-06-18"
log = logging.getLogger("digest.linkedin_mcp")

DRAFT_ID = {"type": "string", "pattern": r"^[0-9]{8}-[0-9]{4}-[0-9a-f]{6}$", "description": "Draft id, e.g. 20261125-2333-2dc936"}
TOOLS = [
    {"name": "linkedin_status", "description": "Who is signed in, when the LinkedIn token expires, and how many drafts exist.",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
    {"name": "linkedin_list_drafts", "description": "List drafts and published posts: id, status, title, judge verdict.",
     "inputSchema": {"type": "object", "properties": {}}, "annotations": {"readOnlyHint": True}},
    {"name": "linkedin_show_draft", "description": "Full text of a draft or post, its judge report, image path and LinkedIn URL.",
     "inputSchema": {"type": "object", "properties": {"id": DRAFT_ID}, "required": ["id"]}, "annotations": {"readOnlyHint": True}},
    {"name": "linkedin_create_draft", "description": "Draft a post from the latest Watchfloor analyst note or daily brief. "
     "Writes, checks, judges and revises (up to three rounds) and attaches the branded image. Posts nothing.",
     "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "enum": ["note", "brief"]}}, "required": ["source"]}},
    {"name": "linkedin_update_draft", "description": "Replace a draft's text (for example after a review) and re-run the judge. Posts nothing.",
     "inputSchema": {"type": "object", "properties": {"id": DRAFT_ID, "text": {"type": "string"}}, "required": ["id", "text"]}},
    {"name": "linkedin_judge", "description": "Re-run the judge on a draft: facts against the source, then a second model.",
     "inputSchema": {"type": "object", "properties": {"id": DRAFT_ID}, "required": ["id"]}, "annotations": {"readOnlyHint": True}},
    {"name": "linkedin_publish", "description": "Publish a draft with its image to the owner's LinkedIn profile. Public and "
     "visible to their network. Only call after the owner has explicitly said to publish this draft in the chat; set "
     "confirm=true only then. The judge runs again and must PASS.",
     "inputSchema": {"type": "object", "properties": {"id": DRAFT_ID, "confirm": {"type": "boolean"}}, "required": ["id", "confirm"]},
     "annotations": {"destructiveHint": False, "openWorldHint": True}},
    {"name": "linkedin_edit_post", "description": "Replace the text of a post that is already live (image, reactions and link "
     "stay). Public. Only call after the owner has approved the new text in the chat; set confirm=true only then. "
     "The judge must PASS on the new text.",
     "inputSchema": {"type": "object", "properties": {"id": DRAFT_ID, "text": {"type": "string"}, "confirm": {"type": "boolean"}},
                     "required": ["id", "text", "confirm"]}, "annotations": {"openWorldHint": True}},
]


def _load(did: str) -> tuple:
    f = L.STORE / f"{did}.json"
    if not f.exists():
        raise SystemExit(f"no draft {did}; call linkedin_list_drafts")
    return f, json.loads(f.read_text())


def _summary(d: dict) -> str:
    j = d.get("judge")
    return (f"id: {d['id']}\nstatus: {d['status']}\nsource: {d['source']['title']} ({d['source']['link']})\n"
            f"provider: {d.get('provider')}\nimage: {d.get('image') or 'none'}\n"
            + (f"url: {d['url']}\n" if d.get("url") else "")
            + (post_judge.report(j) + "\n" if j else "judge: not run\n")
            + f"\n{d['text']}")


def call(name: str, args: dict, cfg: dict) -> str:
    if name == "linkedin_status":
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            L.status()
        return buf.getvalue()
    if name == "linkedin_list_drafts":
        rows = []
        for f in sorted(L.STORE.glob("*.json")):
            x = json.loads(f.read_text())
            rows.append(f"{x['id']}  {x['status']:<9} {(x.get('judge') or {}).get('verdict', '-'):<11} {x['source']['title'][:70]}")
        return "\n".join(rows) or "no drafts"
    if name == "linkedin_show_draft":
        return _summary(_load(args["id"])[1])
    if name == "linkedin_create_draft":
        src = L.source_from_note(cfg) if args["source"] == "note" else L.source_from_brief(cfg)
        return _summary(L.draft(cfg, src))
    if name == "linkedin_update_draft":
        f, d = _load(args["id"])
        if d["status"] == "published":
            raise SystemExit("already published: use linkedin_edit_post")
        d["text"] = args["text"].strip()
        d["provider"] = (d.get("provider") or "").split("+")[0] + "+edited"
        L.complete_draft(d, cfg)
        L.run_judge(cfg, d)
        f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
        return _summary(d)
    if name == "linkedin_judge":
        f, d = _load(args["id"])
        L.complete_draft(d, cfg)
        v = L.run_judge(cfg, d)
        f.write_text(json.dumps(d, indent=1, ensure_ascii=False))
        return post_judge.report(v)
    if name == "linkedin_publish":
        if args.get("confirm") is not True:
            raise SystemExit("Not published: the owner has to approve this draft in the chat first (confirm=true).")
        L.publish(cfg, args["id"], yes=True)
        return "Published: " + (_load(args["id"])[1].get("url") or "")
    if name == "linkedin_edit_post":
        if args.get("confirm") is not True:
            raise SystemExit("Not edited: the owner has to approve the new text in the chat first (confirm=true).")
        return "Edited: " + L.edit_post(cfg, args["id"], args["text"].strip())
    raise SystemExit(f"unknown tool {name}")


def handle(msg: dict, cfg: dict) -> dict | None:
    mid, method = msg.get("id"), msg.get("method")
    if mid is None:                                            # notification (e.g. notifications/initialized)
        return None
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "watchfloor-linkedin", "version": "1.0"},
            "instructions": "Drafts and publishes the owner's LinkedIn posts. Publish and edit change a public profile: "
                            "show the owner the exact text first and call them with confirm=true only after they say yes."}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        p = msg.get("params", {})
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):              # stdout carries protocol messages only
                text, err = call(p.get("name", ""), p.get("arguments") or {}, cfg), False
        except SystemExit as e:
            text, err = str(e), True
        except Exception as e:  # noqa: BLE001
            log.error("%s", traceback.format_exc())
            text, err = f"{type(e).__name__}: {str(e)[:400]}", True
        extra = out.getvalue().strip()
        if extra:
            text = f"{extra}\n\n{text}"
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}], "isError": err}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(msg, cfg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
