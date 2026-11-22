"""Offline tests: no network. Run with `python -m pytest -q tests`."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from digest import llm
from digest.main import _sentences, fallback_digest
from digest.render import pack, parse_json, render, validate

HERE = Path(__file__).parent
ITEMS = json.loads((HERE / "sample_items.json").read_text())
LLM_OUT = (HERE / "sample_llm.json").read_text()


def test_validate_drops_urls_not_in_input():
    digest, problems = validate(parse_json(LLM_OUT), ITEMS)
    urls = [e["primary_source"] for e in digest["items"]]
    assert "https://not-in-input.example/x" not in urls
    assert all("evil.example" not in u for e in digest["items"] for u in e["corroborating_sources"])
    assert [e["rank"] for e in digest["items"]] == [1, 2]
    assert any("URL not in input" in p for p in problems)


def test_validate_enforces_caps():
    many = {"items": [{"headline": f"t{i}", "category": "VULNERABILITY", "primary_source": ITEMS[0]["url"]}
                      for i in range(9)]}
    digest, _ = validate(many, ITEMS)
    assert len(digest["items"]) == 5


def test_pack_never_exceeds_limit_and_keeps_items_whole():
    digest, _ = validate(parse_json(LLM_OUT), ITEMS)
    blocks = render(digest, "2026-11-21", "footer")
    for limit in (400, 1400, 3800):
        msgs = pack(blocks, limit)
        assert all(len(m) <= limit for m in msgs)


def test_fallback_is_deterministic_and_sourced():
    d = fallback_digest(ITEMS, "2026-11-21")
    assert d["items"] and all(e["primary_source"] in {i["url"] for i in ITEMS} for e in d["items"])
    assert d["items"][0]["exploitation"] == "EXPLOITED_CONFIRMED"


def test_sentences_never_cuts_mid_word():
    s = _sentences("First sentence is here. Second one is much longer and keeps going on and on", 40)
    assert s == "First sentence is here."
    assert _sentences("word " * 30, 50).endswith("…")


def test_parse_json_strips_fences():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}


# ---- local LLM adapter against a mock llama-server -------------------------------------------
class _Mock(BaseHTTPRequestHandler):
    seen = {}

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Mock.seen = body
        content = "<think>internal</think>" + LLM_OUT
        out = json.dumps({"choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 1}})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(out.encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def mock_server():
    srv = HTTPServer(("127.0.0.1", 0), _Mock)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()


LOCAL = {"providers": {"local": {"base_url": "http://unused", "model": "local", "json": "schema", "no_think": True}}}


def test_local_llm_sends_schema_and_strips_think(mock_server, monkeypatch):
    monkeypatch.setenv("WF_LOCAL_BASE_URL", mock_server)
    text = llm.complete("local", LOCAL, "sys", "user")
    assert "<think>" not in text and parse_json(text)["items"]
    sent = _Mock.seen
    assert sent["response_format"]["type"] == "json_schema"
    assert sent["chat_template_kwargs"] == {"enable_thinking": False}


# ---- site: model/feed text must never become markup --------------------------------------------
def test_site_escapes_hostile_text(tmp_path, monkeypatch):
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location("site_build", HERE.parent / "site" / "build.py")
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)

    data = tmp_path / "data" / "briefs"
    data.mkdir(parents=True)
    evil = parse_json(LLM_OUT)
    evil["items"][0]["headline"] = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    evil["items"][0]["primary_source"] = "javascript:alert(3)"
    (data / "2026-11-21.json").write_text(json.dumps(evil))
    monkeypatch.setattr(sb, "DATA", tmp_path / "data")
    out = tmp_path / "_site"
    sb.build(out)
    html = (out / "index.html").read_text()
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert 'href="javascript:' not in html


# ---- autonomy: provider chain and facts-only fallback ---------------------------------------
def _cfg(mock_url):
    from digest.config import load_config
    cfg = load_config()
    cfg["llm"]["chain"] = ["local", "gemini"]
    cfg["llm"]["providers"]["local"]["base_url"] = "http://127.0.0.1:9/v1"      # nothing listening
    cfg["llm"]["providers"]["gemini"]["base_url"] = mock_url
    return cfg


def test_chain_falls_through_to_next_provider(mock_server, monkeypatch):
    from digest.main import call_llm
    monkeypatch.setenv("GEMINI_API_KEY", "test")
    monkeypatch.delenv("WF_LLM_CHAIN", raising=False)
    text, provider = call_llm(_cfg(mock_server), ITEMS, {"RUN_DATE": "2026-11-21"})
    assert provider == "gemini" and parse_json(text)["items"]
    assert _Mock.seen["response_format"] == {"type": "json_object"}


def test_all_providers_down_raises_so_main_uses_facts_only(monkeypatch):
    from digest.main import call_llm
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    cfg = _cfg("http://127.0.0.1:9/v1")
    with pytest.raises(RuntimeError, match="all model providers failed"):
        call_llm(cfg, ITEMS, {"RUN_DATE": "2026-11-21"})


# ---- source legitimacy -------------------------------------------------------------------------
def test_press_only_exploitation_claim_is_downgraded():
    items = [{"id": "x", "source_name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/a", "cves": []}]
    d = {"items": [{"headline": "h", "category": "ACTIVE_ATTACK", "exploitation": "EXPLOITED_CONFIRMED",
                    "confidence": "HIGH", "primary_source": "https://www.bleepingcomputer.com/a"}]}
    out, problems = validate(d, items, {"BleepingComputer": "press"})
    e = out["items"][0]
    assert e["exploitation"] == "EXPLOITED_REPORTED" and e["confidence"] == "MEDIUM"
    assert any("downgraded" in p for p in problems)


def test_vendor_source_can_confirm():
    items = [{"id": "x", "source_name": "Cisco PSIRT", "url": "https://sec.cloudapps.cisco.com/a", "cves": []}]
    d = {"items": [{"headline": "h", "category": "VULNERABILITY", "exploitation": "EXPLOITED_CONFIRMED",
                    "primary_source": "https://sec.cloudapps.cisco.com/a"}]}
    out, _ = validate(d, items, {"Cisco PSIRT": "vendor"})
    assert out["items"][0]["exploitation"] == "EXPLOITED_CONFIRMED"


def test_sources_registry_is_https_and_tiered():
    from digest.config import load_config
    cfg = load_config()
    assert all(s["url"].startswith("https://") for s in cfg["sources"]["feeds"])
    assert set(cfg["tiers"].values()) <= {"authority", "vendor", "research", "press", "data"}
    assert all(f.get("domains") for f in cfg["feeds"])


# ---- Teams -------------------------------------------------------------------------------------
def test_teams_card_shape_and_size():
    from digest import teams
    digest, _ = validate(parse_json(LLM_OUT), ITEMS)
    card = teams.brief_card(digest, "2026-11-21", "https://example.github.io")
    assert card["type"] == "AdaptiveCard" and len(json.dumps(card)) < teams.MAX_BYTES
    assert card["actions"][0]["url"].endswith("/brief/2026-11-21/")


# ---- remediation ----------------------------------------------------------------------------
def test_fixed_version_must_appear_in_source():
    from digest.playbook import grounded_versions
    src = "Fixed in FortiOS 7.4.5 and 7.2.10. Upgrade immediately."
    assert grounded_versions("FortiOS 7.4.5, 7.2.10", src) == "FortiOS 7.4.5, 7.2.10"
    assert grounded_versions("FortiOS 7.4.6", src) is None          # invented version dropped
    assert grounded_versions("latest", src) is None                 # no version number, no claim


def test_validate_strips_invented_version_and_adds_controls():
    items = [{"id": "x", "source_name": "Cisco PSIRT", "url": "https://sec.cloudapps.cisco.com/a",
              "title": "Cisco Expressway hard-coded credentials", "text": "Fixed in release 15.3.1.", "cwes": ["CWE-798"]}]
    d = {"items": [{"headline": "Cisco Expressway hard-coded credentials", "category": "VULNERABILITY",
                    "exploitation": "EXPLOITED_CONFIRMED", "fixed_versions": "15.4",
                    "primary_source": "https://sec.cloudapps.cisco.com/a"}]}
    out, problems = validate(d, items, {"Cisco PSIRT": "vendor"})
    rm = out["items"][0]["remediation"]
    assert rm["fixed_versions"] is None and any("not in source" in p for p in problems)
    assert rm["weakness"] == "Hard-coded credentials"
    assert any("management interface" in c for c in rm["compensating_controls"])   # edge device control


def test_playbook_classifies_by_cwe_then_keywords():
    from digest.playbook import classify
    assert classify(["CWE-502"], "") == "deserialization"
    assert classify([], "authentication bypass using an alternate path or channel") == "auth"
    assert classify([], "something else") == "default"


def test_poc_label_requires_evidence():
    items = [{"id": "x", "source_name": "Cisco PSIRT", "url": "https://sec.cloudapps.cisco.com/b",
              "title": "OpenJDK flaw", "text": "A vulnerability could allow remote code execution.", "cves": []}]
    d = {"items": [{"headline": "h", "category": "VULNERABILITY", "exploitation": "POC_PUBLIC",
                    "primary_source": "https://sec.cloudapps.cisco.com/b"}]}
    out, problems = validate(d, items, {"Cisco PSIRT": "vendor"})
    assert out["items"][0]["exploitation"] == "NO_KNOWN_EXPLOIT"
    items[0]["public_poc"] = {"count": 3}
    d["items"][0]["exploitation"] = "POC_PUBLIC"
    out, _ = validate(d, items, {"Cisco PSIRT": "vendor"})
    assert out["items"][0]["exploitation"] == "POC_PUBLIC"


def test_headline_cannot_overclaim_exploitation():
    items = [{"id": "x", "source_name": "Cisco PSIRT", "url": "https://sec.cloudapps.cisco.com/c",
              "title": "nginx flaws", "text": "Vulnerabilities in nginx affect products.", "cves": []}]
    d = {"items": [{"headline": "nginx RCEs Exploited in Palo Alto & Cisco Products", "category": "VULNERABILITY",
                    "exploitation": "NO_KNOWN_EXPLOIT", "primary_source": "https://sec.cloudapps.cisco.com/c"}]}
    out, problems = validate(d, items, {"Cisco PSIRT": "vendor"})
    assert "xploited" not in out["items"][0]["headline"]
    assert any("toned down" in p for p in problems)


def test_notes_render_and_escape_raw_html(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("site_build2", HERE.parent / "site" / "build.py")
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)
    notes = tmp_path / "data" / "notes"
    notes.mkdir(parents=True)
    (notes / "2026-11-21-test.md").write_text(
        "---\ntitle: Test note\ndate: 2026-11-21\nsummary: s\nstatus:\n  - {claim: c, state: reported, note: n}\n"
        "sources:\n  - {title: bad, url: 'javascript:alert(1)'}\n---\n\n## Heading\n\n<script>alert(1)</script>\n\n| a | b |\n|---|---|\n| 1 | 2 |\n")
    monkeypatch.setattr(sb, "DATA", tmp_path / "data")
    out = tmp_path / "_site"
    sb.build(out)
    html = (out / "notes" / "2026-11-21-test" / "index.html").read_text()
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert "<table>" in html and 'href="javascript:' not in html
    assert "Test note" in (out / "notes" / "index.html").read_text()


def test_official_record_becomes_primary_and_nulls_and_tracking_are_cleaned():
    kev = {"id": "CVE-2026-129448", "source_name": "CISA KEV", "title": "VMware vCenter",
           "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-129448", "cves": ["CVE-2026-129448"],
           "kev": {"dueDate": "2026-11-23"}}
    news = {"id": "n", "source_name": "The Hacker News", "title": "Hackers exploit CVE-2026-129448",
            "url": "https://thehackernews.com/a?utm_source=rss", "cves": ["CVE-2026-129448"],
            "kev": {"dueDate": "2026-11-23"}}
    cisco = {"id": "c", "source_name": "Cisco PSIRT", "title": "nginx",
             "url": "https://sec.cloudapps.cisco.com/x?vs_f=Cisco%20Security%26vs_k=1", "cves": []}
    d = {"items": [
        {"headline": "vCenter", "category": "VULNERABILITY", "exploitation": "EXPLOITED_CONFIRMED",
         "identifiers": ["CVE-2026-129448"], "hunt": "null", "fixed_versions": "None",
         "primary_source": "https://thehackernews.com/a?utm_source=rss"},
        {"headline": "nginx", "category": "VULNERABILITY", "exploitation": "NO_KNOWN_EXPLOIT",
         "primary_source": cisco["url"]}]}
    tiers = {"CISA KEV": "authority", "The Hacker News": "press", "Cisco PSIRT": "vendor"}
    out, problems = validate(d, [kev, news, cisco], tiers)
    a, b = out["items"]
    assert a["primary_source"] == kev["url"]
    assert a["corroborating_sources"] == ["https://thehackernews.com/a"]
    assert a["hunt"] is None and a["fixed_versions"] is None
    text = "\n".join(render(out, "2026-11-22"))
    assert "Hunt" not in text and "null" not in text
    assert b["primary_source"] == "https://sec.cloudapps.cisco.com/x"
    assert any("official record" in p for p in problems)


def test_profile_drafts_never_publish():
    import importlib.util
    import yaml
    spec = importlib.util.spec_from_file_location("site_build3", HERE.parent / "site" / "build.py")
    sb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sb)
    raw = {"awards": [{"name": "A", "confirm": True}, {"name": "B"}],
           "earlier": {"names": "x", "confirm": True}, "links": [{"label": "L"}]}
    pub, prev = sb.gate_profile(raw, False), sb.gate_profile(raw, True)
    assert [a["name"] for a in pub["awards"]] == ["B"] and "earlier" not in pub
    assert len(prev["awards"]) == 2 and "earlier" in prev
    # The real profile: nothing published may still carry a [placeholder]
    live = sb.gate_profile(yaml.safe_load((HERE.parent / "site" / "profile.yaml").read_text()), False)
    import re
    assert not re.search(r"\[[a-z][^\]]*\]", yaml.safe_dump(live, allow_unicode=True)), "placeholder in published profile"


def test_linkedin_little_text_and_checks(monkeypatch):
    from digest import linkedin as L
    t = L.little_text("Patch (now) #CloudSecurity see https://theparijat.com/notes/x_y/ a_b")
    assert "\\(now\\)" in t and "{hashtag|\\#|CloudSecurity}" in t
    assert "https://theparijat.com/notes/x_y/" in t and "a\\_b" in t
    cfg = {"site": {"url": "https://theparijat.com"}, "linkedin": {"never_name": ["Hearst"]}}
    src = {"link": "https://theparijat.com/notes/n/", "urls": ["https://www.cisa.gov/a"]}
    good = "Finding.\n\n" + "Detail line. " * 30 + "\nhttps://www.cisa.gov/a\nhttps://theparijat.com/notes/n/\n#A #B"
    assert L.check(good, src, cfg) == []
    bad = good + "\nAt Hearst we delve into https://evil.example/x"
    probs = " ".join(L.check(bad, src, cfg))
    assert "Hearst" in probs and "delve" in probs and "evil.example" in probs


def test_linkedin_publish_needs_approval_and_posts_once(monkeypatch, tmp_path):
    from digest import linkedin as L
    monkeypatch.setattr(L, "STORE", tmp_path)
    cfg = {"site": {"url": "https://theparijat.com"}, "linkedin": {"never_name": []}}
    text = "Finding.\n\n" + "Detail line. " * 30 + "\nhttps://theparijat.com/notes/n/"
    (tmp_path / "d1.json").write_text(json.dumps({"id": "d1", "status": "draft", "text": text,
        "source": {"kind": "note", "title": "t", "link": "https://theparijat.com/notes/n/"}}))
    monkeypatch.setattr(L, "secret", lambda n: {"linkedin-access-token": "tok",
                                                "linkedin-person-urn": "urn:li:person:abc"}.get(n))
    sent = []

    class R:
        status_code, text, headers = 201, "", {"x-restli-id": "urn:li:share:1"}
    monkeypatch.setattr(L.requests, "post", lambda url, **kw: sent.append((url, kw)) or R())
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    L.publish(cfg, "d1")
    assert sent == []                                   # declined: nothing posted
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    L.publish(cfg, "d1")
    url, kw = sent[0]
    assert url.endswith("/rest/posts") and kw["json"]["author"] == "urn:li:person:abc"
    assert kw["headers"]["LinkedIn-Version"] and kw["json"]["visibility"] == "PUBLIC"
    with pytest.raises(SystemExit):
        L.publish(cfg, "d1")                            # already published: refuses to repost


def test_linkedin_blocks_employment_sensitive_wording():
    from digest import linkedin as L
    cfg = {"site": {"url": "https://theparijat.com"}, "linkedin": {"never_name": []}}
    src = {"link": "https://theparijat.com/notes/n/", "urls": []}
    base = "Finding.\n\n" + "Detail line. " * 30 + "\nhttps://theparijat.com/notes/n/"
    for phrase in ["I am open to work.", "Available for consulting.", "At work we saw this.",
                   "Our SOC blocked it.", "DM me for help."]:
        assert any("employment-sensitive" in x for x in L.check(base + "\n" + phrase, src, cfg)), phrase
    assert L.check(base, src, cfg) == []
