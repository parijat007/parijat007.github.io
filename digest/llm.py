"""LLM adapters. Default: local llama.cpp llama-server (OpenAI-compatible) with JSON-schema constrained decoding.

Provider is chosen by config `llm.provider` (or env DIGEST_LLM_PROVIDER):
  local      -> llama-server / LM Studio / Ollama OpenAI endpoint (no data leaves the Mac, $0)
  anthropic  -> Claude API (optional paid fallback)
"""
from __future__ import annotations

import logging
import os
import re

import requests

log = logging.getLogger("digest.llm")

ENUM = lambda *v: {"type": "string", "enum": list(v)}  # noqa: E731
DIGEST_SCHEMA = {
    "type": "object",
    "required": ["run_date", "quiet_day", "executive_pulse", "items", "notes"],
    "additionalProperties": False,
    "properties": {
        "run_date": {"type": "string"},
        "quiet_day": {"type": "boolean"},
        "executive_pulse": {"type": "string", "maxLength": 320},
        "notes": {"type": "string", "maxLength": 240},
        "items": {
            "type": "array", "maxItems": 8,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["rank", "headline", "category", "severity", "exploitation", "is_update",
                             "stack_match", "target", "identifiers", "kev_due_date", "summary", "action",
                             "hunt", "fixed_versions", "confidence", "primary_source", "corroborating_sources"],
                "properties": {
                    "rank": {"type": "integer"},
                    "headline": {"type": "string", "maxLength": 110},
                    "category": ENUM("ACTIVE_ATTACK", "VULNERABILITY", "SUPPLY_CHAIN", "AI_THREAT", "GITHUB_REPO"),
                    "severity": ENUM("CRITICAL", "HIGH", "MEDIUM", "INFO"),
                    "exploitation": ENUM("EXPLOITED_CONFIRMED", "EXPLOITED_REPORTED", "POC_PUBLIC",
                                         "NO_KNOWN_EXPLOIT", "N/A"),
                    "is_update": {"type": "boolean"},
                    "stack_match": {"type": "array", "items": {"type": "string"}},
                    "target": {"type": "string", "maxLength": 160},
                    "identifiers": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
                    "kev_due_date": {"type": ["string", "null"]},
                    "summary": {"type": "string", "maxLength": 360},
                    "action": {"type": "string", "maxLength": 240},
                    "hunt": {"type": ["string", "null"], "maxLength": 200},
                    "fixed_versions": {"type": ["string", "null"], "maxLength": 160},
                    "confidence": ENUM("HIGH", "MEDIUM", "LOW"),
                    "primary_source": {"type": "string"},
                    "corroborating_sources": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                },
            },
        },
    },
}

THINK_RE = re.compile(r"<think>.*?</think>", re.S)


def _openai_compat(name: str, pc: dict, system: str, user: str) -> tuple[str, dict]:
    """One code path for every provider: llama-server, Gemini, Groq, OpenRouter..."""
    base = os.environ.get(f"WF_{name.upper()}_BASE_URL", pc["base_url"]).rstrip("/")
    for var in re.findall(r"\{([A-Z0-9_]+)\}", base):    # e.g. Cloudflare's {CLOUDFLARE_ACCOUNT_ID}
        if not os.environ.get(var):
            raise RuntimeError(f"{name}: no API key in [{var}]")
        base = base.replace("{" + var + "}", os.environ[var])
    headers = {"Content-Type": "application/json"}
    key = next((os.environ[k] for k in pc.get("api_key_env", []) if os.environ.get(k)), None)
    if pc.get("api_key_env") and not key:
        raise RuntimeError(f"{name}: no API key in {pc['api_key_env']}")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    headers.update(pc.get("headers", {}))
    body = {
        "model": os.environ.get(f"WF_{name.upper()}_MODEL", pc["model"]),
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": pc.get("temperature", 0.2),
        "max_tokens": pc.get("max_output_tokens", 4000),
    }
    if pc.get("json") == "schema":
        # llama-server compiles the schema to a grammar: output cannot be malformed JSON
        body["response_format"] = {"type": "json_schema",
                                   "json_schema": {"name": "digest", "strict": True, "schema": DIGEST_SCHEMA}}
    elif pc.get("json") == "object":
        body["response_format"] = {"type": "json_object"}
    if pc.get("reasoning_effort"):
        body["reasoning_effort"] = pc["reasoning_effort"]
    if pc.get("no_think"):
        body["chat_template_kwargs"] = {"enable_thinking": False}   # Qwen3 family
    body.update(pc.get("extra_body", {}))      # provider-specific options, e.g. OpenRouter's reasoning
    url = f"{base}/chat/completions"
    r = requests.post(url, json=body, headers=headers, timeout=pc.get("timeout_seconds", 180),
                      allow_redirects=False)   # a redirect turns POST into GET; surface it instead
    if 300 <= r.status_code < 400:
        raise RuntimeError(f"{name}: redirected HTTP {r.status_code} from {url} to {r.headers.get('location')}")
    if r.status_code >= 400:
        raise RuntimeError(f"{name}: HTTP {r.status_code} {_error_detail(r)}")
    try:
        data = r.json()
    except ValueError:
        safe = {k: v for k, v in r.headers.items() if k.lower() in ("server", "x-github-request-id", "x-ms-error-code",
                                                                     "x-ratelimit-remaining-requests", "via", "www-authenticate")}
        raise RuntimeError(f"{name}: non-JSON response HTTP {r.status_code} "
                           f"content-type={r.headers.get('content-type')} url={r.url} body={r.text[:300]!r} "
                           f"headers={safe} history={[h.status_code for h in r.history]}") from None
    if not data.get("choices"):
        raise RuntimeError(f"{name}: no choices in response: {str(data)[:300]}")
    choice = data["choices"][0]
    text = THINK_RE.sub("", choice["message"].get("content") or "")
    if choice.get("finish_reason") == "length":
        raise RuntimeError(f"{name}: output truncated at max_tokens ({len(text)} chars); raise max_output_tokens")
    return text, data.get("usage", {})


def _error_detail(r) -> str:
    """Short, useful error text. For Google quota errors, name the exact limit that was hit."""
    try:
        body = r.json()
        body = body[0] if isinstance(body, list) else body
        err = body.get("error", body)
        parts = [str(err.get("message", ""))[:160]]
        for d in err.get("details", []) or []:
            for v in d.get("violations", []) or []:
                if v.get("quotaId"):
                    parts.append(f"quota={v['quotaId']} limit={v.get('quotaValue', '?')}")
            if d.get("retryDelay"):
                parts.append(f"retry_after={d['retryDelay']}")
        return " | ".join(p for p in parts if p)
    except (ValueError, AttributeError, TypeError):
        return r.text[:300]


_EXHAUSTED: set[str] = set()   # "provider/model" that hit a per-day quota in this run


# ---------- quota memory and usage log ----------
# A model that answered "daily quota used up" is skipped until its quota resets (Gemini: midnight Pacific), across
# runs on the same machine, instead of being asked again every ten minutes. Every call is logged so
# `python -m digest.llm usage` shows where the day's requests went. Neither file holds prompts, answers or keys.

def _state_dir():
    from pathlib import Path  # noqa: PLC0415
    return Path(os.environ.get("WF_STATE_DIR") or os.path.expanduser("~/.watchfloor"))


def _next_reset(pc: dict):
    from datetime import datetime, time, timedelta  # noqa: PLC0415
    from zoneinfo import ZoneInfo  # noqa: PLC0415
    tz = ZoneInfo(pc.get("quota_reset_tz", "UTC"))
    now = datetime.now(tz)
    return datetime.combine(now.date() + timedelta(days=1), time(0, 5), tz)


def _quota() -> dict:
    import json  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415
    try:
        data = json.loads((_state_dir() / "llm_quota.json").read_text())
    except (OSError, ValueError):
        return {}
    now = datetime.now(timezone.utc)
    return {k: v for k, v in data.items() if isinstance(v, str) and datetime.fromisoformat(v) > now}


def is_exhausted(name: str, model: str) -> bool:
    return f"{name}/{model}" in _EXHAUSTED or f"{name}/{model}" in _quota()


def mark_exhausted(name: str, model: str, pc: dict) -> None:
    import json  # noqa: PLC0415
    _EXHAUSTED.add(f"{name}/{model}")
    try:
        data = _quota()
        data[f"{name}/{model}"] = _next_reset(pc).isoformat()
        d = _state_dir()
        d.mkdir(parents=True, exist_ok=True)
        (d / "llm_quota.json").write_text(json.dumps(data, indent=1))
        log.info("%s/%s: daily quota used up; skipped until %s", name, model, data[f"{name}/{model}"])
    except OSError as e:
        log.warning("could not save the quota note (%s)", type(e).__name__)


def record(name: str, model: str, status: str, usage: dict | None, seconds: float) -> None:
    import json  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415
    row = {"t": datetime.now(timezone.utc).isoformat(timespec="seconds"), "job": os.environ.get("WF_JOB", "")[:40],
           "provider": name, "model": model, "status": status[:40], "s": round(seconds, 1),
           "in": (usage or {}).get("prompt_tokens") or (usage or {}).get("input_tokens") or 0,
           "out": (usage or {}).get("completion_tokens") or (usage or {}).get("output_tokens") or 0}
    try:
        d = _state_dir()
        d.mkdir(parents=True, exist_ok=True)
        f = d / "llm_usage.jsonl"
        if f.exists() and f.stat().st_size > 2_000_000:            # keep the log small: drop the older half
            lines = f.read_text().splitlines()
            f.write_text("\n".join(lines[len(lines) // 2:]) + "\n")
        with f.open("a") as fh:
            fh.write(json.dumps(row) + "\n")
    except OSError:
        pass


def usage_summary(days: int = 1) -> str:
    import json  # noqa: PLC0415
    from collections import Counter  # noqa: PLC0415
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415
    since = datetime.now(timezone.utc) - timedelta(days=days)
    ok, bad, tok = Counter(), Counter(), Counter()
    try:
        lines = (_state_dir() / "llm_usage.jsonl").read_text().splitlines()
    except OSError:
        return "no model calls logged on this machine yet"
    for ln in lines:
        try:
            r = json.loads(ln)
            if datetime.fromisoformat(r["t"]) < since:
                continue
        except (ValueError, KeyError):
            continue
        k = f"{r['provider']}/{r['model']}"
        (ok if r["status"] == "ok" else bad)[k] += 1
        tok[k] += r.get("in", 0) + r.get("out", 0)
    keys = sorted(set(ok) | set(bad), key=lambda k: -(ok[k] + bad[k]))
    out = [f"Model calls in the last {days} day(s) on this machine:"] + \
          [f"  {k:55} ok {ok[k]:3}  failed {bad[k]:3}  tokens {tok[k]:,}" for k in keys] or ["  none"]
    q = _quota()
    if q:
        out.append("Skipped until their daily quota resets:")
        out += [f"  {k} until {v}" for k, v in sorted(q.items())]
    return "\n".join(out)


def prioritise(names: list[str], cfg: dict) -> list[str]:
    """Background jobs (self-tests, the fixer, LinkedIn drafts, the judge: WF_JOB_PRIORITY=background) try the
    providers marked `reserve: true` (Gemini) last, so their small daily quotas are left for the daily brief."""
    if os.environ.get("WF_JOB_PRIORITY") != "background":
        return names
    reserved = [n for n in names if (cfg.get("providers") or {}).get(n, {}).get("reserve")]
    return [n for n in names if n not in reserved] + reserved


def _anthropic(name: str, pc: dict, system: str, user: str) -> tuple[str, dict]:
    import anthropic

    resp = anthropic.Anthropic(max_retries=3).messages.create(
        model=pc.get("model", "claude-sonnet-5-5"), max_tokens=pc.get("max_output_tokens", 4000),
        system=system, messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    return text, {"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens}


def chain(cfg: dict) -> list[str]:
    env = os.environ.get("WF_LLM_CHAIN")
    names = [c.strip() for c in env.split(",") if c.strip()] if env else cfg.get("chain", ["local"])
    return prioritise(names, cfg)


RETRYABLE = ("HTTP 413", "tokens_limit_reached", "HTTP 404", "HTTP 400", "HTTP 410", "deprecated", "not found", "does not exist", "HTTP 429", "HTTP 500", "HTTP 502",
             "HTTP 503", "HTTP 504", "truncated", "no choices")


def _retryable(msg: str) -> bool:
    return any(k in msg for k in RETRYABLE)


_DISCOVERED: dict[str, list[str]] = {}


def discover_free_models(pc: dict, limit: int = 4) -> list[str]:
    """OpenRouter: current free models that answer directly (no hidden reasoning) and do JSON.
    The free router can land on a 'thinking' model that spends the whole budget before answering."""
    key = pc["base_url"]
    if key in _DISCOVERED:
        return _DISCOVERED[key]
    try:
        data = requests.get(pc["base_url"].rstrip("/") + "/models", timeout=20).json().get("data", [])
    except (requests.RequestException, ValueError):
        return []
    picks, seen = [], {"free": 0, "json": 0, "context": 0}
    for m in data:
        sp = set(m.get("supported_parameters") or [])
        price = m.get("pricing") or {}
        free = m.get("id", "").endswith(":free") or (str(price.get("prompt")) == "0" and str(price.get("completion")) == "0")
        arch = m.get("architecture") or {}
        if not free or m.get("id") == "openrouter/free" or arch.get("output_modalities") not in (None, ["text"]):
            continue                                   # skip music, image and other non-text models
        seen["free"] += 1
        if not ({"response_format", "structured_outputs"} & sp):
            continue
        seen["json"] += 1
        if (m.get("context_length") or 0) < 32000:
            continue
        seen["context"] += 1
        # Prefer models without reasoning; a model that can reason is still usable because every request
        # switches reasoning off (config extra_body), and one that insists simply fails over to the next.
        picks.append(("reasoning" not in sp, m.get("context_length") or 0, m["id"]))
    log.info("%s: %d free models, %d with JSON output, %d with 32k+ context", pc.get("label", key),
             seen["free"], seen["json"], seen["context"])
    _DISCOVERED[key] = [p[-1] for p in sorted(picks, reverse=True)[:limit]]
    log.info("%s: discovered free models %s", pc.get("label", key), _DISCOVERED[key])
    return _DISCOVERED[key]


def complete(name: str, cfg: dict, system: str, user: str) -> str:
    pc = cfg["providers"][name]
    fn = _anthropic if pc.get("kind") == "anthropic" else _openai_compat
    models = pc.get("models") or [pc.get("model", "local")]
    if pc.get("discover_free"):
        models = discover_free_models(pc) + [m for m in models if m not in _DISCOVERED.get(pc["base_url"], [])]
    last = None
    import time as _t  # noqa: PLC0415
    skipped = 0
    for m in models:
        if is_exhausted(name, m):
            skipped += 1
            continue
        t0 = _t.monotonic()
        # Move to the next model when this one is retired (404/400), overloaded (429/5xx),
        # slow (timeout) or cut off: one busy model must not take out the whole provider.
        try:
            try:
                text, usage = fn(name, {**pc, "model": m}, system, user)
            except RuntimeError as e:
                # Providers with per-minute anonymous limits (OVHcloud: 2/min per model) ask to wait, not to give up.
                if not (pc.get("wait_on_429") and "HTTP 429" in str(e)):
                    raise
                import time  # noqa: PLC0415
                log.info("%s: %s is rate limited; waiting %ss and trying it once more", name, m, pc["wait_on_429"])
                time.sleep(pc["wait_on_429"])
                text, usage = fn(name, {**pc, "model": m}, system, user)
            log.info("LLM provider=%s model=%s usage=%s", name, m, usage)
            record(name, m, "ok", usage, _t.monotonic() - t0)
            pc["_used_model"] = m
            return text
        except (RuntimeError, requests.RequestException) as e:
            err = e if isinstance(e, RuntimeError) else RuntimeError(f"{name}: {type(e).__name__} on {m}")
            msg = str(e)
            record(name, m, (re.search(r"HTTP \d+", msg) or [type(e).__name__])[0], None, _t.monotonic() - t0)
            if "PerDay" in msg or "per day" in msg.lower():   # daily quota gone: skip it until it resets
                mark_exhausted(name, m, pc)
            if last is None or "HTTP 404" not in msg:     # a retired model says less than an overload
                last = err
            if "no API key" in msg or not (_retryable(msg) or isinstance(e, requests.RequestException)):
                raise last from None
            log.warning("%s: model %s failed (%s), trying next model", name, m, msg[:260])
    if last is None and skipped:
        raise RuntimeError(f"{name}: every model is out of daily quota (HTTP 429 PerDay); skipped until it resets")
    raise last or RuntimeError(f"{name}: no models configured")


def local_up(cfg: dict) -> bool:
    pc = cfg["providers"].get("local", {})
    base = os.environ.get("WF_LOCAL_BASE_URL", pc.get("base_url", "http://127.0.0.1:8080/v1")).rstrip("/")
    try:
        return requests.get(base.removesuffix("/v1") + "/health", timeout=3).status_code == 200
    except requests.RequestException:
        return False


def ensure_local(cfg: dict):
    """Start the Mac's local model for a short job (e.g. a LinkedIn draft) when it is not running, so routine
    drafting uses the Mac instead of free cloud quotas. Returns the process to stop afterwards, or None when the
    model was already up, cannot be started here, or another llama-server (e.g. a SEC545 batch) holds the memory."""
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    import time  # noqa: PLC0415
    if os.environ.get("WF_LOCAL_ONDEMAND", "1") == "0" or local_up(cfg):
        return None
    server, model = os.environ.get("LLAMA_SERVER", ""), os.path.expanduser(os.environ.get("MODEL_PATH", ""))
    if not (server and model and os.path.exists(server) and os.path.exists(model)):
        return None
    if shutil.which("pgrep") and subprocess.run(["pgrep", "-x", "llama-server"], capture_output=True).returncode == 0:
        log.info("local model: another llama-server is running; leaving the memory to it")
        return None
    port, ctx = os.environ.get("LLAMA_PORT", "8080"), os.environ.get("LLAMA_CTX", "32768")
    logf = open(os.path.expanduser("~/Library/Logs/watchfloor-llama.log"), "ab")  # noqa: SIM115
    proc = subprocess.Popen([server, "-m", model, "--port", port, "-c", ctx, "-ngl", "99", "-fa", "on", "-ctk", "q8_0",
                             "-ctv", "q8_0", "--jinja", "--host", "127.0.0.1"], stdout=logf, stderr=logf)
    for _ in range(90):
        if local_up(cfg):
            log.info("local model: started for this job")
            return proc
        if proc.poll() is not None:
            break
        time.sleep(2)
    log.warning("local model: did not start; using cloud models")
    proc.terminate()
    return None


def stop_local(proc) -> None:
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except Exception:  # noqa: BLE001
            proc.kill()
        log.info("local model: stopped")


if __name__ == "__main__":
    import sys
    if sys.argv[1:2] == ["usage"]:
        print(usage_summary(int(sys.argv[2]) if len(sys.argv) > 2 else 1))
    else:
        print("usage: python -m digest.llm usage [days]")
