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
    """One code path for every provider: llama-server, GitHub Models, Gemini, Groq, OpenRouter..."""
    base = os.environ.get(f"WF_{name.upper()}_BASE_URL", pc["base_url"]).rstrip("/")
    headers = {"Content-Type": "application/json"}
    key = next((os.environ[k] for k in pc.get("api_key_env", []) if os.environ.get(k)), None)
    if pc.get("api_key_env") and not key:
        raise RuntimeError(f"{name}: no API key in {pc['api_key_env']}")
    if key:
        headers["Authorization"] = f"Bearer {key}"
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
    if pc.get("no_think"):
        body["chat_template_kwargs"] = {"enable_thinking": False}   # Qwen3 family
    r = requests.post(f"{base}/chat/completions", json=body, headers=headers,
                      timeout=pc.get("timeout_seconds", 180))
    if r.status_code >= 400:
        raise RuntimeError(f"{name}: HTTP {r.status_code} {r.text[:200]}")
    data = r.json()
    text = THINK_RE.sub("", data["choices"][0]["message"].get("content") or "")
    return text, data.get("usage", {})


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
    return [c.strip() for c in env.split(",") if c.strip()] if env else cfg.get("chain", ["local"])


def complete(name: str, cfg: dict, system: str, user: str) -> str:
    pc = cfg["providers"][name]
    fn = _anthropic if pc.get("kind") == "anthropic" else _openai_compat
    text, usage = fn(name, pc, system, user)
    log.info("LLM provider=%s model=%s usage=%s", name, pc.get("model"), usage)
    return text


def local_up(cfg: dict) -> bool:
    pc = cfg["providers"].get("local", {})
    base = os.environ.get("WF_LOCAL_BASE_URL", pc.get("base_url", "http://127.0.0.1:8080/v1")).rstrip("/")
    try:
        return requests.get(base.removesuffix("/v1") + "/health", timeout=3).status_code == 200
    except requests.RequestException:
        return False
