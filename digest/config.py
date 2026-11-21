"""Load config.yaml + sources.yaml as one dict. Sources are the single registry of trusted inputs."""
from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    cfg = yaml.safe_load((ROOT / "config.yaml").read_text())
    src = yaml.safe_load((ROOT / "sources.yaml").read_text())
    for s in src["apis"] + src["feeds"]:
        if not s["url"].startswith("https://"):
            raise ValueError(f"source {s['name']} is not HTTPS")
    cfg["feeds"] = src["feeds"]
    cfg["sources"] = src
    cfg["tiers"] = {s["name"]: s["tier"] for s in src["apis"] + src["feeds"]}
    return cfg
