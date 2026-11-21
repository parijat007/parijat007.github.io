# Watchfloor architecture

```mermaid
flowchart TB
  subgraph SRC["Trusted sources (sources.yaml)"]
    A1[CISA KEV · NVD · GitHub Advisory<br/>authority]
    A2[MSRC · Palo Alto · Fortinet · Cisco · AWS<br/>vendor PSIRTs]
    A3[Unit 42 · Google TI · Microsoft TI<br/>research]
    A4[BleepingComputer · THN · SecurityWeek · The Record · Krebs<br/>press]
    A5[EPSS · PoC-in-GitHub · GitHub search<br/>data]
  end

  subgraph GATE["Collect and gate (no LLM)"]
    G1[HTTPS only · off-domain links dropped]
    G2[Enrich: KEV flag + due date, CVSS, EPSS,<br/>PoC count, corroboration count, stack match]
    G3[Dedupe · pre-rank · cap items]
  end
  SRC --> G1 --> G2 --> G3

  subgraph HOURLY["GitHub Actions · every hour"]
    H1[watch.py: KEV + vendor + critical GHSA]
    H2{New KEV hits<br/>stack watchlist?}
  end
  G3 --> H1 --> H2

  subgraph DAILY["Daily brief · model chain"]
    M0{Mac awake?<br/>6:35 AM + on wake}
    M1[Local llama-server<br/>Qwen3.6-35B-A3B · JSON grammar]
    M2[GitHub Models<br/>free · built-in token]
    M3[Gemini free tier]
    M4[Facts-only brief<br/>no model]
    C0{Cloud check 7:20 AM ET:<br/>brief already published?}
  end
  G3 --> M0
  M0 -- yes --> M1
  M0 -- no --> C0
  C0 -- no --> M2
  C0 -- yes --> SKIP[skip]
  M1 -- fails / busy --> M2
  M2 -- fails / quota --> M3
  M3 -- fails --> M4

  subgraph VAL["Validate before publish"]
    V1[Schema check]
    V2[Every URL must be collected]
    V3[Claim guard: press-only cannot be<br/>'confirmed'; confidence capped]
    V4[Caps: 5 threats + 3 repos]
  end
  M1 & M2 & M3 & M4 --> V1 --> V2 --> V3 --> V4

  subgraph OUT["Publish and deliver"]
    D1[(data/briefs/*.json<br/>data/watch.json<br/>git = audit trail)]
    D2[GitHub Pages: profile + today + watch<br/>+ archive + sources + RSS/JSON]
    D3[WhatsApp · CallMeBot]
    D4[Microsoft Teams · Workflows webhook<br/>Adaptive Card]
  end
  V4 --> D1 --> D2
  V4 --> D3 & D4
  H1 --> D1
  H2 -- yes --> D3 & D4

  subgraph OPS["Operate"]
    O1[CI tests on every change]
    O2[Dead-man's switch pings]
    O3[Source health on /method]
    O4[Report-an-error issues]
  end
  D2 -.-> O3
