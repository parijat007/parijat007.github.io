---
title: "AI Security Spotlight: when the tool tells the agent what to do"
date: 2026-11-25
summary: >
  Model Context Protocol (MCP) servers are now a supply-chain risk of their own. This week: new research finds
  prompt injection and tool poisoning are the leading technique in flagged MCP servers, AWS fixed a flaw where
  prompt injection made its ECS MCP server hand back cleartext secrets, and a Langflow MCP flaw has been under
  automated attack since September. What happened, how the attack works, and what to check.
tlp: CLEAR
tags: [AI Security Spotlight, MCP, AI agents, Supply chain, Prompt injection]
visual:
  kicker: AI Security Spotlight
  title: When the tool tells the agent what to do
  steps:
    - The agent reads text an attacker can influence (a ticket, log line, page or tool description)
    - Hidden instructions ask it to troubleshoot a service
    - It calls a legitimate tool with its own legitimate access
    - Before 0.1.36, the ECS MCP tool returned secrets in cleartext
    - The same instructions ask the agent to repeat or send them
  highlight: 4
  figures:
    - {value: "22%", label: "of 834 flagged MCP servers: prompt injection or tool poisoning", state: reported}
    - {value: "0.1.36", label: "ECS MCP Server fix for CVE-2026-135614", state: confirmed}
    - {value: "1,423", label: "Langflow attempts logged on honeypots", state: reported}
status:
  - {claim: "Prompt injection or tool poisoning in 22% of flagged MCP servers", state: reported, note: "OX Security research, 834 flagged MCP servers, July to October 2026; flagged does not mean malicious"}
  - {claim: "Amazon ECS MCP Server leaks secrets to prompt injection (CVE-2026-135614)", state: confirmed, note: "AWS advisory, fixed in 0.1.36"}
  - {claim: "Langflow MCP stdio command injection (CVE-2026-105740) attacked in the wild", state: reported, note: "Honeypot data; not in CISA KEV as of 25 November 2026"}
  - {claim: "Langflow code injection CVE-2026-9198 exploited", state: confirmed, note: "In CISA KEV since 4 August 2026"}
sources:
  - {title: "OX Security: Plug and Pray, how AI is changing software supply chain attacks (press release)", url: "https://finance.yahoo.com/technology/ai/articles/ai-agents-taking-orders-strangers-150000503.html"}
  - {title: "AWS security bulletin 2026-200-AWS: Amazon ECS MCP Server", url: "https://aws.amazon.com/security/security-bulletins/2026-200-aws/"}
  - {title: "GitHub advisory GHSA-ppc7-5jf2-gcfc (awslabs/mcp)", url: "https://github.com/awslabs/mcp/security/advisories/GHSA-ppc7-5jf2-gcfc"}
  - {title: "CVE-2026-135614 record", url: "https://www.strix.ai/cve/CVE-2026-135614"}
  - {title: "SecNews: CVE-2026-105740, 1,423 attempts to exploit Langflow", url: "https://www.secnews.gr/en/740618/cve-2026-105740-langflow-eypatheia-rce/"}
  - {title: "CSA Singapore: active exploitation of IBM Langflow OSS (CVE-2026-9198)", url: "https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2026-099/"}
  - {title: "OWASP Top 10 for Agentic Applications", url: "https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agent"}
  - {title: "MITRE ATLAS: LLM Prompt Injection, Indirect (AML.T0051.001)", url: "https://d3fend.mitre.org/offensive-technique/attack/AML.T0051.001/"}
  - {title: "MITRE ATT&CK: Indirect Prompt Injection (T1698)", url: "https://attack.mitre.org/techniques/T1698/"}
---

## What is happening

An AI agent does what its tools tell it, with the permissions it already holds. That turns every Model Context
Protocol (MCP) server an agent connects to into part of its supply chain, and three items this month show the
risk from three sides.

| Date (2026) | Item | Status |
|---|---|---|
| 23 Nov | OX Security research on 834 flagged MCP servers: prompt injection or tool poisoning in 22%, install-time code execution in 16% | Reported (vendor research) |
| 24 Nov | AWS fixes CVE-2026-135614: prompt injection makes the Amazon ECS MCP Server return cleartext secrets | Confirmed, fixed in 0.1.36 |
| Since Sep | Langflow CVE-2026-105740: commands injected through MCP server settings run on the Langflow host; 1,423 attempts logged on honeypots | Reported exploitation, fixed in 1.9.0 |

**The shift:** in package registries, malicious code usually runs at install. OX Security found the order reversed
for MCP servers: the poisoned tool does not need to run anything itself. It instructs the agent, and the agent
uses its own access. Two more figures from the same research stand out: 83% of the flagged MCP servers ran code
that could not be independently verified, and two publisher accounts were behind 44% of them. Flagged is not
the same as malicious, and OX does not claim every weakness was exploited.

## How the attack works

Take the AWS case, because it is confirmed and fixed. The ECS MCP Server has a troubleshooting tool, and a setting
that redacts secrets from what it returns.

1. The agent reads something an attacker can influence: a ticket, a log line, a web page, a tool description.
2. Hidden instructions in that text ask the agent to "troubleshoot" a service.
3. The agent calls the troubleshooting tool, a legitimate action with legitimate access.
4. Before version 0.1.36, the tool returned task-definition environment variables and secret references in
   cleartext, despite the redaction setting.
5. The agent now holds the secrets in its context, where the same injected instructions can ask it to repeat or
   send them.

No exploit code, no malware, no unusual login. Every step is the agent doing its job, which is why this class is
hard to see with controls built for code execution.

The Langflow flaw is the blunter version of the same lesson. Langflow let a user define an MCP server's command,
arguments and environment variables, then ran them on the server. An attacker with a low-privilege account, or
none where authentication was off, could run commands as the Langflow process. Langflow has also had a separate
code-injection flaw (CVE-2026-9198) confirmed exploited and listed in CISA KEV since August: AI workflow builders
are now routine targets.

## Mapped to the frameworks

| Step | OWASP LLM Top 10 (2025) | OWASP Agentic Top 10 | MITRE ATLAS | MITRE ATT&CK |
|---|---|---|---|---|
| Instructions hidden in content or a tool description | LLM01 Prompt Injection | ASI01 Agent Goal Hijack | AML.T0051.001 Indirect prompt injection | T1698 Indirect Prompt Injection |
| A poisoned or unverified MCP server in the toolchain | LLM03 Supply Chain | ASI04 Agentic Supply Chain Vulnerabilities | AML.T0010 AI Supply Chain Compromise | |
| Agent calls a legitimate tool for the attacker | LLM06 Excessive Agency | ASI02 Tool Misuse and Exploitation | AML.T0053 AI Agent Tool Invocation | |
| Secrets returned to the agent and passed on | LLM02 Sensitive Information Disclosure | ASI03 Identity and Privilege Abuse | | |

## What to do this week

**Patch:**
- Amazon ECS MCP Server (`awslabs.ecs-mcp-server`): upgrade to 0.1.36 or later, then rotate any credential kept
  as a plaintext task-definition environment variable. Move those to AWS Secrets Manager or Parameter Store references.
- Langflow: upgrade to 1.9.0 or later; the broader MCP execution fix is in 1.10.3. Keep authentication on and the
  instance off the internet.

**Inventory:** you cannot defend MCP servers you do not know about. Look for MCP client configuration on
developer machines and build hosts: `mcp.json` files in editor settings folders (`.vscode`, `.cursor`), and
`claude_desktop_config.json`. Record who published each server, where its code comes from, and the token it holds.

**Reduce what a hijacked agent can reach:**
- Give each MCP server its own narrowly scoped credential, not a developer's personal token.
- Keep secrets out of anything a tool can return: environment variables in task definitions are visible to every
  role with describe permissions.
- Require a human approval step for tools that write, send or delete.
- Pin MCP servers to reviewed versions. A server that changes without a release is a finding in itself.

**Hunt** (adapt to your own logging):
- AWS CloudTrail: `ecs:DescribeTaskDefinition` and `secretsmanager:GetSecretValue` calls from roles used by
  AI agents or MCP servers, especially in bursts or outside the agent's normal pattern.
- Langflow hosts: shell or interpreter processes started by the Langflow process, and outbound connections from it
  to hosts it does not normally reach.
- Agent hosts: new outbound destinations right after an agent read external content (a ticket, a page, an email).

## Why it matters

Prompt injection is no longer only a model problem. Once an agent has tools and credentials, a single paragraph
of text in the wrong place can act with that agent's permissions. Treat MCP servers like any third-party code
with production access: inventoried, pinned, least-privileged, and logged.
