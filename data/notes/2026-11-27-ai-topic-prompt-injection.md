---
title: 'AI Security Topics: Prompt Injection'
date: '2026-11-27'
summary: Prompt injection occurs when manipulated inputs alter a large language model's intended behavior or output.
  Defenders must implement robust architecture controls because techniques like RAG and fine-tuning fail to fully
  prevent these stochastic vulnerabilities.
tlp: CLEAR
tags:
- AI Security Topics
- AI security
- OWASP Top 10 for LLM Applications 2025
- LLM01
topic_id: owasp-llm01
framework: OWASP Top 10 for LLM Applications 2025 LLM01:2025
visual:
  kicker: AI Security Topics
  title: Indirect Prompt Injection Attack Flow
  steps:
  - Attacker embeds hidden malicious instructions into a webpage or document.
  - User requests the LLM to summarize or process the external resource.
  - LLM parses the external content and interprets the embedded instructions.
  - Model alters its behavior to execute unauthorized actions or render exfiltration links.
status: []
sources:
- title: 'OWASP Top 10 for LLM Applications 2025: LLM01 Prompt Injection'
  url: https://genai.owasp.org/llm-top-10/
drafted_by: gemini (model), approved by the owner
---

## What it is

A Prompt Injection Vulnerability occurs when user prompts alter an LLM's behavior or output in unintended ways. These inputs can be direct from a user or indirect from external sources like websites or files, and they do not need to be human-readable as long as the model parses them. The vulnerability stems from how models process prompts and pass prompt data internally, potentially forcing the model to violate guidelines, reveal sensitive details, execute arbitrary commands, or enable unauthorized access.

## How the attack works

In a direct injection attack, an adversary submits a prompt to a support chatbot ordering it to ignore previous guidelines, query private data stores, and send unauthorized emails. In an indirect attack, a user asks an LLM to summarize a webpage containing hidden instructions; when parsed, the instructions cause the LLM to render an image linking to an external URL, exfiltrating the private conversation context. Attacks can also leverage multimodal inputs by hiding instructions within an image, split payloads across documents like resumes, or append adversarial suffixes and encoded text (such as Base64 or emojis) to bypass standard input filters.

## Problem, risk, mitigation

- Problem: System instructions can be overridden by direct user prompts or hidden external inputs. Risk: Disclosure of sensitive system infrastructure, system prompts, or private user data. Mitigation: Constrain model behavior with explicit system prompt limitations and apply input and output filtering using semantic filters, string-checking, and RAG Triad evaluations.
- Problem: Models directly trigger privileged backend functions or commands based on untrusted instructions. Risk: Unauthorized access, execution of arbitrary commands in connected systems, and compromise of critical decisions. Mitigation: Enforce privilege control by managing function APIs in deterministic code rather than in the model, enforce least privilege access, and require human-in-the-loop approval for high-risk operations.
- Problem: External data sources like RAG repositories or web documents contain embedded malicious payloads. Risk: Content manipulation, indirect prompt injection, and silent exfiltration of private session data. Mitigation: Segregate and clearly denote untrusted external content to restrict its influence on user prompts.

## What to do

- **Inventory:** Identify all internal and external data sources parsed by LLMs, including RAG repositories, file uploads, and web scrapers, to map untrusted input boundaries.
- **Contain:** Handle API tokens and extensible functions within deterministic code rather than granting direct function access to the model, and implement human approval steps for high-risk operations.
- **Harden:** Segregate untrusted external content from user prompts and enforce strict system prompt constraints that instruct the model to adhere to context and ignore instruction modifications.
- **Detect:** Apply semantic filters, string checks for disallowed content, and use the RAG Triad framework to evaluate context relevance, groundedness, and answer validity.
- **Hunt:** Perform adversarial testing and attack simulations, treating the model as an untrusted user to evaluate access controls and trust boundaries.
