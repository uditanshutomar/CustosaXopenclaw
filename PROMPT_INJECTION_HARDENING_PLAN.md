# Custosa Prompt Injection Hardening Plan (Deep Review)

Date: 2026-02-01  
Scope: **Plan only** (no code changes in this pass)  
Goal: Make Custosa’s prompt-injection protection **robust and production‑ready** across *all* OpenClaw entry points, with clear policy, strong defaults, and measurable effectiveness.

---

## 1) Executive Summary

Custosa already implements meaningful defenses (multi-layer detection, WS/HTTP inspection, Telegram approval, output filtering, JSON depth limits, role‑escalation detection, tool‑argument checks). The remaining risk is **coverage + policy consistency**, especially for:

- **OpenClaw HTTP APIs** that bypass `/tools/invoke`
- **OpenClaw channels** (e.g., WhatsApp) that do **not pass through the proxy**
- **Schema/endpoint gaps** and uneven enforcement across WS methods
- **Tool governance** that relies on substrings instead of explicit policy
- **Output/indirect injection** across all event types and tool results

This plan closes those gaps with a **full entry‑point map**, a **policy engine**, **channel integration (hooks/policy)**, stronger **tool governance**, and **evaluation harnesses** to validate real‑world behavior.

---

## 2) System Map: Where Prompts Enter (Based on Code + OpenClaw Docs)

### A) WebSocket Gateway API (dashboard/WebChat and API clients)
- WS uses `req`/`res`/`event` frames.  
- Common methods include chat and node calls (e.g., `chat.send`, `chat.inject`, `node.invoke`).  

**Why it matters:** WS is the primary path Custosa already monitors, but method coverage must be **schema‑driven**, not hardcoded.

### B) HTTP Tool Invocation API
- `POST /tools/invoke` with JSON body including `tool`, `args`, `sessionKey`, and policy/confirm fields.  

**Why it matters:** Custosa inspects `/tools/invoke`, but must validate **full schema** and enforce policy consistently.

### C) OpenAI‑Compatible HTTP APIs
- `POST /v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, etc.  

**Why it matters:** These endpoints allow prompts **outside** WS and **outside** `/tools/invoke`.

### D) Channel Ingest (WhatsApp and others)
- WhatsApp session lives **inside** the OpenClaw gateway and is configured via `channels.whatsapp` in the OpenClaw config file.
- WhatsApp also supports config‑write commands (`/config set`, `/config unset`, allowlist updates).  

**Why it matters:** These channel inputs are not routed through Custosa unless we integrate into the gateway or route all channel inputs through Custosa.

### E) Gateway Security Model
- Gateway trusts forwarded headers only for configured `trustedProxies`.
- Device auth can be disabled with `dangerouslyDisableDeviceAuth`.  

**Why it matters:** Custosa must respect these assumptions and **avoid accidental trust escalation**.

### F) Gateway Policy & Hooks
- OpenClaw supports policy and hooks (gateway‑side code execution) that can intercept/modify behavior.  

**Why it matters:** Hooks/policy are the **only reliable way** to cover channel inputs that bypass the proxy.

---

## 3) Current Controls (Observed in Code)

### Strong points already present
- JSON depth/key limits (DoS hardening)
- Non‑JSON and non‑dict frames do **not** fail‑open
- Role‑escalation detection (client‑supplied `system/assistant` roles)
- Tool argument validation (SSRF/path traversal/shell chaining)
- Output filtering for instruction laundering in gateway→client stream
- Session‑context scoring (multi‑turn amplification)
- Hold/approval flow with Telegram

### Gaps that still matter in production

#### Coverage gaps
- WS coverage still depends on `ANALYZED_METHODS` and heuristics.
- HTTP coverage only enforces `/tools/invoke`; OpenAI‑compatible endpoints are **untouched**.
- WhatsApp (and other channels) are **inside gateway**, not proxied.

#### Policy gaps
- Tool risk is substring‑based; unknown tools are not explicitly governed.
- No explicit policy language; decisions are embedded in code paths.

#### Output/indirect injection gaps
- Output filtering is limited to some event types.
- Tool results/data are not always strongly “tainted” as untrusted.

#### Operational gaps
- No uniform evaluation harness or adversarial testing suite.
- Update integrity is not verified (supply‑chain risk).

---

## 4) Hardening Strategy (Defense‑in‑Depth)

### Guiding invariants
1. **Client input is untrusted**; any role escalation or schema violation is suspicious.
2. **No fail‑open** on parse or schema mismatch for security‑critical paths.
3. **Unknown = suspicious** (tools, methods, endpoints).
4. **Data ≠ instructions**: tool outputs and external content must be treated as untrusted.
5. **Single policy engine** decides; detection engines only score.

---

## 5) Phased Plan (Detailed)

### Phase 0 — Ground truth map (1–2 days)
**Objective:** Make sure we cover *every* entry point and the exact schemas.

- Create a definitive **Entry‑Point Map**:
  - WS methods list (from OpenClaw WS protocol docs + runtime observation)
  - HTTP endpoints list (OpenAI compatibility endpoints + tools invoke)
  - Channel sources (WhatsApp + any other gateway‑internal channels)
- Add a “traffic tracing” mode:
  - Record method + endpoint + content‑type stats (no sensitive payloads)
  - Validate coverage without exposing user data

**Deliverable:** `docs/entry_points.md` + initial list of methods/endpoints to be governed.

---

### Phase 1 — Coverage & invariants (High impact, fast)
**Objective:** Close bypasses and normalize enforcement across protocols.

1) **WS enforcement**
- Replace `ANALYZED_METHODS` with schema‑based detection:
  - If request is `type=req` and `params` contain any text fields, analyze.
  - Maintain a *denylist* of safe/no‑text methods to reduce noise.
- Treat **binary WS frames** as suspicious by default (hold or block).

2) **HTTP enforcement**
- Add analysis to **OpenAI HTTP APIs** (`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`):
  - Extract prompts/messages and analyze.
  - Enforce role invariants in `messages[]`.
- Enforce strict JSON parse + schema checks for all content‑bearing endpoints.

3) **Strict role invariants**
- Any client‑supplied `system/developer/assistant` role in requests ⇒ HOLD/BLOCK.

4) **Uniform “unknown” behavior**
- Unknown endpoint/tool/method defaults to HOLD.

**Deliverable:** full protocol coverage with no fail‑open bypasses.

---

### Phase 2 — Policy engine + tool governance (Medium impact, core robustness)
**Objective:** Replace ad‑hoc decisions with a **central policy engine**.

1) **Policy Engine**
- Add a policy layer separate from detection:
  - Inputs: endpoint/method/tool, provenance, risk, user/channel, auth context.
  - Outputs: ALLOW/HOLD/BLOCK + reviewer hints + action requirements.

2) **Tool governance**
- Replace substring tool risk with **explicit allow/deny lists** and per‑tool schemas.
- Add per‑tool “**allowed domains/paths**” and per‑field validation.
- Default unknown tool to **HOLD**.

3) **Channel‑specific governance**
- For WhatsApp “configWrites” or any channel commands, require HOLD or explicit allowlist.

**Deliverable:** policy config file (versioned) + enforcement in proxy.

---

### Phase 3 — Indirect injection + output safety (High impact)
**Objective:** Treat tool outputs and retrieved data as untrusted.

1) **Provenance‑aware scoring**
- Strengthen provenance weights (user vs tool vs external).
- Automatically tag tool results and web content as **data‑only**.

2) **Output filtering expansion**
- Analyze all gateway→client event types and tool outputs.
- Add **leak detection** for system prompts, secrets, or policy text.
- Provide safe “sanitized response” with clear user notification.

3) **Instruction laundering controls**
- Detect hidden/embedded instructions in tool results (markdown, JSON, HTML).

**Deliverable:** consistent outbound filtering and provenance enforcement.

---

### Phase 4 — Channel coverage via Gateway Hooks (Critical for real‑world)
**Objective:** Protect **WhatsApp and other gateway‑internal channels**.

1) **Gateway hook integration**
- Implement a gateway hook that runs the same detection/policy logic *before* messages reach the LLM or tools.
- Ensure hook uses the same policy config and detection engine.

2) **Unified enforcement**
- Route channel traffic through the same “policy decision” pipeline:
  - If BLOCK → respond with safe denial message.
  - If HOLD → queue approval (Telegram) with channel context.

**Deliverable:** channels covered, not just dashboard/web clients.

---

### Phase 5 — Human‑in‑the‑loop UX (Reliability)
**Objective:** Make approval reliable under real‑world latency.

- Standardize **async approval** for HTTP and WS:
  - Return `CUSTOSA_PENDING_APPROVAL` + `request_id`
  - Provide `/tools/status` polling and optional webhook callback
- Add **expiry + replay prevention**
- Add reviewer‑safe summaries and hashes (no secret exposure)

**Deliverable:** approvals work with 5‑minute waits without client disconnect issues.

---

### Phase 6 — Evaluation & red‑team testing (Proof of robustness)
**Objective:** Prevent regression and prove “real‑world” behavior.

- Build a **prompt‑injection test suite**:
  - Direct, indirect, multi‑turn, tool‑arg, and channel‑specific tests
- Add fuzzing for JSON and WS frames (depth, type confusion, weird encodings)
- Measure **false‑positive** and **false‑negative** rates over time
- Include “prompt laundering” and “role escalation” test cases

**Deliverable:** CI‑ready test harness + baseline metrics.

---

### Phase 7 — Deployment & supply‑chain hardening
**Objective:** Eliminate operational bypasses and update risks.

- Ensure gateway port is **localhost‑only** or firewalled
- Verify `trustedProxies` are set correctly; never trust forwarded headers by default
- Detect `dangerouslyDisableDeviceAuth` and warn/block if enabled
- Add signed update verification or pinned release hashes for updates

**Deliverable:** secure deployment posture and reduced operational risk.

---

## 6) “Perfect in Real‑World” Checklist

Use this as the go‑live gate:

- [ ] All entry points mapped and enforced (WS + HTTP + channels)
- [ ] Unknown methods/tools → HOLD or BLOCK
- [ ] Role escalation blocked/held consistently
- [ ] Tool args validated against schema & allowlists
- [ ] Output filtering covers all event types
- [ ] Human approval works with async clients (no 15‑second failures)
- [ ] Gateway hooks protect WhatsApp and other channels
- [ ] Fuzzing + adversarial suite passes
- [ ] Logs are sanitized; no secrets leak to Telegram/logs

---

## 7) Immediate Next Actions (If you want to proceed)

1) Confirm the **full list of OpenClaw endpoints** in your deployment (WS + HTTP).
2) Decide the **policy defaults** (HOLD vs BLOCK) for unknown tools/roles.
3) Choose **where** the enforcement should live:
   - Proxy only, or
   - Proxy + Gateway hook (recommended for channels)
4) Approve the initial policy config schema.

---

## Appendix — Quick Notes from Code Review

- Proxy already blocks non‑JSON and non‑dict WS frames (good).  
- Role escalation detection exists (good) but needs **strict policy defaults**.  
- Output filtering exists but only on select event types (needs expansion).  
- Tool risk is substring‑based (should be explicit policy).  
- `/tools/invoke` is protected; **OpenAI HTTP APIs are not yet**.  
- Channel messages (WhatsApp) bypass proxy unless we hook into gateway.

---

**End of Plan.**
