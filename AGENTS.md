# n4n4ku Project Memory & Agent Guidelines

## 1. Project Overview
- **Name**: `n4n4ku`
- **Purpose**: Autonomous AI Agent for Domain Reconnaissance & Attack Surface Management (ASM).
- **Core Philosophy**: Autonomous decision-making using ReAct function calling (*Thought ➔ Action ➔ Observation*), high-concurrency parallel I/O, live telemetry streaming, and zero unnecessary bloat.

## 2. Architecture & Components
- **Server**: Express.js with Server-Sent Events (SSE) streaming at `/api/scan/:id/stream` (`src/server.ts`).
- **Agent Core**:
  - `src/agent/orchestrator.ts`: ReAct master loop executing tool calls autonomously.
  - `src/agent/llm_react.ts`: OpenAI-compatible streaming function-calling client.
  - `src/agent/tools_schema.ts`: JSON schema for callable recon tools.
  - `src/agent/llm.ts`: Fallback report generator & heuristic engine.
  - `src/agent/events.ts`: Strongly typed telemetry events.
- **Recon Tools**:
  - `src/tools/ct.ts`: Certificate Transparency log scraper (`crt.sh`).
  - `src/tools/dns.ts`: DNS record resolution, Wildcard DNS detection & filter, cloud takeover CNAME fingerprinting.
  - `src/tools/http.ts`: HTTP/TLS status, title, server banner, tech stack fingerprinting, anomaly alerts.
  - `src/tools/runner.ts`: Parallel worker pool with concurrency control (`p-limit`) and progress telemetry.
- **Scope & Store**:
  - `src/core/scope.ts`: Domain normalization and strict scope boundary checking.
  - `src/store/state.ts`: In-memory session state with JSON persistence (`data/scans.json`).
- **Frontend Cockpit**:
  - Vanilla HTML/JS with Tailwind CSS (CDN), Lucide icons, and Marked.js (`public/`).
  - 3-Panel Cockpit: Pipeline Stepper, Live Agent Terminal, Realtime Asset Matrix Table.

## 3. Docker & Deployment
- Containerized via `Dockerfile` (Node 22 Alpine) bundled with essential diagnostic utilities:
  - `bind-tools` (`dig`, `host`, `nslookup`)
  - `curl`, `whois`, `openssl`, `ca-certificates`, `tini`
- Docker Compose (`docker-compose.yml`) configures `host.docker.internal:host-gateway` bridge so the container can reach local AI proxies (9router) running on the host machine.

## 4. LLM & Provider Configuration
- Supported providers: 9router (local proxy), Google Gemini, OpenAI, Ollama, OpenRouter.
- Configured via `.env`:
  - `LLM_BASE_URL=http://localhost:20128/v1` (Docker automatically bridges to `http://host.docker.internal:20128/v1`)
  - `LLM_MODEL=wombo` (auto-aliased if user enters `combo wumbo`)
  - `LLM_API_KEY=...`

## 5. Coding & Security Rules
- **No Secrets in Repo**: Never commit `.env` or hardcoded API keys.
- **Ponytail Mode**: Write minimal, clean, standard-library-first code. Avoid adding bloated dependencies.
- **Ethical & Defensive**: Reconnaissance must respect target scope boundaries.
