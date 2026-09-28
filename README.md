# n4n4ku // Autonomous Recon Agent

Agentic AI tool untuk domain reconnaissance & Attack Surface Management (ASM) dengan eksekusi otonom (ReAct function calling), tool concurrency paralel, dan live telemetry streaming.

---

## ⚡ Fitur Utama

- **Autonomous ReAct Agent Loop**: Model AI memanggil tools secara mandiri (*Thought ➔ Action ➔ Observation*) untuk merencanakan langkah recon, melakukan triage anomali, dan menyusun laporan intelijen permukaan serangan.
- **Tools ReAct Terintegrasi**:
  - `get_apex_dns`: Audit DNS Apex (NS, MX, SPF, DMARC, SOA) & deteksi Wildcard DNS.
  - `discover_subdomains_ct`: Agregasi subdomain pasif via Certificate Transparency (`crt.sh`).
  - `resolve_subdomain_batch`: Mass DNS Resolver paralel dengan deteksi IP aktif & CNAME mapping.
  - `probe_http_batch`: HTTP/TLS Fingerprinting untuk ekstraksi status code, server banner, web tech, dan anomali.
  - `inspect_takeover_risk`: Deteksi potensi dangling CNAME ke layanan cloud (AWS S3, CloudFront, Azure, GitHub Pages, dll.).
- **High-Visibility Cockpit (Web UI)**:
  - 3-Panel Dashboard: Pipeline Stepper, Live Thought & Action Terminal, Realtime Discovered Assets Table.
  - Full Live Telemetry via Server-Sent Events (SSE).
- **Multi-Provider AI Ready**: Terintegrasi langsung dengan 9router (`http://localhost:20128/v1` model `wombo`), Google Gemini, atau OpenAI-compatible endpoints lainnya.
- **Docker Ready**: Dilengkapi utilitas audit jaringan bawaan (`bind-tools`, `curl`, `whois`, `openssl`, `tini`).

---

## 🚀 Cara Menjalankan dengan Docker (Rekomendasi)

Pastikan Docker Desktop aktif, lalu jalankan:

```bash
docker compose up -d --build
```

Buka browser di: **`http://localhost:3000`**

Untuk melihat log kontainer secara live:
```bash
docker compose logs -f
```

Untuk menghentikan kontainer:
```bash
docker compose down
```

---

## 💻 Menjalankan Langsung Tanpa Docker (Node.js)

```bash
# 1. Install dependensi
npm install

# 2. Jalankan mode development
npm run dev

# Atau build & run production:
npm run build
npm start
```

---

## ⚙️ Konfigurasi (`.env`)

Salin template konfigurasi:
```bash
cp .env.example .env
```

Contoh konfigurasi `.env`:

```env
PORT=3000

# 9router / Local OpenAI-compatible Proxy
LLM_API_KEY=your_api_key_here
LLM_BASE_URL=http://localhost:20128/v1
LLM_MODEL=wombo

# Atau jika menggunakan Google Gemini langsung:
# GEMINI_API_KEY=AIzaSy...
# LLM_MODEL=gemini-2.5-flash
```

---

## 📁 Struktur Direktori

```text
n4n4ku/
├── src/
│   ├── server.ts              # Express API & SSE Telemetry server
│   ├── agent/
│   │   ├── orchestrator.ts    # ReAct agent execution loop
│   │   ├── llm_react.ts       # OpenAI-compatible streaming function calling client
│   │   ├── tools_schema.ts    # JSON schema definisi tools untuk LLM
│   │   ├── llm.ts             # Fallback synthesis & heuristic report generator
│   │   └── events.ts          # Skema event telemetri
│   ├── tools/
│   │   ├── ct.ts              # Certificate Transparency scraper (crt.sh)
│   │   ├── dns.ts             # DNS audit & Wildcard resolver
│   │   ├── http.ts            # Parallel HTTP & tech stack prober
│   │   └── runner.ts          # Parallel concurrency limiter (p-limit)
│   ├── core/
│   │   └── scope.ts           # Scope validation & trust boundary guard
│   └── store/
│       └── state.ts           # In-memory & JSON session state
├── public/                    # Web Cockpit (HTML, CSS, JS)
├── Dockerfile                 # Multi-stage build + network tools
├── docker-compose.yml         # Container compose config
└── README.md
```

---

## 🛡️ Catatan Keamanan & Etika
Tool ini dirancang untuk tujuan audit keamanan defensif, Attack Surface Management (ASM), dan ethical security assessment. Pastikan Anda memiliki izin resmi sebelum melakukan pemindaian terhadap domain target.
