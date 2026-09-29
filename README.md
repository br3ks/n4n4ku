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
- **OWASP WSTG v4.2 Security Audit (Information Gathering)**:
  - Menu baru untuk audit keamanan web mendalam berdasarkan standar OWASP WSTG 4.2.
  - **10 Dedicated Sub-Agents** dengan skenario uji terfokus:
    1. `WSTG-INFO-01`: Search Engine Discovery (`SearchEngineReconSubagent`)
    2. `WSTG-INFO-02`: Fingerprint Web Server (`WebServerFingerprintSubagent`)
    3. `WSTG-INFO-03`: Review Webserver Metafiles (`WebserverMetafilesSubagent`)
    4. `WSTG-INFO-04`: Enumerate Applications on Webserver (`AppEnumerationSubagent`)
    5. `WSTG-INFO-05`: Review Webpage Content for Information Leakage (`ContentLeakageSubagent`)
    6. `WSTG-INFO-06`: Identify Application Entry Points (`EntryPointsSubagent`)
    7. `WSTG-INFO-07`: Map Execution Paths Through Application (`ExecutionPathsSubagent`)
    8. `WSTG-INFO-08`: Fingerprint Web Application Framework (`FrameworkFingerprintSubagent`)
    9. `WSTG-INFO-09`: Fingerprint Web Application (`AppFingerprintSubagent`)
    10. `WSTG-INFO-10`: Map Application Architecture (`ArchitectureMapSubagent`)
  - Sub-agent checklist matrix, realtime log stream, findings ledger, dan dynamic modal detail.
  - Laporan audit resmi OWASP WSTG 4.2 yang digenerate oleh AI dengan rekomendasi remediasi taktis.
- **High-Visibility Cockpit (Web UI)**:
  - Dual Mode Switcher: **Domain Recon** &amp; **WSTG 4.2 Audit**.
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
