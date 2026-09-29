import express from "express";
import cors from "cors";
import path from "node:path";
import dotenv from "dotenv";
import { createSession, getSession, listSessions, saveSessionToDisk } from "./store/state.js";
import { ReconOrchestrator } from "./agent/orchestrator.js";
import { AgentEvent } from "./agent/events.js";
import { createAuditSession, getAuditSession, listAuditSessions } from "./wstg/store.js";
import { WstgAuditOrchestrator } from "./wstg/orchestrator.js";
import { WstgEvent } from "./wstg/types.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(process.cwd(), "public");

app.use(cors());
app.use(express.json());
app.use(express.static(PUBLIC_DIR));

// Healthcheck
app.get("/health", (req, res) => {
  res.json({ status: "ok", app: "n4n4ku", version: "1.0.0" });
});

// Launch new recon scan
app.post("/api/scan", (req, res) => {
  const { domain, dnsConcurrency, httpConcurrency } = req.body;
  if (!domain || typeof domain !== "string") {
    res.status(400).json({ error: "Parameter 'domain' wajib diisi." });
    return;
  }

  const session = createSession(domain);

  const orchestrator = new ReconOrchestrator(
    session,
    {
      apiKey: process.env.LLM_API_KEY || process.env.GEMINI_API_KEY,
      baseUrl: process.env.LLM_BASE_URL,
      model: process.env.LLM_MODEL,
    },
    dnsConcurrency ? Number(dnsConcurrency) : 25,
    httpConcurrency ? Number(httpConcurrency) : 15
  );

  // Background execution
  orchestrator
    .start()
    .then(() => {
      saveSessionToDisk(session);
    })
    .catch(() => {
      saveSessionToDisk(session);
    });

  res.status(202).json({
    scanId: session.id,
    targetDomain: session.targetDomain,
    status: session.status,
  });
});

// Real-time Telemetry via Server-Sent Events (SSE)
app.get("/api/scan/:id/stream", (req, res) => {
  const session = getSession(req.params.id);
  if (!session) {
    res.status(404).json({ error: "Sesi scan tidak ditemukan." });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  // Send initial snapshot
  const initialPayload = {
    type: "snapshot",
    id: session.id,
    targetDomain: session.targetDomain,
    status: session.status,
    assetsCount: session.assets.length,
    report: session.report,
  };
  res.write(`data: ${JSON.stringify(initialPayload)}\n\n`);

  // Stream live events
  const onEvent = (event: AgentEvent) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  session.eventBus.on("event", onEvent);

  // Keep-alive heartbeat every 15s
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    session.eventBus.off("event", onEvent);
  });
});

// Get session details
app.get("/api/scan/:id", (req, res) => {
  const session = getSession(req.params.id);
  if (!session) {
    res.status(404).json({ error: "Scan tidak ditemukan." });
    return;
  }
  res.json({
    id: session.id,
    targetDomain: session.targetDomain,
    status: session.status,
    startedAt: session.startedAt,
    completedAt: session.completedAt,
    dnsSummary: session.dnsSummary,
    assets: session.assets,
    report: session.report,
  });
});

// List recent scans
app.get("/api/scans", (req, res) => {
  res.json(listSessions());
});

// ==========================================
// OWASP WSTG 4.2 Information Gathering API
// ==========================================

// Launch new WSTG 4.2 Audit
app.post("/api/wstg/audit", (req, res) => {
  const { url, concurrency } = req.body;
  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "Parameter 'url' wajib diisi (contoh: https://example.com)." });
    return;
  }

  let formattedUrl = url.trim();
  if (!formattedUrl.startsWith("http://") && !formattedUrl.startsWith("https://")) {
    formattedUrl = `https://${formattedUrl}`;
  }

  let domain = "";
  try {
    const parsed = new URL(formattedUrl);
    domain = parsed.hostname;
  } catch {
    res.status(400).json({ error: "Format URL tidak valid." });
    return;
  }

  const session = createAuditSession(formattedUrl, domain);
  const orchestrator = new WstgAuditOrchestrator(
    session,
    {
      apiKey: process.env.LLM_API_KEY || process.env.GEMINI_API_KEY,
      baseUrl: process.env.LLM_BASE_URL,
      model: process.env.LLM_MODEL,
    },
    concurrency ? Number(concurrency) : 2
  );

  // Background execution
  orchestrator.start().catch((err) => {
    console.error("[WSTG Error]", err);
  });

  res.status(202).json({
    auditId: session.id,
    targetUrl: session.targetUrl,
    targetDomain: session.targetDomain,
    status: session.status,
  });
});

// Real-time SSE Telemetry for WSTG Audit
app.get("/api/wstg/audit/:id/stream", (req, res) => {
  const session = getAuditSession(req.params.id);
  if (!session) {
    res.status(404).json({ error: "Sesi WSTG Audit tidak ditemukan." });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  // Initial snapshot
  const initialPayload = {
    type: "snapshot",
    id: session.id,
    targetUrl: session.targetUrl,
    targetDomain: session.targetDomain,
    status: session.status,
    results: session.results,
    findings: session.findings,
    report: session.report,
  };
  res.write(`data: ${JSON.stringify(initialPayload)}\n\n`);

  // Stream live WSTG events
  const onEvent = (event: WstgEvent) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  session.eventBus.on("wstg_event", onEvent);

  // Heartbeat every 15s
  const heartbeat = setInterval(() => {
    res.write(`: heartbeat\n\n`);
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    session.eventBus.off("wstg_event", onEvent);
  });
});

// Get WSTG session details
app.get("/api/wstg/audit/:id", (req, res) => {
  const session = getAuditSession(req.params.id);
  if (!session) {
    res.status(404).json({ error: "Audit tidak ditemukan." });
    return;
  }
  res.json({
    id: session.id,
    targetUrl: session.targetUrl,
    targetDomain: session.targetDomain,
    status: session.status,
    startedAt: session.startedAt,
    completedAt: session.completedAt,
    results: session.results,
    findings: session.findings,
    report: session.report,
  });
});

// List recent WSTG audits
app.get("/api/wstg/audits", (req, res) => {
  res.json(listAuditSessions());
});

// Fallback index.html for SPA
app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.listen(PORT, () => {
  console.log(`\n=================================================`);
  console.log(`⚡ n4n4ku Autonomous Recon Engine running`);
  console.log(`🌐 Web UI: http://localhost:${PORT}`);
  console.log(`=================================================\n`);
});
