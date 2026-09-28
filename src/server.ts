import express from "express";
import cors from "cors";
import path from "node:path";
import dotenv from "dotenv";
import { createSession, getSession, listSessions, saveSessionToDisk } from "./store/state.js";
import { ReconOrchestrator } from "./agent/orchestrator.js";
import { AgentEvent } from "./agent/events.js";

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
