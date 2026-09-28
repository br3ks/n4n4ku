import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { ScanSession } from "../agent/orchestrator.js";

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const SCANS_FILE = path.join(DATA_DIR, "scans.json");

const sessions = new Map<string, ScanSession>();

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch {}
}

export function createSession(domain: string): ScanSession {
  const id = `scan_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const session: ScanSession = {
    id,
    targetDomain: domain,
    status: "RUNNING",
    startedAt: new Date().toISOString(),
    assets: [],
    eventBus: new EventEmitter(),
  };

  // Keep max 100 listeners to avoid warnings
  session.eventBus.setMaxListeners(100);
  sessions.set(id, session);
  return session;
}

export function getSession(id: string): ScanSession | undefined {
  return sessions.get(id);
}

export function listSessions() {
  return Array.from(sessions.values()).map((s) => ({
    id: s.id,
    targetDomain: s.targetDomain,
    status: s.status,
    startedAt: s.startedAt,
    completedAt: s.completedAt,
    assetCount: s.assets.length,
    aliveCount: s.assets.filter((a) => a.httpStatus || a.ip).length,
  }));
}

export function saveSessionToDisk(session: ScanSession) {
  try {
    ensureDataDir();
    let currentData: any[] = [];
    if (fs.existsSync(SCANS_FILE)) {
      currentData = JSON.parse(fs.readFileSync(SCANS_FILE, "utf-8"));
    }
    const idx = currentData.findIndex((item) => item.id === session.id);
    const serialized = {
      id: session.id,
      targetDomain: session.targetDomain,
      status: session.status,
      startedAt: session.startedAt,
      completedAt: session.completedAt,
      assets: session.assets,
      dnsSummary: session.dnsSummary,
      report: session.report,
    };
    if (idx >= 0) {
      currentData[idx] = serialized;
    } else {
      currentData.unshift(serialized);
    }
    fs.writeFileSync(SCANS_FILE, JSON.stringify(currentData.slice(0, 50), null, 2), "utf-8");
  } catch {}
}
