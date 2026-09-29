import { EventEmitter } from "node:events";
import fs from "node:fs";
import path from "node:path";
import { WstgChecklistResult, WstgFinding } from "./types.js";

const DATA_DIR = process.env.DATA_DIR || path.join(process.cwd(), "data");
const AUDITS_FILE = path.join(DATA_DIR, "wstg_audits.json");

export interface WstgAuditSession {
  id: string;
  targetUrl: string;
  targetDomain: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED";
  startedAt: string;
  completedAt?: string;
  results: Record<string, WstgChecklistResult>;
  findings: WstgFinding[];
  report: string;
  eventBus: EventEmitter;
}

const auditSessions = new Map<string, WstgAuditSession>();

function ensureDataDir() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  } catch {}
}

export function createAuditSession(targetUrl: string, targetDomain: string): WstgAuditSession {
  const id = `wstg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const session: WstgAuditSession = {
    id,
    targetUrl,
    targetDomain,
    status: "RUNNING",
    startedAt: new Date().toISOString(),
    results: {},
    findings: [],
    report: "",
    eventBus: new EventEmitter(),
  };

  session.eventBus.setMaxListeners(100);
  auditSessions.set(id, session);
  return session;
}

export function getAuditSession(id: string): WstgAuditSession | undefined {
  return auditSessions.get(id);
}

export function listAuditSessions() {
  return Array.from(auditSessions.values()).map((s) => ({
    id: s.id,
    targetUrl: s.targetUrl,
    targetDomain: s.targetDomain,
    status: s.status,
    startedAt: s.startedAt,
    completedAt: s.completedAt,
    totalChecklists: Object.keys(s.results).length,
    findingsCount: s.findings.length,
  }));
}

export function saveAuditSessionToDisk(session: WstgAuditSession) {
  try {
    ensureDataDir();
    let currentData: any[] = [];
    if (fs.existsSync(AUDITS_FILE)) {
      try {
        currentData = JSON.parse(fs.readFileSync(AUDITS_FILE, "utf-8"));
      } catch {}
    }

    const idx = currentData.findIndex((item) => item.id === session.id);
    const serialized = {
      id: session.id,
      targetUrl: session.targetUrl,
      targetDomain: session.targetDomain,
      status: session.status,
      startedAt: session.startedAt,
      completedAt: session.completedAt,
      results: session.results,
      findings: session.findings,
      report: session.report,
    };

    if (idx >= 0) {
      currentData[idx] = serialized;
    } else {
      currentData.unshift(serialized);
    }

    // Keep up to 20 past audits
    fs.writeFileSync(AUDITS_FILE, JSON.stringify(currentData.slice(0, 20), null, 2), "utf-8");
  } catch (err) {
    console.error("[WSTG Store] Gagal menyimpan audit session:", err);
  }
}
