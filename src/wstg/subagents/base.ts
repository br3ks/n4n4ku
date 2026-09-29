import { WstgChecklistResult, WstgFinding, WstgInfoId, WstgSeverity, WstgStatus } from "../types.js";

export interface SubagentContext {
  targetUrl: string;
  targetDomain: string;
  ip?: string;
  log: (level: "INFO" | "WARN" | "PASS" | "FAIL", message: string) => void;
  llmConfig: {
    apiKey?: string;
    baseUrl?: string;
    model?: string;
  };
}

export type SubagentExecutor = (ctx: SubagentContext) => Promise<WstgChecklistResult>;

/**
 * Standard HTTP Fetch helper with timeout, custom user-agent, and error handling.
 */
export async function safeFetch(
  url: string,
  options: RequestInit & { timeoutMs?: number } = {}
): Promise<{ status: number; headers: Headers; text: string; ok: boolean; error?: string }> {
  const timeoutMs = options.timeoutMs || 8000;
  const headers = new Headers(options.headers || {});
  if (!headers.has("User-Agent")) {
    headers.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SAL4WAKU-Audit/1.0 (OWASP-WSTG-Recon)");
  }

  try {
    const res = await fetch(url, {
      ...options,
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });

    let text = "";
    try {
      const rawText = await res.text();
      text = rawText.slice(0, 150000); // 150KB limit to prevent memory bloat
    } catch {}

    return {
      status: res.status,
      headers: res.headers,
      text,
      ok: res.ok,
    };
  } catch (err: any) {
    return {
      status: 0,
      headers: new Headers(),
      text: "",
      ok: false,
      error: err.name === "TimeoutError" ? "Request Timeout" : err.message || "Fetch Failed",
    };
  }
}

/**
 * Helper to calculate final status and highest severity from a list of findings.
 */
export function evaluateFindings(
  findings: WstgFinding[],
  defaultPassSummary: string,
  defaultPassRecommendation: string
): {
  status: WstgStatus;
  severity: WstgSeverity;
  evidenceSummary: string;
  recommendation: string;
} {
  if (findings.length === 0) {
    return {
      status: "PASS",
      severity: "NONE",
      evidenceSummary: defaultPassSummary,
      recommendation: defaultPassRecommendation,
    };
  }

  // Priority order for highest severity
  const severityOrder: WstgSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "NONE"];
  let highestSeverity: WstgSeverity = "NONE";
  for (const s of severityOrder) {
    if (findings.some((f) => f.severity === s)) {
      highestSeverity = s;
      break;
    }
  }

  const isFail = highestSeverity === "CRITICAL" || highestSeverity === "HIGH" || highestSeverity === "MEDIUM";
  const status: WstgStatus = isFail ? "FAIL" : "REVIEW";

  const evidenceSummary = findings
    .map((f) => `[${f.severity}] ${f.title}: ${f.evidence}`)
    .join(" | ");

  const recommendation = findings
    .map((f) => f.recommendation)
    .filter(Boolean)
    .join(" ");

  return {
    status,
    severity: highestSeverity,
    evidenceSummary,
    recommendation,
  };
}
