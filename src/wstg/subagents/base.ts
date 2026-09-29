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

export interface RawProbeRecord {
  method: string;
  url: string;
  status: number;
  headers?: Record<string, string>;
  bodySnippet?: string;
}

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
 * Format raw probe logs into readable HTTP transcripts for verification evidence.
 */
export function formatRawOutputs(records: RawProbeRecord[]): string {
  if (records.length === 0) return "Tidak ada raw probe tercatat.";
  return records
    .map((r, idx) => {
      const headerLines = r.headers
        ? Object.entries(r.headers)
            .map(([k, v]) => `  ${k}: ${v}`)
            .join("\n")
        : "";
      const bodySnippet = r.bodySnippet
        ? `\n  [Body Sample (${r.bodySnippet.length} chars)]:\n  ${r.bodySnippet.slice(0, 300).replace(/\n/g, "\n  ")}`
        : "";
      return `--- [Probe #${idx + 1}] ${r.method} ${r.url} ---\n  Status: HTTP ${r.status}\n${headerLines}${bodySnippet}`;
    })
    .join("\n\n");
}

/**
 * Evaluates whether an observed HTTP 200 response is a False Positive (e.g., SPA catch-all, soft 404, or WAF challenge).
 */
export function checkFalsePositive(
  probeType: "env" | "git" | "graphql" | "actuator" | "wp_users" | "cots" | "vhost" | "metafile",
  status: number,
  body: string,
  contentType = ""
): { isFalsePositive: boolean; reason: string } {
  if (status !== 200) {
    return { isFalsePositive: false, reason: `Status code ${status} bukan 200 OK.` };
  }

  const isHtml = /<!DOCTYPE html|<html|<head|<body|<script/i.test(body);
  const isSpaCatchAll = isHtml && (body.includes('id="root"') || body.includes('id="__next"') || body.includes('window.__NUXT__') || body.includes("React"));

  switch (probeType) {
    case "env":
      if (isHtml) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Server mengembalikan halaman HTML/SPA catch-all untuk path .env, bukan file konfigurasi environment nyata.",
        };
      }
      if (!/^[A-Z0-9_]+\s*=\s*.+/m.test(body)) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Konten tidak memiliki struktur sintaks KEY=VALUE yang valid untuk file .env.",
        };
      }
      break;

    case "git":
      if (isHtml || (!body.includes("ref: refs/") && !/^[0-9a-f]{40}/i.test(body.trim()))) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Respon untuk .git/HEAD bukan git reference pointer (terdeteksi template HTML atau custom error 200).",
        };
      }
      break;

    case "graphql":
      if (isHtml || body.includes("GraphQL introspection is not allowed") || body.includes("Introspection is disabled") || !body.includes("__schema")) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Endpoint GraphQL secara eksplisit memblokir kueri introspeksi schema.",
        };
      }
      break;

    case "actuator":
      if (isHtml || !body.startsWith("{") || !body.includes("propertySources")) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Respon /actuator/env bukan payload JSON Spring Boot Actuator asli (HTML fallback).",
        };
      }
      break;

    case "wp_users":
      if (isHtml || !body.startsWith("[") || body.includes("rest_cannot_access") || body.includes("rest_no_route")) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: REST API user enumeration dibatasi atau dinonaktifkan oleh server.",
        };
      }
      break;

    case "cots":
      if (isSpaCatchAll) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Endpoint COTS merespons dengan shell SPA catch-all bawaan frontend framework.",
        };
      }
      break;

    case "metafile":
      if (isHtml) {
        return {
          isFalsePositive: true,
          reason: "FALSE POSITIVE: Respon metafile berformat HTML (indikasi custom 404 soft-error).",
        };
      }
      break;
  }

  return { isFalsePositive: false, reason: "VERIFIED TRUE POSITIVE: Respons diverifikasi memenuhi signature teknis asli temuan." };
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
  // Filter out any finding marked as false positive
  const validFindings = findings.filter((f) => f.isVerifiedTruePositive !== false);

  if (validFindings.length === 0) {
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
    if (validFindings.some((f) => f.severity === s)) {
      highestSeverity = s;
      break;
    }
  }

  const isFail = highestSeverity === "CRITICAL" || highestSeverity === "HIGH" || highestSeverity === "MEDIUM";
  const status: WstgStatus = isFail ? "FAIL" : "REVIEW";

  const evidenceSummary = validFindings
    .map((f) => `[${f.severity}] ${f.title}: ${f.evidence}`)
    .join(" | ");

  const recommendation = validFindings
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
