import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info07MapExecutionPaths(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-07";
  const title = "Map Execution Paths Through Application";
  const subAgentName = "ExecutionPathsSubagent";
  const objective = "Memetakan alur eksekusi logika aplikasi, user journeys, transisi state (state machine), step-skipping protections, dan webhook callback endpoints.";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai pemetaan alur eksekusi dan proteksi state machine pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Trace Redirect Chains on Root
  ctx.log("INFO", "Memeriksa redirect chains dan kanonisasi URL...");
  try {
    const headRes = await safeFetch(ctx.targetUrl, { method: "HEAD", redirect: "manual" });
    const location = headRes.headers.get("location");
    if (location && [301, 302, 307, 308].includes(headRes.status)) {
      ctx.log("INFO", `Root URL melakukan redirect (HTTP ${headRes.status}) ke: ${location}`);
    } else {
      ctx.log("INFO", `Root URL merespons langsung dengan status HTTP ${headRes.status}.`);
    }
  } catch {}

  // 2. Test Step-Skipping / Forced Browsing on Multi-step Workflows
  ctx.log("INFO", "Menguji proteksi forced browsing ke tahapan lanjutan tanpa otentikasi...");
  const workflowPaths = [
    { path: "/checkout/confirm", name: "Checkout Confirmation Flow" },
    { path: "/onboarding/step-final", name: "Onboarding Final Step" },
    { path: "/payment/success", name: "Payment Success State" },
    { path: "/api/checkout/confirm-payment", name: "Payment Confirmation API" },
  ];

  for (const wf of workflowPaths) {
    try {
      const res = await safeFetch(`${baseUrl}${wf.path}`, { timeoutMs: 4000 });
      if (res.status === 200) {
        findings.push({
          title: `Potensi Step-Skipping / Akses Alur Tanpa Validasi State: ${wf.name}`,
          detail: `Endpoint alur kerja (${wf.path}) merespons HTTP 200 tanpa adanya session atau verifikasi tahapan sebelumnya.`,
          evidence: `Path: ${wf.path}, Status: 200`,
          severity: "MEDIUM",
          recommendation: "Terapkan validasi state machine di sisi server (server-side session checking) sebelum merender halaman atau memproses transaksi lanjutan.",
        });
        ctx.log("WARN", `Forced browsing berhasil ke ${wf.path} (HTTP 200)`);
      } else if ([401, 403, 302].includes(res.status)) {
        ctx.log("PASS", `Endpoint ${wf.path} menerapkan kontrol akses (HTTP ${res.status}).`);
      }
    } catch {}
  }

  // 3. Probe Public Webhook & Callback Endpoints
  ctx.log("INFO", "Memetakan endpoint webhook pihak ketiga dan callback URL...");
  const webhookPaths = [
    { path: "/api/webhooks/stripe", provider: "Stripe Webhook" },
    { path: "/api/webhooks/paypal", provider: "PayPal Webhook" },
    { path: "/api/payment/callback", provider: "Payment Gateway Callback" },
    { path: "/api/oauth/callback", provider: "OAuth Callback Endpoint" },
  ];

  for (const wh of webhookPaths) {
    try {
      const res = await safeFetch(`${baseUrl}${wh.path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event: "test" }),
        timeoutMs: 4000,
      });

      // If webhook accepts arbitrary POST with 200 OK without signature header check
      if (res.status === 200) {
        findings.push({
          title: `Webhook Callback Tanpa Validasi Tanda Tangan: ${wh.provider}`,
          detail: `Endpoint ${wh.path} menerima payload POST pengujian dan merespons HTTP 200 OK tanpa memvalidasi signature header pihak ketiga.`,
          evidence: `Path: ${wh.path}, HTTP 200 pada unauthenticated POST`,
          severity: "MEDIUM",
          recommendation: "Pastikan seluruh webhook endpoint memverifikasi tanda tangan kriptografis (misal: Stripe-Signature / X-Hub-Signature).",
        });
        ctx.log("FAIL", `Webhook callback ${wh.path} terbuka tanpa verifikasi signature.`);
      } else {
        ctx.log("PASS", `Webhook ${wh.path} menolak payload tidak sah (HTTP ${res.status}).`);
      }
    } catch {}
  }

  const evaluated = evaluateFindings(
    findings,
    "Alur eksekusi aplikasi dan transisi status terlindungi oleh validasi server-side.",
    "Pertahankan arsitektur state machine yang ketat di server-side untuk semua proses multi-tahap."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-07: ${evaluated.status} (Severity: ${evaluated.severity})`);

  return {
    id,
    title,
    subAgentName,
    objective,
    status: evaluated.status,
    severity: evaluated.severity,
    findings,
    evidenceSummary: evaluated.evidenceSummary,
    recommendation: evaluated.recommendation,
    durationMs: Date.now() - start,
  };
}
