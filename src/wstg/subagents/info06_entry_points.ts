import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info06IdentifyEntryPoints(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-06";
  const title = "Identify Application Entry Points";
  const subAgentName = "EntryPointsSubagent";
  const objective = "Memetakan seluruh attack surface aplikasi: URL routes, dynamic parameters, REST/GraphQL documentation, dan testing HTTP dangerous methods (TRACE/OPTIONS).";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai identifikasi entry points dan attack surface pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Test HTTP TRACE Method (Cross-Site Tracing / XST)
  ctx.log("INFO", "Menguji apakah metode HTTP TRACE diizinkan oleh server...");
  try {
    const traceRes = await safeFetch(ctx.targetUrl, { method: "TRACE" });
    if (traceRes.status === 200 && (traceRes.text.includes("TRACE") || traceRes.text.includes("Host:"))) {
      findings.push({
        title: "Metode HTTP TRACE Diizinkan (XST Vulnerability Risk)",
        detail: "Server merespons request TRACE dengan memantulkan kembali request headers. Ini memungkinkan penyerang mencuri HTTP-Only cookies melalui teknik Cross-Site Tracing.",
        evidence: `HTTP TRACE -> status ${traceRes.status}`,
        severity: "LOW",
        recommendation: "Nonaktifkan metode HTTP TRACE pada konfigurasi web server (misal: 'TraceEnable Off' pada Apache).",
      });
      ctx.log("FAIL", "HTTP TRACE diizinkan (200 OK)!");
    } else {
      ctx.log("PASS", `HTTP TRACE ditolak atau dinonaktifkan (HTTP ${traceRes.status}).`);
    }
  } catch {}

  // 2. Test HTTP OPTIONS Method
  ctx.log("INFO", "Mengirim HTTP OPTIONS untuk memetakan Allowed Methods...");
  try {
    const optionsRes = await safeFetch(ctx.targetUrl, { method: "OPTIONS" });
    const allowHeader = optionsRes.headers.get("allow");
    if (allowHeader) {
      ctx.log("INFO", `Header 'Allow' terdeteksi: ${allowHeader}`);
      if (/PUT|DELETE/i.test(allowHeader)) {
        findings.push({
          title: "Metode HTTP Berisiko Diizinkan pada Root Endpoint",
          detail: `Header Allow mengumumkan dukungan metode berisiko: ${allowHeader}.`,
          evidence: `Allow: ${allowHeader}`,
          severity: "INFORMATIONAL",
          recommendation: "Pastikan metode PUT dan DELETE dibatasi hanya untuk endpoint API yang memerlukan otentikasi ketat.",
        });
      }
    }
  } catch {}

  // 3. Probe REST API Documentation (Swagger / OpenAPI)
  ctx.log("INFO", "Memeriksa ketersediaan portal dokumentasi API (Swagger/OpenAPI)...");
  const apiDocsPaths = [
    { path: "/swagger.json", name: "Swagger JSON Schema" },
    { path: "/swagger-ui.html", name: "Swagger UI Interface" },
    { path: "/swagger-ui/index.html", name: "Swagger UI Index" },
    { path: "/api-docs", name: "Springdoc / OpenAPI Endpoint" },
    { path: "/openapi.json", name: "OpenAPI Specification JSON" },
  ];

  for (const item of apiDocsPaths) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 4000 });
      if (res.status === 200 && (res.text.includes('"swagger"') || res.text.includes('"openapi"') || res.text.includes("swagger-ui"))) {
        findings.push({
          title: `Dokumentasi API Publik Terbuka: ${item.name}`,
          detail: `Endpoint ${item.path} dapat diakses tanpa otentikasi. Ini mengungkap seluruh struktur rute API, model data, dan parameter backend kepada penyerang.`,
          evidence: `Path: ${item.path} (HTTP 200)`,
          severity: "LOW",
          recommendation: "Batasi akses ke dokumentasi Swagger/OpenAPI hanya untuk tim internal atau aktifkan di environment staging saja.",
        });
        ctx.log("WARN", `Portal dokumentasi terbuka di ${item.path}`);
        break;
      }
    } catch {}
  }

  // 4. Probe GraphQL Introspection
  ctx.log("INFO", "Memeriksa endpoint GraphQL dan status schema introspection...");
  const graphqlPaths = ["/graphql", "/api/graphql"];
  for (const gp of graphqlPaths) {
    try {
      const gqlRes = await safeFetch(`${baseUrl}${gp}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: "query IntrospectionQuery{__schema{queryType{name}}}",
        }),
        timeoutMs: 5000,
      });

      if (gqlRes.status === 200 && gqlRes.text.includes("__schema")) {
        findings.push({
          title: "GraphQL Introspection Schema Terbuka di Lingkungan Produksi",
          detail: `Endpoint ${gp} merespons query introspeksi. Penyerang dapat mengunduh seluruh skema GraphQL, tipe data, serta fungsi mutasi.`,
          evidence: `GraphQL Endpoint: ${gp} (Introspection Active)`,
          severity: "MEDIUM",
          recommendation: "Nonaktifkan GraphQL introspection di lingkungan produksi.",
        });
        ctx.log("FAIL", `GraphQL Introspection aktif pada ${gp}`);
        break;
      }
    } catch {}
  }

  const evaluated = evaluateFindings(
    findings,
    "Entry point aplikasi terkontrol dengan baik. HTTP TRACE dinonaktifkan dan dokumentasi API internal terproteksi.",
    "Pertahankan pembatasan metode HTTP serta proteksi endpoint dokumentasi API."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-06: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
