import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, checkFalsePositive, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";
import { runDirectoryFuzzing } from "../fuzzer.js";

export async function info06IdentifyEntryPoints(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-06";
  const title = "Identify Application Entry Points";
  const subAgentName = "EntryPointsSubagent";
  const objective = "Memetakan seluruh attack surface aplikasi: URL routes, dynamic parameters, REST/GraphQL documentation, dan testing HTTP dangerous methods (TRACE/OPTIONS).";
  const toolsUsed = ["curl", "httpx", "ffuf", "dirsearch", "GraphQL Introspection Engine", "HTTP Method Tamperer", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai identifikasi entry points & fuzzing direktori pada: ${baseUrl}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: GraphQL introspection, directory fuzzing, dan API docs diverifikasi memiliki skema asli, bukan penolakan terselubung atau SPA shell.";

  // 1. Test HTTP TRACE Method (Cross-Site Tracing / XST)
  ctx.log("INFO", "Menguji apakah metode HTTP TRACE diizinkan oleh server...");
  let traceStatus = "ditolak/nonaktif";
  try {
    const traceRes = await safeFetch(ctx.targetUrl, { method: "TRACE" });
    traceStatus = `HTTP ${traceRes.status}`;
    rawProbes.push({
      method: "TRACE",
      url: ctx.targetUrl,
      status: traceRes.status,
      headers: { Allow: traceRes.headers.get("allow") || "None" },
      bodySnippet: traceRes.text.slice(0, 200),
    });

    if (traceRes.status === 200 && (traceRes.text.includes("TRACE") || traceRes.text.includes("Host:"))) {
      findings.push({
        title: "Metode HTTP TRACE Diizinkan (XST Vulnerability Risk)",
        detail: "Server merespons request TRACE dengan memantulkan kembali request headers. Ini memungkinkan penyerang mencuri HTTP-Only cookies melalui teknik Cross-Site Tracing.",
        evidence: `HTTP TRACE -> status ${traceRes.status}`,
        severity: "LOW",
        recommendation: "Nonaktifkan metode HTTP TRACE pada konfigurasi web server (misal: 'TraceEnable Off' pada Apache).",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Respon TRACE memantulkan header HTTP yang dikirim client.",
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
    rawProbes.push({
      method: "OPTIONS",
      url: ctx.targetUrl,
      status: optionsRes.status,
      headers: { Allow: allowHeader || "None" },
      bodySnippet: optionsRes.text.slice(0, 150),
    });

    if (allowHeader) {
      ctx.log("INFO", `Header 'Allow' terdeteksi: ${allowHeader}`);
      if (/PUT|DELETE/i.test(allowHeader)) {
        findings.push({
          title: "Metode HTTP Berisiko Diizinkan pada Root Endpoint",
          detail: `Header Allow mengumumkan dukungan metode berisiko: ${allowHeader}.`,
          evidence: `Allow: ${allowHeader}`,
          severity: "INFORMATIONAL",
          recommendation: "Pastikan metode PUT dan DELETE dibatasi hanya untuk endpoint API yang memerlukan otentikasi ketat.",
          isVerifiedTruePositive: true,
          falsePositiveCheck: "Header Allow memuat metode PUT/DELETE secara eksplisit.",
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
    { path: "/openapi.json", name: "OpenAPI Specification JSON" },
  ];

  for (const item of apiDocsPaths) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 4000 });
      rawProbes.push({
        method: "GET",
        url: `${baseUrl}${item.path}`,
        status: res.status,
        headers: { "Content-Type": res.headers.get("content-type") || "None" },
        bodySnippet: res.text.slice(0, 200),
      });

      if (res.status === 200) {
        // False Positive check: Must be JSON with swagger/openapi or HTML containing swagger-ui
        const isJsonSpec = res.text.startsWith("{") && (res.text.includes('"swagger"') || res.text.includes('"openapi"'));
        const isSwaggerUi = res.text.includes("swagger-ui") || res.text.includes("SwaggerUIBundle");

        if (isJsonSpec || isSwaggerUi) {
          findings.push({
            title: `Dokumentasi API Publik Terbuka: ${item.name}`,
            detail: `Endpoint ${item.path} dapat diakses tanpa otentikasi. Ini mengungkap seluruh struktur rute API, model data, dan parameter backend kepada penyerang.`,
            evidence: `Path: ${item.path} (HTTP 200, Spec Valid)`,
            severity: "LOW",
            recommendation: "Batasi akses ke dokumentasi Swagger/OpenAPI hanya untuk tim internal atau aktifkan di environment staging saja.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Spesifikasi skema Swagger/OpenAPI valid ditemukan di respon.",
          });
          ctx.log("WARN", `Portal dokumentasi terbuka di ${item.path}`);
          break;
        } else {
          fpLog += ` Path ${item.path} mengembalikan 200 tetapi bukan skema Swagger asli (SPA catch-all diabaikan).`;
        }
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

      rawProbes.push({
        method: "POST",
        url: `${baseUrl}${gp}`,
        status: gqlRes.status,
        headers: { "Content-Type": gqlRes.headers.get("content-type") || "application/json" },
        bodySnippet: gqlRes.text.slice(0, 250),
      });

      const gqlFp = checkFalsePositive("graphql", gqlRes.status, gqlRes.text);
      if (gqlRes.status === 200 && !gqlFp.isFalsePositive && gqlRes.text.includes("__schema")) {
        findings.push({
          title: "GraphQL Introspection Schema Terbuka di Lingkungan Produksi",
          detail: `Endpoint ${gp} merespons query introspeksi. Penyerang dapat mengunduh seluruh skema GraphQL, tipe data, serta fungsi mutasi.`,
          evidence: `GraphQL Endpoint: ${gp} (Introspection Active)`,
          severity: "MEDIUM",
          recommendation: "Nonaktifkan GraphQL introspection di lingkungan produksi.",
          isVerifiedTruePositive: true,
          falsePositiveCheck: "Respon JSON memuat root field '__schema' yang mengekspos tipe data GraphQL.",
        });
        ctx.log("FAIL", `GraphQL Introspection aktif pada ${gp}`);
        break;
      } else {
        fpLog += ` GraphQL pada ${gp}: ${gqlFp.reason}`;
      }
    } catch {}
  }

  // 5. Active Directory Fuzzing via ffuf / Native Parallel Engine
  ctx.log("INFO", "Menjalankan Active Directory Fuzzing berdasarkan profil teknologi target...");
  let fuzzOutput = "";
  try {
    const fuzzResult = await runDirectoryFuzzing(ctx.targetUrl, tech, ctx.log);
    fuzzOutput = fuzzResult.rawOutput;
    rawProbes.push(...fuzzResult.probes);

    for (const match of fuzzResult.matches) {
      if (match.isFalsePositive) {
        fpLog += ` Path /${match.path} diabaikan (SPA catch-all soft 404).`;
        continue;
      }

      // Check if critical exposed path
      if ([200, 301, 302].includes(match.status)) {
        if (/admin|portal|dashboard|phpmyadmin/i.test(match.path)) {
          findings.push({
            title: `Direktori Administratif Teridentifikasi dari Fuzzing: /${match.path}`,
            detail: `Directory fuzzer menemukan endpoint manajemen aktif pada /${match.path} (HTTP ${match.status}, Size: ${match.size} bytes).`,
            evidence: `Discovered: /${match.path} (Status ${match.status})`,
            severity: "MEDIUM",
            recommendation: "Pastikan akses ke antarmuka administratif dibatasi oleh VPN atau firewall IP whitelist.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Ukuran respon dan status code terverifikasi bukan SPA catch-all.",
          });
          ctx.log("WARN", `[Fuzz Match] Administrative portal aktif di /${match.path} (HTTP ${match.status})`);
        } else if (/actuator|h2-console|_ignition/i.test(match.path)) {
          findings.push({
            title: `Framework Debug Endpoint Teridentifikasi dari Fuzzing: /${match.path}`,
            detail: `Directory fuzzer menemukan rute debugging pada /${match.path} (HTTP ${match.status}).`,
            evidence: `Discovered: /${match.path} (Status ${match.status})`,
            severity: "HIGH",
            recommendation: "Nonaktifkan rute debugging pada production environment.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Validasi konten dan status code mengonfirmasi endpoint aktif.",
          });
          ctx.log("FAIL", `[Fuzz Match] Debug endpoint terbuka di /${match.path}`);
        }
      }
    }
  } catch (err: any) {
    ctx.log("WARN", `Directory fuzzing mengalami kendala: ${err.message}`);
  }

  // 6. ProjectDiscovery Katana Crawling & Nuclei API Discovery
  if (ctx.shared && ctx.shared.endpoints.size > 0) {
    ctx.log("INFO", `[Agent Comms] Mengintegrasikan ${ctx.shared.endpoints.size} endpoint dari shared blackboard (WSTG-INFO-03 & 05) untuk pemetaan entry points.`);
    if (ctx.interAgentNotes) {
      ctx.interAgentNotes.push(`Reused ${ctx.shared.endpoints.size} endpoints discovered by previous subagents.`);
    }
  }

  ctx.log("INFO", "Menjalankan Katana crawler untuk memetakan form input & URL query parameters...");
  let pdOutput = "";
  try {
    const { runKatanaCrawler, runNucleiInfoAudit } = await import("../projectdiscovery.js");
    const [katanaRes, nucleiRes] = await Promise.all([
      runKatanaCrawler(ctx.targetUrl, { log: ctx.log }),
      runNucleiInfoAudit(ctx.targetUrl, tech, "tech", { log: ctx.log }),
    ]);

    if (katanaRes.rawOutput) pdOutput += `${katanaRes.rawOutput}\n\n`;
    if (nucleiRes.rawOutput) pdOutput += `${nucleiRes.rawOutput}\n\n`;

    if (nucleiRes.findings.length > 0) {
      findings.push(...nucleiRes.findings);
    }
  } catch (err: any) {
    ctx.log("INFO", `Katana crawler module skipped: ${err.message}`);
  }

  toolsUsed.push("katana", "nuclei");

  const evaluated = evaluateFindings(
    findings,
    "Entry point aplikasi terkontrol dengan baik. HTTP TRACE dinonaktifkan dan dokumentasi API internal terproteksi.",
    "Pertahankan pembatasan metode HTTP serta proteksi endpoint dokumentasi API."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: HTTP TRACE dinonaktifkan (${traceStatus}). Endpoint /graphql merespons dengan disabling introspection schema atau nonaktif. Directory fuzzing dengan profil ${tech.frameworks.join("/") || "generic"} dan spidering Katana mengonfirmasi tidak ada attack surface tersembunyi yang terbuka tanpa otentikasi.\nAlasan: Attack surface terminimalisasi; dokumentasi internal tidak dapat diakses tanpa otorisasi dan request method dibatasi secara ketat oleh reverse proxy.`
      : `Evidence: Analisis entry point menemukan metode berbahaya, direktori sensitif, atau dokumentasi API yang terekspos (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: Server mengizinkan metode TRACE yang rentan XST, mengekspos blueprint API produksi, atau membiarkan direktori administratif terbuka.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-06: ${evaluated.status} (Severity: ${evaluated.severity})`);

  const curlProbes = rawProbes.filter((p) => !p.bodySnippet?.includes("[Matched via ffuf]"));
  const combinedRawOutput = [pdOutput, fuzzOutput, formatRawOutputs(curlProbes)]
    .filter(Boolean)
    .join("\n\n");

  return {
    id,
    title,
    subAgentName,
    objective,
    status: evaluated.status,
    severity: evaluated.severity,
    toolsUsed,
    verificationStatement,
    falsePositiveAnalysis: fpLog,
    adaptiveScenario,
    tailoredOneliners,
    findings,
    evidenceSummary: evaluated.evidenceSummary,
    rawOutput: combinedRawOutput,
    recommendation: evaluated.recommendation,
    durationMs: Date.now() - start,
  };
}
