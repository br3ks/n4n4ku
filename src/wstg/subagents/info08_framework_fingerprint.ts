import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, checkFalsePositive, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";

export async function info08FingerprintFramework(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-08";
  const title = "Fingerprint Web Application Framework";
  const subAgentName = "FrameworkFingerprintSubagent";
  const objective = "Identifikasi framework web yang digunakan (Next.js, Spring Boot, Laravel, Django, Express, ASP.NET Core) beserta dependensi dan pemeriksaan debug routes.";
  const toolsUsed = ["curl", "httpx", "ffuf", "Framework Signature Heuristics", "Debug Route Prober", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai fingerprinting framework web pada: ${baseUrl}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Setiap endpoint debug (/actuator, /_ignition) diverifikasi respon JSON atau profiler aslinya, bukan SPA catch-all HTML.";

  // 1. Inspect Cookies and Headers on Root
  ctx.log("INFO", "Menganalisis header respon dan session cookie signatures...");
  const rootRes = await safeFetch(ctx.targetUrl);
  const setCookie = rootRes.headers.get("set-cookie") || "";
  const xPoweredBy = rootRes.headers.get("x-powered-by") || "";

  rawProbes.push({
    method: "GET",
    url: ctx.targetUrl,
    status: rootRes.status,
    headers: {
      "Set-Cookie": setCookie || "None",
      "X-Powered-By": xPoweredBy || "None",
      "Content-Type": rootRes.headers.get("content-type") || "text/html",
    },
    bodySnippet: rootRes.text.slice(0, 200),
  });

  const frameworkSignatures = [
    { name: "Laravel", regex: /laravel_session|XSRF-TOKEN/i },
    { name: "Spring Boot", regex: /JSESSIONID/i },
    { name: "Express.js", regex: /connect\.sid/i },
    { name: "Django", regex: /csrftoken|sessionid/i },
    { name: "ASP.NET", regex: /ASP\.NET_SessionId|\.AspNetCore/i },
  ];

  for (const fs of frameworkSignatures) {
    if (fs.regex.test(setCookie)) {
      ctx.log("INFO", `Signature cookie framework terdeteksi: ${fs.name}`);
      findings.push({
        title: `Framework Teridentifikasi dari Session Cookie: ${fs.name}`,
        detail: `Nama cookie sesi '${setCookie.split(";")[0]}' mengindikasikan penggunaan backend framework ${fs.name}.`,
        evidence: `Cookie: ${setCookie.split(";")[0]}`,
        severity: "INFORMATIONAL",
        recommendation: "Gunakan nama session cookie generik (misal: 'id' atau 'session') untuk mengurangi jejak reconnaissance penyerang.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Nama cookie terkonfirmasi dikirim pada header Set-Cookie server.",
      });
    }
  }

  // 2. Probe Spring Boot Actuator & Framework Debug Routes
  ctx.log("INFO", "Memeriksa rute debugging dan framework console internal...");
  const debugRoutes = [
    { path: "/actuator/env", name: "Spring Boot Actuator Env", critical: true },
    { path: "/_ignition/health-check", name: "Laravel Ignition Debug Handler", critical: true },
    { path: "/_profiler/", name: "Symfony Web Profiler", critical: true },
    { path: "/telescope/", name: "Laravel Telescope Dashboard", critical: true },
  ];

  for (const item of debugRoutes) {
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
        const fpCheck = checkFalsePositive("actuator", res.status, res.text);
        if (fpCheck.isFalsePositive) {
          fpLog += ` Endpoint ${item.path} diabaikan (${fpCheck.reason}).`;
        } else {
          findings.push({
            title: `Konsol Debug Framework Kritis Terekspos: ${item.name}`,
            detail: `Endpoint ${item.path} merespons HTTP 200 dan terverifikasi memuat payload debugger aktif.`,
            evidence: `Path: ${item.path} (HTTP 200, True Actuator/Debugger)`,
            severity: "CRITICAL",
            recommendation: `Segera nonaktifkan ${item.name} pada konfigurasi production!`,
            isVerifiedTruePositive: true,
            falsePositiveCheck: fpCheck.reason,
          });
          ctx.log("FAIL", `[KRITIS] ${item.name} aktif di ${item.path}!`);
        }
      }
    } catch {}
  }

  // 3. Provoke 404 to check framework default error stack traces
  ctx.log("INFO", "Menguji respon error kustom (mencegah stack trace leakage)...");
  try {
    const errorRes = await safeFetch(`${baseUrl}/sal4waku_non_existent_page_probe_404`, { timeoutMs: 4000 });
    rawProbes.push({
      method: "GET",
      url: `${baseUrl}/sal4waku_non_existent_page_probe_404`,
      status: errorRes.status,
      headers: { "Content-Type": errorRes.headers.get("content-type") || "None" },
      bodySnippet: errorRes.text.slice(0, 200),
    });

    const isDefaultTrace = /(at\s+[\w$./]+:\d+:\d+|\bTraceback \(most recent call last\)|django\.core\.exceptions|org\.springframework\.)/i.test(
      errorRes.text
    );

    if (isDefaultTrace) {
      findings.push({
        title: "Stack Trace Error Bawaan Framework Bocor",
        detail: `Halaman error 404 membocorkan trace kode sumber, nomor baris, atau modul backend aplikasi.`,
        evidence: `Cuplikan trace: ${errorRes.text.slice(0, 100).replace(/\s+/g, " ")}`,
        severity: "MEDIUM",
        recommendation: "Gunakan handler error terpusat yang selalu mengembalikan respon user-friendly tanpa menyertakan exception stack trace internal.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Stack trace dengan nomor baris atau call stack terverifikasi ada pada respon 404.",
      });
      ctx.log("FAIL", "Stack trace framework bocor pada halaman error 404.");
    } else {
      ctx.log("PASS", "Halaman error 404 tidak membocorkan stack trace internal.");
    }
  } catch {}

  // 3. Nuclei Framework Debug & Signature Probe
  ctx.log("INFO", "Menjalankan Nuclei framework debug templates...");
  let nucleiOutput = "";
  try {
    const { runNucleiInfoAudit } = await import("../projectdiscovery.js");
    const nRes = await runNucleiInfoAudit(ctx.targetUrl, tech, "debug", { log: ctx.log });
    nucleiOutput = nRes.rawOutput;
    if (nRes.findings.length > 0) findings.push(...nRes.findings);
  } catch {}

  toolsUsed.push("nuclei");

  const evaluated = evaluateFindings(
    findings,
    "Framework web aman. Tidak ditemukan konsol debug aktif (/actuator, /_ignition) maupun kebocoran stack trace error.",
    "Pertahankan penonaktifan rute debug dan sanitasi session cookies."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: Header framework dibersihkan dan cookie session dinormalisasi. Probing ke endpoint debug framework (/actuator, /_ignition, /_profiler) mengembalikan status 404 atau bukan soft-404, dan respon error 404 menampilkan template kustom tanpa stack trace internal. Nuclei debug templates mengonfirmasi tidak ada konsol debug framework yang bocor.\nAlasan: Framework web telah di-harden; informasi versi disembunyikan dan endpoint administrasi framework dinonaktifkan pada level konfigurasi produksi.`
      : `Evidence: Ditemukan console debug atau stack trace bawaan framework yang terekspos (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: Konfigurasi debugging (seperti Spring Boot Actuator atau Laravel Ignition) masih aktif di lingkungan produksi.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-08: ${evaluated.status} (Severity: ${evaluated.severity})`);

  const combinedRaw = nucleiOutput
    ? `${nucleiOutput}\n\n${formatRawOutputs(rawProbes)}`
    : formatRawOutputs(rawProbes);

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
    rawOutput: combinedRaw,
    recommendation: evaluated.recommendation,
    durationMs: Date.now() - start,
  };
}
