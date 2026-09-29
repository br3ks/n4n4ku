import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info08FingerprintFramework(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-08";
  const title = "Fingerprint Web Application Framework";
  const subAgentName = "FrameworkFingerprintSubagent";
  const objective = "Identifikasi framework web yang digunakan (Next.js, Spring Boot, Laravel, Django, Express, ASP.NET Core) beserta dependensi dan pemeriksaan debug routes.";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai fingerprinting framework web pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Inspect Cookies and Headers on Root
  ctx.log("INFO", "Menganalisis header respon dan session cookie signatures...");
  const rootRes = await safeFetch(ctx.targetUrl);
  const setCookie = rootRes.headers.get("set-cookie") || "";

  const frameworkSignatures = [
    { name: "Laravel", regex: /laravel_session|XSRF-TOKEN/i, cookie: true },
    { name: "Spring Boot", regex: /JSESSIONID/i, cookie: true },
    { name: "Express.js", regex: /connect\.sid/i, cookie: true },
    { name: "Django", regex: /csrftoken|sessionid/i, cookie: true },
    { name: "ASP.NET", regex: /ASP\.NET_SessionId|\.AspNetCore/i, cookie: true },
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
      });
    }
  }

  // Check Next.js / Nuxt HTML tags
  if (rootRes.text.includes("__NEXT_DATA__")) {
    ctx.log("INFO", "Framework Next.js / React terdeteksi via __NEXT_DATA__ tag.");
  } else if (rootRes.text.includes("__NUXT__")) {
    ctx.log("INFO", "Framework Nuxt.js / Vue terdeteksi via __NUXT__ object.");
  }

  // 2. Probe Spring Boot Actuator & Framework Debug Routes
  ctx.log("INFO", "Memeriksa rute debugging dan framework console internal...");
  const debugRoutes = [
    { path: "/actuator/env", name: "Spring Boot Actuator Env", critical: true },
    { path: "/actuator/health", name: "Spring Boot Actuator Health", critical: false },
    { path: "/_ignition/health-check", name: "Laravel Ignition Debug Handler", critical: true },
    { path: "/_profiler/", name: "Symfony Web Profiler", critical: true },
    { path: "/telescope/", name: "Laravel Telescope Dashboard", critical: true },
    { path: "/django-admin/", name: "Django Administration Portal", critical: false },
  ];

  for (const item of debugRoutes) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 4000 });
      if (res.status === 200) {
        if (item.critical) {
          findings.push({
            title: `Konsol Debug Framework Kritis Terekspos: ${item.name}`,
            detail: `Endpoint ${item.path} merespons HTTP 200. Debugger ini dapat mengekspos environment variable, database password, atau memicu RCE.`,
            evidence: `Path: ${item.path} (HTTP 200)`,
            severity: "CRITICAL",
            recommendation: `Segera nonaktifkan ${item.name} pada konfigurasi production!`,
          });
          ctx.log("FAIL", `[KRITIS] ${item.name} aktif di ${item.path}!`);
        } else {
          ctx.log("INFO", `Debug endpoint terdeteksi: ${item.path} (HTTP 200)`);
        }
      }
    } catch {}
  }

  // 3. Provoke 404 to check framework default error stack traces
  ctx.log("INFO", "Menguji respon error kustom (mencegah stack trace leakage)...");
  try {
    const errorRes = await safeFetch(`${baseUrl}/sal4waku_non_existent_page_probe_404`, { timeoutMs: 4000 });
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
      });
      ctx.log("FAIL", "Stack trace framework bocor pada halaman error 404.");
    } else {
      ctx.log("PASS", "Halaman error 404 tidak membocorkan stack trace internal.");
    }
  } catch {}

  const evaluated = evaluateFindings(
    findings,
    "Framework web aman. Tidak ditemukan konsol debug aktif (/actuator, /_ignition) maupun kebocoran stack trace error.",
    "Pertahankan penonaktifan rute debug dan sanitasi session cookies."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-08: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
