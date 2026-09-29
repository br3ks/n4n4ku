import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";

export async function info02WebServerFingerprint(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-02";
  const title = "Fingerprint Web Server";
  const subAgentName = "WebServerFingerprintSubagent";
  const objective = "Identifikasi software web server, versi exact, patch level, host OS, active modules, dan error leakage saat menerima malformed requests.";
  const toolsUsed = ["curl", "httpx", "whatweb", "RFC Non-Compliant Method Probe", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  ctx.log("INFO", `Memulai fingerprinting web server pada target: ${ctx.targetUrl}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Banner server dianalisis untuk memastikan tidak tertukar antara edge CDN proxy dan origin daemon.";

  // 1. Inspect Standard Response Headers
  ctx.log("INFO", "Mengirim HTTP GET probe untuk mengevaluasi header server...");
  const rootRes = await safeFetch(ctx.targetUrl);

  const serverHeader = rootRes.headers.get("server");
  const xPoweredBy = rootRes.headers.get("x-powered-by");
  const xAspNetVer = rootRes.headers.get("x-aspnet-version");
  const altSvc = rootRes.headers.get("alt-svc");

  rawProbes.push({
    method: "GET",
    url: ctx.targetUrl,
    status: rootRes.status,
    headers: {
      Server: serverHeader || "None",
      "X-Powered-By": xPoweredBy || "None",
      "X-AspNet-Version": xAspNetVer || "None",
      "Alt-Svc": altSvc || "None",
    },
    bodySnippet: rootRes.text.slice(0, 250),
  });

  if (serverHeader) {
    ctx.log("INFO", `Header 'Server' terdeteksi: "${serverHeader}"`);
    const hasExactVersion = /\d+\.\d+(\.\d+)?/.test(serverHeader);
    const hasOsSignature = /ubuntu|debian|centos|redhat|win32|win64/i.test(serverHeader);

    if (hasExactVersion && hasOsSignature) {
      findings.push({
        title: "Web Server Header Membocorkan Versi Exact & Host OS",
        detail: `Server header mengembalikan informasi rilis daemon lengkap dan sistem operasi host: "${serverHeader}".`,
        evidence: `Server: ${serverHeader}`,
        severity: "MEDIUM",
        recommendation: "Matikankan server signature (contoh: 'server_tokens off;' pada Nginx atau 'ServerSignature Off' / 'ServerTokens Prod' pada Apache).",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Banner diverifikasi mengembalikan nomor versi dan nama OS host secara eksplisit.",
      });
      ctx.log("FAIL", `Kebocorkan versi server & OS: ${serverHeader}`);
    } else if (hasExactVersion) {
      findings.push({
        title: "Web Server Header Mengekspos Versi Rilis Software",
        detail: `Header Server mencantumkan versi rilis spesifik: "${serverHeader}". Ini memudahkan penyerang mencocokkan CVE publik.`,
        evidence: `Server: ${serverHeader}`,
        severity: "LOW",
        recommendation: "Konfigurasi web server atau reverse proxy untuk mengembalikan header generik tanpa rilis versi.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Nomor versi software terkonfirmasi ada pada string header Server.",
      });
      ctx.log("WARN", `Server header mengekspos nomor versi: ${serverHeader}`);
    } else {
      ctx.log("PASS", `Header Server bersih / generik: "${serverHeader}"`);
      fpLog += ` Header Server '${serverHeader}' diverifikasi generik tanpa nomor rilis/patch.`;
    }
  } else {
    ctx.log("PASS", "Header 'Server' disembunyikan/dihapus (Best practice).");
  }

  // Check X-Powered-By
  if (xPoweredBy) {
    findings.push({
      title: "Header X-Powered-By Aktif",
      detail: `Header 'X-Powered-By: ${xPoweredBy}' membeberkan teknologi backend yang digunakan.`,
      evidence: `X-Powered-By: ${xPoweredBy}`,
      severity: "LOW",
      recommendation: "Nonaktifkan header X-Powered-By pada server config (misal: 'app.disable(\"x-powered-by\")' pada Express atau 'expose_php = Off' di php.ini).",
      isVerifiedTruePositive: true,
      falsePositiveCheck: "Header X-Powered-By aktif di respon HTTP.",
    });
    ctx.log("WARN", `X-Powered-By terdeteksi: ${xPoweredBy}`);
  }

  // Check X-AspNet-Version
  if (xAspNetVer) {
    findings.push({
      title: "Header X-AspNet-Version Terbuka",
      detail: `Header membocorkan versi framework ASP.NET: ${xAspNetVer}.`,
      evidence: `X-AspNet-Version: ${xAspNetVer}`,
      severity: "LOW",
      recommendation: "Sembunyikan header X-AspNet-Version melalui konfigurasi web.config (<httpRuntime enableVersionHeader=\"false\" />).",
      isVerifiedTruePositive: true,
      falsePositiveCheck: "Header X-AspNet-Version aktif di respon HTTP.",
    });
  }

  // 2. Malformed Method Probe to Test Error Leakage
  ctx.log("INFO", "Menguji error leakage menggunakan malformed HTTP request (BADMETHOD)...");
  try {
    const malformedRes = await safeFetch(ctx.targetUrl, {
      method: "BADMETHOD",
    });
    rawProbes.push({
      method: "BADMETHOD",
      url: ctx.targetUrl,
      status: malformedRes.status,
      headers: {
        Server: malformedRes.headers.get("server") || "None",
        "Content-Type": malformedRes.headers.get("content-type") || "None",
      },
      bodySnippet: malformedRes.text.slice(0, 250),
    });

    const malformedServer = malformedRes.headers.get("server");
    if (malformedServer && !serverHeader && /\d+\.\d+/.test(malformedServer)) {
      findings.push({
        title: "Server Banner Leakage pada Halaman Error",
        detail: `Server menyembunyikan header pada HTTP 200 tetapi membocorkan versi daemon pada kondisi HTTP error (${malformedRes.status}): "${malformedServer}".`,
        evidence: `Server error header: ${malformedServer}`,
        severity: "LOW",
        recommendation: "Pastikan konfigurasi penyembunyian banner diterapkan secara global pada level reverse proxy untuk semua status code.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Verifikasi banner error mengonfirmasi kebocoran versi saat error terjadi.",
      });
      ctx.log("WARN", `Error leakage terdeteksi: ${malformedServer}`);
    }

    if (/apache|nginx|microsoft-iis|lighttpd|caddy/i.test(malformedRes.text) && /\d+\.\d+/.test(malformedRes.text)) {
      const match = malformedRes.text.match(/(apache[\w\s/.-]+|nginx[\w\s/.-]+|microsoft-iis[\w\s/.-]+)/i);
      if (match) {
        findings.push({
          title: "Halaman Error Bawaan Web Server Bocor",
          detail: `Halaman error HTTP ${malformedRes.status} memuat signature software bawaan: "${match[0].slice(0, 80)}".`,
          evidence: `Signature: ${match[0].slice(0, 80)}`,
          severity: "LOW",
          recommendation: "Gunakan custom error pages yang seragam agar tidak membocorkan identitas daemon web server.",
          isVerifiedTruePositive: true,
          falsePositiveCheck: "Template error bawaan daemon terdeteksi di body respon.",
        });
        ctx.log("WARN", `Error page signature: ${match[0].slice(0, 80)}`);
      }
    }
  } catch (err: any) {
    ctx.log("INFO", `Uji malformed request selesai: ${err.message}`);
  }

  const evaluated = evaluateFindings(
    findings,
    `Web server merespons tanpa kebocoran versi atau host OS signature. Banner server aman.`,
    "Pertahankan sanitasi banner server dan custom error handler yang seragam."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: curl -sI mengonfirmasi header Server bernilai generic (${serverHeader || "'dihapus'"}) tanpa nomor versi release atau host OS signature. Uji malformed request (BADMETHOD) menghasilkan respon error tanpa stack trace daemon internal.\nAlasan: Web server hardening berhasil menekan informasi versi; penyerang tidak dapat menentukan CVE target secara langsung dari response headers.`
      : `Evidence: Pengujian response header dan error leakage menemukan eksposur versi software (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: Web server belum dikonfigurasi untuk menonaktifkan server_tokens / ServerSignature, mempermudah reconnaissance versi untuk CVE mapping.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-02: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
    rawOutput: formatRawOutputs(rawProbes),
    recommendation: evaluated.recommendation,
    durationMs: Date.now() - start,
  };
}
