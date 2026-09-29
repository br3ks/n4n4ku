import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info02WebServerFingerprint(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-02";
  const title = "Fingerprint Web Server";
  const subAgentName = "WebServerFingerprintSubagent";
  const objective = "Identifikasi software web server, versi exact, patch level, host OS, active modules, dan error leakage saat menerima malformed requests.";

  ctx.log("INFO", `Memulai fingerprinting web server pada target: ${ctx.targetUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Inspect Standard Response Headers
  ctx.log("INFO", "Mengirim HTTP GET probe untuk mengevaluasi header server...");
  const rootRes = await safeFetch(ctx.targetUrl);

  const serverHeader = rootRes.headers.get("server");
  const xPoweredBy = rootRes.headers.get("x-powered-by");
  const xAspNetVer = rootRes.headers.get("x-aspnet-version");
  const altSvc = rootRes.headers.get("alt-svc");

  if (serverHeader) {
    ctx.log("INFO", `Header 'Server' terdeteksi: "${serverHeader}"`);
    // Check if exact version or OS signature is exposed (e.g. Apache/2.4.49, nginx/1.18.0 (Ubuntu))
    const hasExactVersion = /\d+\.\d+(\.\d+)?/.test(serverHeader);
    const hasOsSignature = /ubuntu|debian|centos|redhat|win32|win64/i.test(serverHeader);

    if (hasExactVersion && hasOsSignature) {
      findings.push({
        title: "Web Server Header Membocorkan Versi Exact & Host OS",
        detail: `Server header mengembalikan informasi rilis daemon lengkap dan sistem operasi host: "${serverHeader}".`,
        evidence: `Server: ${serverHeader}`,
        severity: "MEDIUM",
        recommendation: "Matikankan server signature (contoh: 'server_tokens off;' pada Nginx atau 'ServerSignature Off' / 'ServerTokens Prod' pada Apache).",
      });
      ctx.log("FAIL", `Kebocorkan versi server & OS: ${serverHeader}`);
    } else if (hasExactVersion) {
      findings.push({
        title: "Web Server Header Mengekspos Versi Rilis Software",
        detail: `Header Server mencantumkan versi rilis spesifik: "${serverHeader}". Ini memudahkan penyerang mencocokkan CVE publik.`,
        evidence: `Server: ${serverHeader}`,
        severity: "LOW",
        recommendation: "Konfigurasi web server atau reverse proxy untuk mengembalikan header generik tanpa rilis versi.",
      });
      ctx.log("WARN", `Server header mengekspos nomor versi: ${serverHeader}`);
    } else {
      ctx.log("PASS", `Header Server bersih / generik: "${serverHeader}"`);
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
    });
    ctx.log("WARN", `X-AspNet-Version terdeteksi: ${xAspNetVer}`);
  }

  if (altSvc) {
    ctx.log("INFO", `Alt-Svc terdeteksi: ${altSvc.slice(0, 50)}... (Mendukung HTTP/3 QUIC)`);
  }

  // 2. Malformed Method Probe to Test Error Leakage
  ctx.log("INFO", "Menguji error leakage menggunakan malformed HTTP request (BADMETHOD)...");
  try {
    const malformedRes = await safeFetch(ctx.targetUrl, {
      method: "BADMETHOD",
    });
    ctx.log("INFO", `Status respon untuk BADMETHOD: ${malformedRes.status}`);

    const malformedServer = malformedRes.headers.get("server");
    if (malformedServer && !serverHeader && /\d+\.\d+/.test(malformedServer)) {
      findings.push({
        title: "Server Banner Leakage pada Halaman Error",
        detail: `Server menyembunyikan header pada HTTP 200 tetapi membocorkan versi daemon pada kondisi HTTP error (${malformedRes.status}): "${malformedServer}".`,
        evidence: `Server error header: ${malformedServer}`,
        severity: "LOW",
        recommendation: "Pastikan konfigurasi penyembunyian banner diterapkan secara global pada level reverse proxy untuk semua status code.",
      });
      ctx.log("WARN", `Error leakage terdeteksi: ${malformedServer}`);
    }

    // Check body error for OS/daemon default pages
    if (/apache|nginx|microsoft-iis|lighttpd|caddy/i.test(malformedRes.text) && /\d+\.\d+/.test(malformedRes.text)) {
      const match = malformedRes.text.match(/(apache[\w\s/.-]+|nginx[\w\s/.-]+|microsoft-iis[\w\s/.-]+)/i);
      if (match) {
        findings.push({
          title: "Halaman Error Bawaan Web Server Bocor",
          detail: `Halaman error HTTP ${malformedRes.status} memuat signature software bawaan: "${match[0].slice(0, 80)}".`,
          evidence: `Signature: ${match[0].slice(0, 80)}`,
          severity: "LOW",
          recommendation: "Gunakan custom error pages yang seragam agar tidak membocorkan identitas daemon web server.",
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

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-02: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
