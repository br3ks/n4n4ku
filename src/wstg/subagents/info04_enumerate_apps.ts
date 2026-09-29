import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info04EnumerateApplications(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-04";
  const title = "Enumerate Applications on Webserver";
  const subAgentName = "AppEnumerationSubagent";
  const objective = "Identifikasi multi-tenancy, virtual hosts, mounted sub-applications, dan portal administrasi infrastruktur (Grafana, Kibana, Jenkins, phpMyAdmin).";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai enumerasi sub-aplikasi dan virtual hosts pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Probe common sub-application mount points
  const candidatePaths = [
    { path: "/admin", name: "Admin Portal", critical: false },
    { path: "/portal", name: "User Portal", critical: false },
    { path: "/api", name: "REST API Endpoint", critical: false },
    { path: "/dashboard", name: "Dashboard Interface", critical: false },
    { path: "/grafana", name: "Grafana Monitoring Console", critical: true },
    { path: "/jenkins", name: "Jenkins CI/CD Console", critical: true },
    { path: "/kibana", name: "Kibana Log Viewer", critical: true },
    { path: "/phpmyadmin", name: "phpMyAdmin Database Manager", critical: true },
    { path: "/swagger", name: "Swagger API Documentation", critical: false },
    { path: "/docs", name: "API Documentation", critical: false },
  ];

  ctx.log("INFO", `Memeriksa ${candidatePaths.length} endpoint umum sub-aplikasi...`);

  for (const item of candidatePaths) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 5000 });
      if (res.status === 200) {
        if (item.critical) {
          findings.push({
            title: `Konsol Infrastruktur Kritis Terekspos: ${item.name}`,
            detail: `Endpoint ${item.path} merespons HTTP 200 OK. Aplikasi manajemen internal terbuka ke publik tanpa isolasi firewall/VPN.`,
            evidence: `Path: ${item.path}, HTTP 200, Content: ${res.text.slice(0, 100)}...`,
            severity: "HIGH",
            recommendation: `Segera isolasi endpoint ${item.path} ke jaringan internal atau batasi via IP Whitelist dan VPN.`,
          });
          ctx.log("FAIL", `[EKSPOSUR KRITIS] ${item.name} aktif di ${item.path} (HTTP 200)`);
        } else {
          ctx.log("INFO", `Endpoint sub-aplikasi ditemukan: ${item.path} (HTTP 200)`);
        }
      } else if (res.status === 401 || res.status === 403) {
        ctx.log("PASS", `Endpoint ${item.path} terproteksi otorisasi (HTTP ${res.status}).`);
      }
    } catch {}
  }

  // 2. Virtual Host header probing (Bypass testing)
  ctx.log("INFO", "Menguji Virtual Host routing menggunakan custom Host header...");
  const vhostsToTest = [`dev.${ctx.targetDomain}`, `staging.${ctx.targetDomain}`, `internal.${ctx.targetDomain}`];

  for (const vhost of vhostsToTest) {
    try {
      const vhostRes = await safeFetch(ctx.targetUrl, {
        headers: { Host: vhost },
        timeoutMs: 5000,
      });

      // If server responds with 200 and custom text different from standard 404/Bad Request
      if (vhostRes.status === 200 && vhostRes.text.length > 200) {
        findings.push({
          title: "Virtual Host Staging/Internal Dapat Diakses Melalui Host Header",
          detail: `Server merespons HTTP 200 saat Host header disetel ke '${vhost}'. Ini mengindikasikan konfigurasi virtual host internal dapat diakses publik.`,
          evidence: `Host: ${vhost} -> HTTP 200`,
          severity: "MEDIUM",
          recommendation: "Konfigurasi reverse proxy / web server untuk memblokir permintaan dengan Host header yang tidak terdaftar resmi.",
        });
        ctx.log("WARN", `Virtual host responsif untuk Host: ${vhost}`);
        break;
      }
    } catch {}
  }

  const evaluated = evaluateFindings(
    findings,
    "Tidak ditemukan konsol manajemen internal terbuka (Grafana, Jenkins, phpMyAdmin) dan isolasi virtual host berjalan baik.",
    "Pertahankan segmentasi jaringan dan hindari meng-host aplikasi internal pada IP origin publik yang sama."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-04: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
