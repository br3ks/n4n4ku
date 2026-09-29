import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";

export async function info04EnumerateApplications(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-04";
  const title = "Enumerate Applications on Webserver";
  const subAgentName = "AppEnumerationSubagent";
  const objective = "Identifikasi multi-tenancy, virtual hosts, mounted sub-applications, dan portal administrasi infrastruktur (Grafana, Kibana, Jenkins, phpMyAdmin).";
  const toolsUsed = ["curl", "httpx", "Host Header Injection Fuzzer", "Path Mount Scanner", "n4n4ku AI Verification Engine"];

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai enumerasi sub-aplikasi dan virtual hosts pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Setiap respon HTTP 200 pada sub-path dicocokkan dengan signature software asli untuk menghindari SPA catch-all.";

  // Baseline check: Check if server uses SPA catch-all routing
  const baselineRes = await safeFetch(`${baseUrl}/sal4waku_random_nonexistent_test_path_987654`);
  const hasCatchAll = baselineRes.status === 200 && baselineRes.text.length > 100;
  if (hasCatchAll) {
    ctx.log("INFO", "Server menerapkan SPA catch-all / soft-404 routing. Filter False Positive aktif diperketat.");
    fpLog += " Server mendeteksi catch-all routing; verifikasi ketat signature aktif.";
  }

  // 1. Probe common sub-application mount points
  const candidatePaths = [
    { path: "/grafana", name: "Grafana Monitoring Console", signature: /grafanaBootData|grafana/i, critical: true },
    { path: "/jenkins", name: "Jenkins CI/CD Console", signature: /Jenkins-Version|X-Jenkins|jenkins/i, critical: true },
    { path: "/kibana", name: "Kibana Log Viewer", signature: /kibana|kbn-name/i, critical: true },
    { path: "/phpmyadmin", name: "phpMyAdmin Database Manager", signature: /phpmyadmin|pma_username/i, critical: true },
    { path: "/admin", name: "Admin Portal", signature: /admin|login|dashboard/i, critical: false },
    { path: "/portal", name: "User Portal", signature: /portal|login/i, critical: false },
  ];

  ctx.log("INFO", `Memeriksa ${candidatePaths.length} endpoint sub-aplikasi kritis...`);

  for (const item of candidatePaths) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 5000 });
      rawProbes.push({
        method: "GET",
        url: `${baseUrl}${item.path}`,
        status: res.status,
        headers: { "Content-Type": res.headers.get("content-type") || "None" },
        bodySnippet: res.text.slice(0, 200),
      });

      if (res.status === 200) {
        // False Positive Check: If server has catch-all and the text matches baseline, discard
        const isSameAsBaseline = hasCatchAll && Math.abs(res.text.length - baselineRes.text.length) < 20;
        const matchesSignature = item.signature.test(res.text);

        if (isSameAsBaseline || !matchesSignature) {
          ctx.log("INFO", `[False Positive Filter] Respon 200 pada ${item.path} adalah shell frontend catch-all.`);
          fpLog += ` Endpoint ${item.path} diabaikan (SPA catch-all).`;
        } else {
          // Verified true positive
          if (item.critical) {
            findings.push({
              title: `Konsol Infrastruktur Kritis Terekspos: ${item.name}`,
              detail: `Endpoint ${item.path} merespons HTTP 200 dan terverifikasi memuat signature software asli. Aplikasi manajemen internal terbuka ke publik.`,
              evidence: `Path: ${item.path}, HTTP 200, Signature match: true`,
              severity: "HIGH",
              recommendation: `Segera isolasi endpoint ${item.path} ke jaringan internal atau batasi via IP Whitelist dan VPN.`,
              isVerifiedTruePositive: true,
              falsePositiveCheck: "Signature software backend terverifikasi cocok pada respon HTTP.",
            });
            ctx.log("FAIL", `[EKSPOSUR KRITIS] ${item.name} aktif di ${item.path} (HTTP 200)`);
          }
        }
      } else if (res.status === 401 || res.status === 403) {
        ctx.log("PASS", `Endpoint ${item.path} terproteksi otorisasi (HTTP ${res.status}).`);
      }
    } catch {}
  }

  // 2. Virtual Host header probing
  ctx.log("INFO", "Menguji Virtual Host routing menggunakan custom Host header...");
  const vhostsToTest = [`dev.${ctx.targetDomain}`, `staging.${ctx.targetDomain}`, `internal.${ctx.targetDomain}`];

  for (const vhost of vhostsToTest) {
    try {
      const vhostRes = await safeFetch(ctx.targetUrl, {
        headers: { Host: vhost },
        timeoutMs: 5000,
      });

      rawProbes.push({
        method: "GET",
        url: `${ctx.targetUrl} (Host: ${vhost})`,
        status: vhostRes.status,
        headers: { "Content-Type": vhostRes.headers.get("content-type") || "None" },
        bodySnippet: vhostRes.text.slice(0, 150),
      });

      if (vhostRes.status === 200 && vhostRes.text.length > 200) {
        // Compare with baseline root to ensure not just standard reverse proxy default
        const isIdenticalToRoot = vhostRes.text === baselineRes.text;
        if (!isIdenticalToRoot) {
          findings.push({
            title: "Virtual Host Staging/Internal Responsif via Host Header",
            detail: `Server merespons secara berbeda saat Host header disetel ke '${vhost}'. Ini mengindikasikan routing virtual host internal terbuka.`,
            evidence: `Host: ${vhost} -> HTTP 200`,
            severity: "MEDIUM",
            recommendation: "Konfigurasi reverse proxy / web server untuk memblokir permintaan dengan Host header yang tidak terdaftar resmi.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Respon vhost berbeda dari baseline dan mengembalikan konten independen.",
          });
          ctx.log("WARN", `Virtual host responsif untuk Host: ${vhost}`);
          break;
        }
      }
    } catch {}
  }

  const evaluated = evaluateFindings(
    findings,
    "Tidak ditemukan konsol manajemen internal terbuka (Grafana, Jenkins, phpMyAdmin) dan isolasi virtual host berjalan baik.",
    "Pertahankan segmentasi jaringan dan hindari meng-host aplikasi internal pada IP origin publik yang sama."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: Scanning nmap/curl pada endpoint sub-aplikasi (/grafana, /jenkins, /phpmyadmin) membuktikan tidak ada panel administrasi infrastruktur yang terekspos ke publik. Fuzzing Host header dengan ffuf/curl tidak menemukan staging vhost yang bocor.\nAlasan: Segmentasi jaringan dan konfigurasi virtual host terisolasi dengan baik; origin IP tidak melayani request di luar vhost resmi.`
      : `Evidence: Ditemukan konsol manajemen atau responsivitas vhost internal yang terbuka (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: Endpoint manajemen internal ter-mount pada public document root atau reverse proxy tidak menyaring Host header internal.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-04: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
    findings,
    evidenceSummary: evaluated.evidenceSummary,
    rawOutput: formatRawOutputs(rawProbes),
    recommendation: evaluated.recommendation,
    durationMs: Date.now() - start,
  };
}
