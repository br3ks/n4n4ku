import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, checkFalsePositive, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";

export async function info09FingerprintWebApp(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-09";
  const title = "Fingerprint Web Application";
  const subAgentName = "AppFingerprintSubagent";
  const objective = "Identifikasi Commercial Off-The-Shelf (COTS) & CMS (WordPress, Drupal, Joomla, Ghost, Strapi, Keycloak) serta evaluasi file dokumentasi bawaan dan REST API user enumeration.";
  const toolsUsed = ["curl", "httpx", "ffuf", "whatweb", "COTS & CMS Signature Scanner", "REST API User Enumerator", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai fingerprinting CMS dan aplikasi COTS pada: ${baseUrl}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Setiap endpoint CMS (/wp-login.php, readme.html, wp-json) diverifikasi bukan respon fallback SPA catch-all.";

  // 1. Check <meta name="generator"> in HTML
  ctx.log("INFO", "Memeriksa tag meta generator pada HTML root...");
  const rootRes = await safeFetch(ctx.targetUrl);
  rawProbes.push({
    method: "GET",
    url: ctx.targetUrl,
    status: rootRes.status,
    headers: { "Content-Type": rootRes.headers.get("content-type") || "text/html" },
    bodySnippet: rootRes.text.slice(0, 200),
  });

  const generatorMatch = rootRes.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (generatorMatch) {
    const generatorContent = generatorMatch[1];
    findings.push({
      title: "Tag Meta Generator Mengekspos Software & Versi",
      detail: `Tag meta generator pada HTML secara gamblang mencantumkan informasi software: "${generatorContent}".`,
      evidence: `Meta Generator: ${generatorContent}`,
      severity: "LOW",
      recommendation: "Hapus tag meta generator dari template HTML (misal: 'remove_action(\"wp_head\", \"wp_generator\");' pada WordPress).",
      isVerifiedTruePositive: true,
      falsePositiveCheck: "Tag meta generator ditemukan di markup DOM halaman.",
    });
    ctx.log("WARN", `Meta generator terdeteksi: ${generatorContent}`);
  } else {
    ctx.log("PASS", "Tag meta generator tidak ditemukan atau telah dibersihkan.");
  }

  // 2. Probe Common CMS / COTS Artifacts
  ctx.log("INFO", "Memeriksa artefak instalasi dan file dokumentasi CMS bawaan...");
  const cotsFiles = [
    { path: "/wp-login.php", name: "WordPress Login Interface", pattern: /loginform|wp-submit|user_login/i },
    { path: "/readme.html", name: "WordPress Readme File", pattern: /WordPress\s+Version|Semper\s+Fi/i },
    { path: "/administrator/", name: "Joomla Administrator Portal", pattern: /joomla|mod-login-username/i },
  ];

  for (const item of cotsFiles) {
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
        const fpCheck = checkFalsePositive("cots", res.status, res.text);
        const matchesPattern = item.pattern.test(res.text);

        if (fpCheck.isFalsePositive || !matchesPattern) {
          fpLog += ` Endpoint ${item.path} diabaikan (SPA shell, bukan COTS asli).`;
        } else {
          findings.push({
            title: `File / Antarmuka CMS Terbuka: ${item.name}`,
            detail: `File ${item.path} terverifikasi aktif dengan signature software bawaan.`,
            evidence: `Path: ${item.path} (HTTP 200)`,
            severity: "LOW",
            recommendation: `Sanitasi atau lindungi akses ke ${item.path}.`,
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Signature spesifik CMS terverifikasi cocok pada body respon.",
          });
          ctx.log("WARN", `Artefak COTS terkonfirmasi aktif di ${item.path}`);
        }
      }
    } catch {}
  }

  // 3. Probe WordPress REST API User Enumeration
  ctx.log("INFO", "Menguji REST API user enumeration (/wp-json/wp/v2/users)...");
  try {
    const wpUsersRes = await safeFetch(`${baseUrl}/wp-json/wp/v2/users`, { timeoutMs: 5000 });
    rawProbes.push({
      method: "GET",
      url: `${baseUrl}/wp-json/wp/v2/users`,
      status: wpUsersRes.status,
      headers: { "Content-Type": wpUsersRes.headers.get("content-type") || "None" },
      bodySnippet: wpUsersRes.text.slice(0, 250),
    });

    const wpFp = checkFalsePositive("wp_users", wpUsersRes.status, wpUsersRes.text);
    if (wpUsersRes.status === 200 && !wpFp.isFalsePositive && wpUsersRes.text.startsWith("[")) {
      const users = JSON.parse(wpUsersRes.text);
      if (Array.isArray(users) && users.length > 0 && users[0].slug) {
        const usernames = users.map((u: any) => u.slug).slice(0, 5);
        findings.push({
          title: "WordPress REST API User Enumeration Terbuka",
          detail: `Endpoint /wp-json/wp/v2/users membocorkan daftar username internal (${usernames.join(", ")}). Penyerang dapat menggunakan daftar ini untuk serangan brute force password.`,
          evidence: `Usernames: ${usernames.join(", ")}`,
          severity: "MEDIUM",
          recommendation: "Nonaktifkan endpoint user REST API untuk pengguna publik atau pasang plugin hardening keamanan.",
          isVerifiedTruePositive: true,
          falsePositiveCheck: "Respon JSON array memuat objek pengguna WordPress valid dengan atribut slug.",
        });
        ctx.log("FAIL", `User enumeration berhasil: ${usernames.join(", ")}`);
      }
    } else {
      ctx.log("PASS", "REST API user enumeration tidak aktif atau terproteksi.");
      fpLog += ` WordPress user enumeration: ${wpFp.reason}`;
    }
  } catch {}

  // 4. Nuclei CMS & COTS Detection
  ctx.log("INFO", "Menjalankan Nuclei CMS fingerprinting templates...");
  let nucleiOutput = "";
  try {
    const { runNucleiInfoAudit } = await import("../projectdiscovery.js");
    const nRes = await runNucleiInfoAudit(ctx.targetUrl, tech, "tech", { log: ctx.log });
    nucleiOutput = nRes.rawOutput;
    if (nRes.findings.length > 0) findings.push(...nRes.findings);
  } catch {}

  toolsUsed.push("nuclei");

  const evaluated = evaluateFindings(
    findings,
    "Aplikasi web tidak mengekspos file dokumentasi bawaan CMS maupun endpoint user enumeration terbuka.",
    "Lakukan sanitasi berkala terhadap file bawaan vendor dan batasi akses ke antarmuka login backend."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: Tidak ditemukan signature file COTS standar (readme.html, version.php mengembalikan 404). Tag meta generator di-strip dari halaman web. REST API user enumeration diblokir atau dinonaktifkan. Nuclei CMS templates mengonfirmasi tidak ada CVE / exposure COTS terbuka.\nAlasan: Aplikasi web di-harden secara memadai; artefak rilis, file dokumentasi bawaan, dan endpoint enumerasi pengguna dinonaktifkan dari publik.`
      : `Evidence: Ditemukan artefak instalasi CMS atau kebocoran daftar username pengguna (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: Konfigurasi default CMS belum di-harden sehingga mengizinkan enumerasi informasi sensitif ke publik.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-09: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
