import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info09FingerprintWebApp(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-09";
  const title = "Fingerprint Web Application";
  const subAgentName = "AppFingerprintSubagent";
  const objective = "Identifikasi Commercial Off-The-Shelf (COTS) & CMS (WordPress, Drupal, Joomla, Ghost, Strapi, Keycloak) serta evaluasi file dokumentasi bawaan dan REST API user enumeration.";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai fingerprinting CMS dan aplikasi COTS pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Check <meta name="generator"> in HTML
  ctx.log("INFO", "Memeriksa tag meta generator pada HTML root...");
  const rootRes = await safeFetch(ctx.targetUrl);
  const generatorMatch = rootRes.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (generatorMatch) {
    const generatorContent = generatorMatch[1];
    findings.push({
      title: "Tag Meta Generator Mengekspos Software & Versi",
      detail: `Tag meta generator pada HTML secara gamblang mencantumkan informasi software: "${generatorContent}".`,
      evidence: `Meta Generator: ${generatorContent}`,
      severity: "LOW",
      recommendation: "Hapus tag meta generator dari template HTML (misal: 'remove_action(\"wp_head\", \"wp_generator\");' pada WordPress).",
    });
    ctx.log("WARN", `Meta generator terdeteksi: ${generatorContent}`);
  } else {
    ctx.log("PASS", "Tag meta generator tidak ditemukan atau telah dibersihkan.");
  }

  // 2. Probe Common CMS / COTS Artifacts
  ctx.log("INFO", "Memeriksa artefak instalasi dan file dokumentasi CMS bawaan...");
  const cotsFiles = [
    { path: "/wp-login.php", name: "WordPress Login Interface", cms: "WordPress" },
    { path: "/readme.html", name: "WordPress Readme File", cms: "WordPress" },
    { path: "/license.txt", name: "CMS License File", cms: "Generic CMS" },
    { path: "/administrator/", name: "Joomla Administrator Portal", cms: "Joomla" },
    { path: "/ghost/", name: "Ghost CMS Admin Portal", cms: "Ghost" },
    { path: "/server/info", name: "Directus Server Info Endpoint", cms: "Directus" },
  ];

  for (const item of cotsFiles) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 4000 });
      if (res.status === 200 && res.text.length > 50) {
        // If readme.html exposes version
        if (item.path === "/readme.html" && /version\s+\d+\.\d+/i.test(res.text)) {
          const vMatch = res.text.match(/version\s+\d+\.\d+(\.\d+)?/i);
          findings.push({
            title: "File Readme CMS Terbuka & Mengekspos Versi Rilis",
            detail: `File ${item.path} dapat diakses langsung dan mengungkap versi CMS: ${vMatch ? vMatch[0] : "Version found"}.`,
            evidence: `URL: ${baseUrl}${item.path}`,
            severity: "LOW",
            recommendation: `Hapus file ${item.path} dari document root produksi.`,
          });
          ctx.log("WARN", `Readme terbuka di ${item.path} membocorkan versi.`);
        } else {
          ctx.log("INFO", `Artefak COTS terdeteksi: ${item.name} (${item.path})`);
        }
      }
    } catch {}
  }

  // 3. Probe WordPress REST API User Enumeration
  ctx.log("INFO", "Menguji REST API user enumeration (/wp-json/wp/v2/users)...");
  try {
    const wpUsersRes = await safeFetch(`${baseUrl}/wp-json/wp/v2/users`, { timeoutMs: 5000 });
    if (wpUsersRes.status === 200 && wpUsersRes.text.startsWith("[")) {
      const users = JSON.parse(wpUsersRes.text);
      if (Array.isArray(users) && users.length > 0 && users[0].slug) {
        const usernames = users.map((u: any) => u.slug).slice(0, 5);
        findings.push({
          title: "WordPress REST API User Enumeration Terbuka",
          detail: `Endpoint /wp-json/wp/v2/users membocorkan daftar username internal (${usernames.join(", ")}). Penyerang dapat menggunakan daftar ini untuk serangan brute force password.`,
          evidence: `Usernames: ${usernames.join(", ")}`,
          severity: "MEDIUM",
          recommendation: "Nonaktifkan endpoint user REST API untuk pengguna publik atau pasang plugin hardening keamanan.",
        });
        ctx.log("FAIL", `User enumeration berhasil: ${usernames.join(", ")}`);
      }
    } else {
      ctx.log("PASS", "REST API user enumeration tidak aktif atau terproteksi.");
    }
  } catch {}

  const evaluated = evaluateFindings(
    findings,
    "Aplikasi web tidak mengekspos file dokumentasi bawaan CMS maupun endpoint user enumeration terbuka.",
    "Lakukan sanitasi berkala terhadap file bawaan vendor dan batasi akses ke antarmuka login backend."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-09: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
