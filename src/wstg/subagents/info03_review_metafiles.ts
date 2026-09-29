import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info03ReviewMetafiles(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-03";
  const title = "Review Webserver Metafiles";
  const subAgentName = "WebserverMetafilesSubagent";
  const objective = "Inspeksi file metadata server (robots.txt, sitemap.xml, security.txt, .well-known/*, crossdomain.xml) untuk menemukan private routes, unlinked admin paths, dan security policies.";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai review file metadata server pada target: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Probe robots.txt
  ctx.log("INFO", "Memeriksa keberadaan dan isi /robots.txt...");
  const robotsRes = await safeFetch(`${baseUrl}/robots.txt`);
  if (robotsRes.status === 200 && robotsRes.text.toLowerCase().includes("user-agent")) {
    ctx.log("INFO", "robots.txt ditemukan dan dapat diakses.");
    const lines = robotsRes.text.split("\n");
    const disallows = lines
      .filter((l) => l.trim().toLowerCase().startsWith("disallow:"))
      .map((l) => l.split(":")[1]?.trim() || "");

    const sensitiveDisallows = disallows.filter((p) =>
      /\/(admin|dashboard|portal|backup|internal|secret|private|config|api\/v\d|staging|dev)/i.test(p)
    );

    if (sensitiveDisallows.length > 0) {
      findings.push({
        title: "File robots.txt Membocorkan Direktori Administratif / Sensitif",
        detail: `Direktori berikut terdaftar pada aturan Disallow di robots.txt: ${sensitiveDisallows.slice(0, 5).join(", ")}. Ini membantu penyerang memetakan path bernilai tinggi.`,
        evidence: `Disallow paths: ${sensitiveDisallows.join(", ")}`,
        severity: "LOW",
        recommendation: "Hindari mencantumkan direktori sensitif/rahasia di robots.txt publik. Lindungi direktori tersebut dengan kontrol autentikasi dan otorisasi yang ketat.",
      });
      ctx.log("WARN", `robots.txt membocorkan ${sensitiveDisallows.length} path sensitif.`);
    } else {
      ctx.log("PASS", `robots.txt tidak memuat path sensitif kritis (${disallows.length} aturan disallow reguler).`);
    }
  } else {
    ctx.log("INFO", `robots.txt tidak ditemukan (HTTP ${robotsRes.status}).`);
  }

  // 2. Probe security.txt (RFC 9116)
  ctx.log("INFO", "Memeriksa kepatuhan RFC 9116 (.well-known/security.txt)...");
  let secRes = await safeFetch(`${baseUrl}/.well-known/security.txt`);
  if (secRes.status !== 200) {
    secRes = await safeFetch(`${baseUrl}/security.txt`);
  }

  if (secRes.status === 200 && secRes.text.toLowerCase().includes("contact:")) {
    ctx.log("PASS", "File security.txt valid sesuai RFC 9116 ditemukan.");
    const hasExpires = secRes.text.toLowerCase().includes("expires:");
    if (!hasExpires) {
      findings.push({
        title: "security.txt Tidak Memuat Direktif 'Expires'",
        detail: "File security.txt ada tetapi tidak mencantumkan batas waktu validitas (Expires:) sesuai RFC 9116.",
        evidence: "Expires directive missing",
        severity: "INFORMATIONAL",
        recommendation: "Tambahkan direktif 'Expires: YYYY-MM-DDTHH:MM:SSZ' pada security.txt.",
      });
    }
  } else {
    ctx.log("INFO", "File security.txt tidak ditemukan atau tidak memuat direktif Contact.");
  }

  // 3. Probe crossdomain.xml & clientaccesspolicy.xml
  ctx.log("INFO", "Memeriksa kebijakan Flash/Silverlight cross-domain permissions...");
  const crossdomainRes = await safeFetch(`${baseUrl}/crossdomain.xml`);
  if (crossdomainRes.status === 200) {
    if (crossdomainRes.text.includes('domain="*"')) {
      findings.push({
        title: "File crossdomain.xml Terlalu Permisif (Wildcard Domain)",
        detail: "crossdomain.xml mengizinkan akses dari domain apa pun ('*'), memungkinkan eksfiltrasi data lintas-domain pada legacy client.",
        evidence: 'crossdomain.xml memuat domain="*"',
        severity: "MEDIUM",
        recommendation: "Batasi domain yang diizinkan pada crossdomain.xml atau hapus file jika Flash/RIA tidak lagi digunakan.",
      });
      ctx.log("FAIL", "crossdomain.xml mengizinkan akses dari sembarang domain (wildcard).");
    } else {
      ctx.log("PASS", "crossdomain.xml ada dengan konfigurasi terikat spesifik.");
    }
  }

  // 4. Probe Mobile App Bindings (.well-known/assetlinks.json & apple-app-site-association)
  ctx.log("INFO", "Memeriksa mobile deep-link metadata (.well-known/assetlinks.json & apple-app-site-association)...");
  const assetlinksRes = await safeFetch(`${baseUrl}/.well-known/assetlinks.json`);
  if (assetlinksRes.status === 200 && assetlinksRes.text.includes("package_name")) {
    ctx.log("INFO", "Ditemukan konfigurasi Android App Links (.well-known/assetlinks.json).");
  }

  const appleRes = await safeFetch(`${baseUrl}/.well-known/apple-app-site-association`);
  if (appleRes.status === 200 && (appleRes.text.includes("applinks") || appleRes.text.includes("appID"))) {
    ctx.log("INFO", "Ditemukan konfigurasi iOS Universal Links (.well-known/apple-app-site-association).");
  }

  // 5. Probe sitemap.xml
  ctx.log("INFO", "Memeriksa ketersediaan sitemap.xml...");
  const sitemapRes = await safeFetch(`${baseUrl}/sitemap.xml`);
  if (sitemapRes.status === 200 && sitemapRes.text.includes("<urlset")) {
    ctx.log("INFO", "sitemap.xml aktif dan dapat diakses.");
    if (sitemapRes.text.match(/(staging|dev|internal|test)\./i)) {
      findings.push({
        title: "sitemap.xml Mengekspos URL Lingkungan Staging/Internal",
        detail: "sitemap.xml memuat URL yang mengarah ke subdomain staging atau internal testing.",
        evidence: "Staging URL detected in sitemap.xml",
        severity: "LOW",
        recommendation: "Bersihkan URL development dan staging dari sitemap produksi.",
      });
      ctx.log("WARN", "sitemap.xml memuat referensi subdomain staging/internal.");
    }
  }

  const evaluated = evaluateFindings(
    findings,
    "Metadata server (robots.txt, sitemap, security.txt, crossdomain) terkonfigurasi dengan aman tanpa kebocoran path rahasia.",
    "Pertahankan auditing berkala terhadap file metadata untuk mencegah registrasi path sensitif."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-03: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
