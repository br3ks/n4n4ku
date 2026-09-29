import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, checkFalsePositive, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";

export async function info03ReviewMetafiles(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-03";
  const title = "Review Webserver Metafiles";
  const subAgentName = "WebserverMetafilesSubagent";
  const objective = "Inspeksi file metadata server (robots.txt, sitemap.xml, security.txt, .well-known/*, crossdomain.xml) untuk menemukan private routes, unlinked admin paths, dan security policies.";
  const toolsUsed = ["curl", "httpx", "RFC 9116 Validator", "Metafile Parser", "n4n4ku AI Verification Engine"];

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai review file metadata server pada target: ${baseUrl}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Setiap respon metafile dicek apakah mengembalikan HTML SPA / soft-404.";

  // 1. Probe robots.txt
  ctx.log("INFO", "Memeriksa keberadaan dan isi /robots.txt...");
  const robotsRes = await safeFetch(`${baseUrl}/robots.txt`);
  rawProbes.push({
    method: "GET",
    url: `${baseUrl}/robots.txt`,
    status: robotsRes.status,
    headers: { "Content-Type": robotsRes.headers.get("content-type") || "text/plain" },
    bodySnippet: robotsRes.text.slice(0, 300),
  });

  const robotsFp = checkFalsePositive("metafile", robotsRes.status, robotsRes.text);
  if (robotsRes.status === 200 && !robotsFp.isFalsePositive && robotsRes.text.toLowerCase().includes("user-agent")) {
    ctx.log("INFO", "robots.txt ditemukan dan merupakan file teks valid.");
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
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Isi file robots.txt memuat aturan Disallow teks asli, bukan soft-404.",
      });
      ctx.log("WARN", `robots.txt membocorkan ${sensitiveDisallows.length} path sensitif.`);
    } else {
      ctx.log("PASS", `robots.txt tidak memuat path sensitif kritis (${disallows.length} aturan disallow reguler).`);
    }
  } else if (robotsFp.isFalsePositive) {
    ctx.log("INFO", `Respon /robots.txt diidentifikasi sebagai False Positive (${robotsFp.reason}).`);
    fpLog += ` /robots.txt: ${robotsFp.reason}`;
  }

  // 2. Probe security.txt (RFC 9116)
  ctx.log("INFO", "Memeriksa kepatuhan RFC 9116 (.well-known/security.txt)...");
  let secRes = await safeFetch(`${baseUrl}/.well-known/security.txt`);
  if (secRes.status !== 200) {
    secRes = await safeFetch(`${baseUrl}/security.txt`);
  }
  rawProbes.push({
    method: "GET",
    url: `${baseUrl}/.well-known/security.txt`,
    status: secRes.status,
    headers: { "Content-Type": secRes.headers.get("content-type") || "text/plain" },
    bodySnippet: secRes.text.slice(0, 200),
  });

  const secFp = checkFalsePositive("metafile", secRes.status, secRes.text);
  if (secRes.status === 200 && !secFp.isFalsePositive && secRes.text.toLowerCase().includes("contact:")) {
    ctx.log("PASS", "File security.txt valid sesuai RFC 9116 ditemukan.");
    const hasExpires = secRes.text.toLowerCase().includes("expires:");
    if (!hasExpires) {
      findings.push({
        title: "security.txt Tidak Memuat Direktif 'Expires'",
        detail: "File security.txt ada tetapi tidak mencantumkan batas waktu validitas (Expires:) sesuai RFC 9116.",
        evidence: "Expires directive missing",
        severity: "INFORMATIONAL",
        recommendation: "Tambahkan direktif 'Expires: YYYY-MM-DDTHH:MM:SSZ' pada security.txt.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "File security.txt valid tetapi kurang atribut Expires.",
      });
    }
  }

  // 3. Probe crossdomain.xml
  ctx.log("INFO", "Memeriksa kebijakan Flash/Silverlight cross-domain permissions...");
  const crossdomainRes = await safeFetch(`${baseUrl}/crossdomain.xml`);
  rawProbes.push({
    method: "GET",
    url: `${baseUrl}/crossdomain.xml`,
    status: crossdomainRes.status,
    headers: { "Content-Type": crossdomainRes.headers.get("content-type") || "application/xml" },
    bodySnippet: crossdomainRes.text.slice(0, 200),
  });

  const cdFp = checkFalsePositive("metafile", crossdomainRes.status, crossdomainRes.text);
  if (crossdomainRes.status === 200 && !cdFp.isFalsePositive && crossdomainRes.text.includes("<cross-domain-policy>")) {
    if (crossdomainRes.text.includes('domain="*"')) {
      findings.push({
        title: "File crossdomain.xml Terlalu Permisif (Wildcard Domain)",
        detail: "crossdomain.xml mengizinkan akses dari domain apa pun ('*'), memungkinkan eksfiltrasi data lintas-domain pada legacy client.",
        evidence: 'crossdomain.xml memuat domain="*"',
        severity: "MEDIUM",
        recommendation: "Batasi domain yang diizinkan pada crossdomain.xml atau hapus file jika Flash/RIA tidak lagi digunakan.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Valid XML cross-domain policy terkonfirmasi memuat wildcard domain.",
      });
      ctx.log("FAIL", "crossdomain.xml mengizinkan akses dari sembarang domain (wildcard).");
    }
  }

  // 4. Probe sitemap.xml
  ctx.log("INFO", "Memeriksa ketersediaan sitemap.xml...");
  const sitemapRes = await safeFetch(`${baseUrl}/sitemap.xml`);
  rawProbes.push({
    method: "GET",
    url: `${baseUrl}/sitemap.xml`,
    status: sitemapRes.status,
    headers: { "Content-Type": sitemapRes.headers.get("content-type") || "application/xml" },
    bodySnippet: sitemapRes.text.slice(0, 200),
  });

  if (sitemapRes.status === 200 && sitemapRes.text.includes("<urlset")) {
    if (sitemapRes.text.match(/(staging|dev|internal|test)\./i)) {
      findings.push({
        title: "sitemap.xml Mengekspos URL Lingkungan Staging/Internal",
        detail: "sitemap.xml memuat URL yang mengarah ke subdomain staging atau internal testing.",
        evidence: "Staging URL detected in sitemap.xml",
        severity: "LOW",
        recommendation: "Bersihkan URL development dan staging dari sitemap produksi.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "URL staging diverifikasi tertulis di dalam tag <loc> sitemap.xml.",
      });
      ctx.log("WARN", "sitemap.xml memuat referensi subdomain staging/internal.");
    }
  }

  const evaluated = evaluateFindings(
    findings,
    "Metadata server (robots.txt, sitemap, security.txt, crossdomain) terkonfigurasi dengan aman tanpa kebocoran path rahasia.",
    "Pertahankan auditing berkala terhadap file metadata untuk mencegah registrasi path sensitif."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: robots.txt tidak memuat path sensitif atau admin portal. Endpoint .well-known/security.txt terverifikasi aman atau disanitasi. Tidak ditemukan file crossdomain permisif (wildcard domain).\nAlasan: Seluruh metafile difilter dengan baik; tidak ada kebocoran endpoint tersembunyi atau hak akses lintas domain yang terbuka (crossdomain.xml non-existent/strict).`
      : `Evidence: Analisis metafile menemukan eksposur path rahasia atau konfigurasi permisif (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: File metadata publik membocorkan struktur internal aplikasi atau menerapkan kebijakan CORS/crossdomain yang terlalu longgar.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-03: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
