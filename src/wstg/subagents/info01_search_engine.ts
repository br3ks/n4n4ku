import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info01SearchEngineRecon(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-01";
  const title = "Conduct Search Engine Discovery and Reconnaissance";
  const subAgentName = "SearchEngineReconSubagent";
  const objective = "Identifikasi data sensitif, endpoint internal, staging portal, atau riwayat exposure melalui web archive dan indeks publik.";

  ctx.log("INFO", `Memulai reconnaissance pasif & search discovery untuk domain: ${ctx.targetDomain}`);

  const findings: WstgFinding[] = [];

  // 1. Query Wayback Machine CDX API for historical indexed URLs
  ctx.log("INFO", "Mengakses Wayback Machine CDX API untuk memetakan indeks historis...");
  const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
    ctx.targetDomain
  )}/*&output=json&limit=60&fl=original,statuscode,mimetype`;

  try {
    const cdxRes = await safeFetch(cdxUrl, { timeoutMs: 10000 });
    if (cdxRes.ok && cdxRes.text.startsWith("[")) {
      const records: string[][] = JSON.parse(cdxRes.text);
      // Skip header row
      const entries = records.slice(1);
      ctx.log("INFO", `Ditemukan ${entries.length} entri URL pada arsip publik.`);

      const sensitivePatterns = [
        { regex: /\.(env|bak|sql|tar|zip|gz|config|old|log)$/i, type: "Exposed Backup/Config File", severity: "HIGH" as const },
        { regex: /\/(admin|dashboard|portal|cpanel|kibana|grafana|swagger|api-docs)/i, type: "Exposed Administrative / API Path", severity: "MEDIUM" as const },
        { regex: /\/(staging|test|dev|internal)\./i, type: "Staging / Internal Environment Subdomain", severity: "LOW" as const },
      ];

      const matchedUrls = new Map<string, { url: string; type: string; severity: "HIGH" | "MEDIUM" | "LOW" }>();

      for (const entry of entries) {
        const originalUrl = entry[0];
        for (const p of sensitivePatterns) {
          if (p.regex.test(originalUrl) && !matchedUrls.has(originalUrl)) {
            matchedUrls.set(originalUrl, { url: originalUrl, type: p.type, severity: p.severity });
          }
        }
      }

      if (matchedUrls.size > 0) {
        const samples = Array.from(matchedUrls.values()).slice(0, 5);
        for (const s of samples) {
          findings.push({
            title: `Arsip Publik Memuat URL Berisiko: ${s.type}`,
            detail: `Wayback Machine menyimpan riwayat snapshot untuk path berisiko: ${s.url}`,
            evidence: `URL: ${s.url}`,
            severity: s.severity,
            recommendation: "Ajukan permohonan penghapusan cache historis ke Wayback Machine jika file memuat data rahasia dan pastikan direktori ditutup.",
          });
          ctx.log("WARN", `[Archive Leak] ${s.type} -> ${s.url}`);
        }
      } else {
        ctx.log("PASS", "Tidak ditemukan URL berisiko tinggi pada riwayat web archive.");
      }
    } else {
      ctx.log("INFO", "Wayback Machine CDX API tidak mengembalikan entri atau timeout.");
    }
  } catch (err: any) {
    ctx.log("INFO", `Pemeriksaan CDX Archive dilewati: ${err.message}`);
  }

  // 2. Check X-Robots-Tag header on root URL
  ctx.log("INFO", "Memeriksa header index directive (X-Robots-Tag) pada root domain...");
  const rootRes = await safeFetch(ctx.targetUrl);
  const xRobots = rootRes.headers.get("x-robots-tag");
  if (xRobots) {
    ctx.log("INFO", `Header X-Robots-Tag terdeteksi: ${xRobots}`);
  } else {
    ctx.log("INFO", "Header X-Robots-Tag tidak disematkan (indexing dikontrol via robots.txt atau meta tag).");
  }

  // 3. Evaluasi temuan
  const evaluated = evaluateFindings(
    findings,
    `Tidak ditemukan indeks arsip sensitif pada domain ${ctx.targetDomain}. Rekon pasif bersih.`,
    "Pertahankan sanitasi direktori publik dan terapkan X-Robots-Tag: noindex pada direktori internal/staging."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-01: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
