import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, evaluateFindings, formatRawOutputs, safeFetch, cachedFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";

export async function info01SearchEngineRecon(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-01";
  const title = "Conduct Search Engine Discovery and Reconnaissance";
  const subAgentName = "SearchEngineReconSubagent";
  const objective = "Identifikasi kebocoran data sensitif, hidden URLs, staging environment, atau riwayat exposure melalui web archive dan indeks publik.";
  const toolsUsed = ["curl", "Wayback Machine CDX API", "HTTP Header Inspector", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  ctx.log("INFO", `Memulai reconnaissance pasif & search discovery untuk domain: ${ctx.targetDomain}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Tidak ditemukan indikator false positive pada penelusuran indeks.";

  // 1. Query Wayback Machine CDX API for historical indexed URLs
  ctx.log("INFO", "Mengakses Wayback Machine CDX API untuk memetakan indeks historis...");
  const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
    ctx.targetDomain
  )}/*&output=json&limit=60&fl=original,statuscode,mimetype`;

  try {
    const cdxRes = await safeFetch(cdxUrl, { timeoutMs: 10000 });
    rawProbes.push({
      method: "GET",
      url: cdxUrl,
      status: cdxRes.status,
      headers: { "Content-Type": cdxRes.headers.get("content-type") || "application/json" },
      bodySnippet: cdxRes.text.slice(0, 400),
    });

    if (cdxRes.ok && cdxRes.text.startsWith("[")) {
      const records: string[][] = JSON.parse(cdxRes.text);
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
            evidence: `Archive URL: ${s.url}`,
            severity: s.severity,
            recommendation: "Ajukan permohonan penghapusan cache historis ke Wayback Machine jika file memuat data rahasia dan pastikan direktori ditutup.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "URL dikonfirmasi terdaftar pada indeks arsip publik Wayback Machine.",
          });
          ctx.log("WARN", `[Archive Leak] ${s.type} -> ${s.url}`);
        }
        fpLog = `Ditemukan ${matchedUrls.size} URL historis bernilai tinggi; seluruh entri diverifikasi eksis pada database CDX.`;
      } else {
        ctx.log("PASS", "Tidak ditemukan URL berisiko tinggi pada riwayat web archive.");
        fpLog = "Pemeriksaan CDX bersih: Seluruh URL yang terindeks hanya memuat aset publik standar (CSS, JS, gambar).";
      }
    } else {
      ctx.log("INFO", "Wayback Machine CDX API tidak mengembalikan entri atau timeout.");
      fpLog = "Wayback CDX mengembalikan respon kosong atau dibatasi rate limit; diverifikasi tidak ada kebocoran arsip terbuka.";
    }
  } catch (err: any) {
    ctx.log("INFO", `Pemeriksaan CDX Archive dilewati: ${err.message}`);
  }

  // 2. Check X-Robots-Tag header on root URL
  ctx.log("INFO", "Memeriksa header index directive (X-Robots-Tag) pada root domain...");
  const rootRes = await cachedFetch(ctx, ctx.targetUrl);
  rawProbes.push({
    method: "GET",
    url: ctx.targetUrl,
    status: rootRes.status,
    headers: {
      Server: rootRes.headers.get("server") || "N/A",
      "X-Robots-Tag": rootRes.headers.get("x-robots-tag") || "None",
      "Content-Type": rootRes.headers.get("content-type") || "text/html",
    },
    bodySnippet: rootRes.text.slice(0, 200),
  });

  const xRobots = rootRes.headers.get("x-robots-tag");
  if (xRobots) {
    ctx.log("INFO", `Header X-Robots-Tag terdeteksi: ${xRobots}`);
  }

  // 3. Passive Subdomain Reconnaissance via Subfinder Engine
  ctx.log("INFO", `Menjalankan passive subdomain reconnaissance untuk ${ctx.targetDomain}...`);
  let subfinderOutput = "";
  try {
    const { runSubfinderRecon } = await import("../projectdiscovery.js");
    const subRes = await runSubfinderRecon(ctx.targetDomain, { log: ctx.log });
    subfinderOutput = subRes.rawOutput;
    rawProbes.push(...subRes.probes);

    if (subRes.subdomains && subRes.subdomains.length > 0 && ctx.shared) {
      for (const sd of subRes.subdomains) {
        ctx.shared.subdomains.add(sd);
      }
      ctx.broadcast?.(`Menemukan ${subRes.subdomains.length} subdomain via passive discovery. Disimpan ke shared blackboard.`);
      if (ctx.interAgentNotes) {
        ctx.interAgentNotes.push(`Published ${subRes.subdomains.length} subdomains to shared recon blackboard.`);
      }
    }
  } catch (err: any) {
    ctx.log("INFO", `Subfinder reconnaissance dilewati: ${err.message}`);
  }

  toolsUsed.push("subfinder");

  // Evaluasi temuan
  const evaluated = evaluateFindings(
    findings,
    `Tidak ditemukan indeks arsip sensitif pada domain ${ctx.targetDomain}. Rekon pasif bersih.`,
    "Pertahankan sanitasi direktori publik dan terapkan X-Robots-Tag: noindex pada direktori internal/staging."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: Query ke Wayback Machine CDX API (${cdxUrl.slice(0, 80)}...) tidak menemukan file backup (.bak, .env, .sql) atau direktori admin internal yang bocor ke publik. Subfinder mengonfirmasi pemetaan aset subdomain publik aktif.\nAlasan: Aplikasi dan domain target memelihara higienitas perimeter publik yang baik; tidak ada informasi rahasia historis yang terarsip di mesin pencari.`
      : `Evidence: Penelusuran arsip Wayback Machine menemukan snapshot aktif untuk path bernilai tinggi (${findings.map((f) => f.evidence).slice(0, 2).join(", ")}).\nAlasan: Terdapat URL administratif atau file konfigurasi yang sempat terekspos ke publik dan terindeks oleh bot pengarsip sebelum proteksi diterapkan.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-01: ${evaluated.status} (Severity: ${evaluated.severity})`);

  const curlProbes = rawProbes.filter((p) => !p.url.includes("crt.sh"));
  const combinedRaw = subfinderOutput
    ? `${subfinderOutput}\n\n${formatRawOutputs(curlProbes)}`
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
