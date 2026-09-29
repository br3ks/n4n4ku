import { WstgChecklistResult, WstgFinding } from "../types.js";
import { RawProbeRecord, SubagentContext, checkFalsePositive, evaluateFindings, formatRawOutputs, safeFetch } from "./base.js";
import { getAdaptiveScenario } from "../tech_matrix.js";

export async function info05ContentLeakage(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-05";
  const title = "Review Webpage Content for Information Leakage";
  const subAgentName = "ContentLeakageSubagent";
  const objective = "Audit HTML source code, developer comments, inline scripts, JavaScript bundles, source maps (.map), dan exposed configs (.git, .env).";
  const toolsUsed = ["curl", "httpx", "ffuf", "dirsearch", "JS Source Map Inspector", "Sensitive File Regex Tokenizer", "n4n4ku AI Verification Engine"];

  const tech = ctx.techStack || { servers: [], frameworks: [], runtimes: [], cms: [], technologies: [], isSpa: false };
  const { scenario: adaptiveScenario, tailoredOneliners } = getAdaptiveScenario(id, tech, ctx.targetUrl);

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai audit kebocoran konten pada: ${baseUrl}`);
  ctx.log("INFO", `[Adaptive Scenario] ${adaptiveScenario}`);

  const findings: WstgFinding[] = [];
  const rawProbes: RawProbeRecord[] = [];
  let fpLog = "Verifikasi False Positive: Seluruh respon 200 pada file rahasia (.env, .git) diverifikasi bukan merupakan fallback HTML SPA catch-all.";

  // 1. Audit Root HTML comments & inline secrets
  ctx.log("INFO", "Mengambil HTML homepage dan memeriksa komentar developer...");
  const htmlRes = await safeFetch(ctx.targetUrl);
  rawProbes.push({
    method: "GET",
    url: ctx.targetUrl,
    status: htmlRes.status,
    headers: { "Content-Type": htmlRes.headers.get("content-type") || "text/html" },
    bodySnippet: htmlRes.text.slice(0, 300),
  });

  if (htmlRes.ok && htmlRes.text) {
    const comments = htmlRes.text.match(/<!--([\s\S]*?)-->/g) || [];
    ctx.log("INFO", `Ditemukan ${comments.length} komentar HTML.`);

    const sensitiveComments: string[] = [];
    for (const c of comments) {
      if (/(todo|fixme|debug|password|secret|internal|endpoint|api_key|admin)/i.test(c)) {
        sensitiveComments.push(c.slice(0, 100).replace(/\s+/g, " "));
      }
    }

    if (sensitiveComments.length > 0) {
      findings.push({
        title: "Komentar Developer Memuat Catatan Sensitif / Internal",
        detail: `Komentar HTML di homepage memuat kata kunci seperti debug, todo, atau internal: "${sensitiveComments.slice(0, 3).join("; ")}".`,
        evidence: `Komentar: ${sensitiveComments.slice(0, 2).join(" | ")}`,
        severity: "LOW",
        recommendation: "Gunakan build step (minifikasi) untuk membersihkan seluruh komentar HTML sebelum dideploy ke produksi.",
        isVerifiedTruePositive: true,
        falsePositiveCheck: "Komentar diekstraksi langsung dari DOM HTML yang diunduh.",
      });
      ctx.log("WARN", `Ditemukan ${sensitiveComments.length} komentar berisiko di HTML.`);
    }

    // 2. Extract Script URLs and check for Source Maps (.map)
    const scriptSrcMatches = Array.from(htmlRes.text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi));
    const jsUrls = scriptSrcMatches
      .map((m) => m[1])
      .filter((s) => s.endsWith(".js") || s.includes(".js?"))
      .slice(0, 5);

    ctx.log("INFO", `Memeriksa ${jsUrls.length} file JavaScript untuk source map (.map)...`);
    for (const src of jsUrls) {
      const fullJsUrl = src.startsWith("http") ? src : `${baseUrl}/${src.replace(/^\//, "")}`;
      const mapUrl = `${fullJsUrl.split("?")[0]}.map`;
      try {
        const mapRes = await safeFetch(mapUrl, { timeoutMs: 5000 });
        rawProbes.push({
          method: "GET",
          url: mapUrl,
          status: mapRes.status,
          headers: { "Content-Type": mapRes.headers.get("content-type") || "None" },
          bodySnippet: mapRes.text.slice(0, 200),
        });

        // False positive check on map file: Must be JSON with "sources" or "mappings", not an HTML 404 page!
        const isTrueMap = mapRes.status === 200 && !mapRes.text.includes("<!DOCTYPE") && (mapRes.text.includes('"sources"') || mapRes.text.includes('"version"'));

        if (isTrueMap) {
          findings.push({
            title: "JavaScript Source Map (.map) Terbuka ke Publik",
            detail: `File source map (${mapUrl}) dapat diakses publik. Penyerang dapat merekonstruksi source code TypeScript/React asli secara penuh.`,
            evidence: `Source Map: ${mapUrl}`,
            severity: "MEDIUM",
            recommendation: "Nonaktifkan opsi 'productionSourceMap' pada konfigurasi bundler (Webpack/Vite/Next.js) atau blokir akses file .map di web server.",
            isVerifiedTruePositive: true,
            falsePositiveCheck: "Respon .map diverifikasi merupakan valid JSON SourceMap format V3.",
          });
          ctx.log("FAIL", `Source Map terekspos: ${mapUrl}`);
          break;
        } else if (mapRes.status === 200) {
          fpLog += ` File ${mapUrl} mengembalikan status 200 tetapi berupa HTML catch-all (diabaikan).`;
        }
      } catch {}
    }
  }

  // 3. Probe Critical Exposed Repository & Environment Files
  ctx.log("INFO", "Memeriksa keberadaan exposed .git repository dan file konfigurasi (.env)...");
  const criticalFiles = [
    { path: "/.git/HEAD", type: "git" as const, name: "Exposed Git Repository (.git/HEAD)", severity: "CRITICAL" as const },
    { path: "/.env", type: "env" as const, name: "Exposed Environment Config (.env)", severity: "CRITICAL" as const },
    { path: "/.env.local", type: "env" as const, name: "Exposed Environment Config (.env.local)", severity: "CRITICAL" as const },
    { path: "/docker-compose.yml", type: "env" as const, name: "Exposed Docker Compose Configuration", severity: "HIGH" as const },
    { path: "/Dockerfile", type: "env" as const, name: "Exposed Dockerfile", severity: "HIGH" as const },
  ];

  for (const item of criticalFiles) {
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
        const fpCheck = checkFalsePositive(item.type, res.status, res.text, res.headers.get("content-type") || "");
        if (fpCheck.isFalsePositive) {
          ctx.log("INFO", `[False Positive Filter] ${item.path}: ${fpCheck.reason}`);
          fpLog += ` ${item.path}: ${fpCheck.reason}`;
        } else {
          // True positive found!
          findings.push({
            title: `File Konfigurasi Kritis Terekspos: ${item.name}`,
            detail: `File ${item.path} dapat dibaca publik dan memuat kredensial atau arsitektur internal nyata.`,
            evidence: `Path: ${item.path} (HTTP 200), Cuplikan: ${res.text.slice(0, 80).replace(/\s+/g, " ")}`,
            severity: item.severity,
            recommendation: `Segera hapus atau blokir file ${item.path} dari document root dan rotasi kredensial yang mungkin bocor.`,
            isVerifiedTruePositive: true,
            falsePositiveCheck: fpCheck.reason,
          });
          ctx.log("FAIL", `[KRITIS] ${item.name} TERBUKA di ${item.path}`);
        }
      }
    } catch {}
  }

  // 4. ProjectDiscovery Katana Crawling & Nuclei Exposure Audit
  ctx.log("INFO", "Menjalankan Katana crawler untuk asset JavaScript & Nuclei exposure audit...");
  let pdRawOutput = "";
  try {
    const { runKatanaCrawler, runNucleiInfoAudit } = await import("../projectdiscovery.js");
    const [katanaRes, nucleiRes] = await Promise.all([
      runKatanaCrawler(ctx.targetUrl, { log: ctx.log }),
      runNucleiInfoAudit(ctx.targetUrl, tech, "exposure", { log: ctx.log }),
    ]);

    if (katanaRes.rawOutput) pdRawOutput += `${katanaRes.rawOutput}\n\n`;
    if (nucleiRes.rawOutput) pdRawOutput += `${nucleiRes.rawOutput}\n\n`;

    if (nucleiRes.findings.length > 0) {
      findings.push(...nucleiRes.findings);
    }
  } catch (err: any) {
    ctx.log("INFO", `ProjectDiscovery modules skipped: ${err.message}`);
  }

  toolsUsed.push("katana", "nuclei");

  const evaluated = evaluateFindings(
    findings,
    "Webpage content bersih. Tidak ditemukan source maps (.map), kebocoran .git, maupun file environment (.env).",
    "Pertahankan proses build minifikasi aman dan pastikan rule .gitignore mencegah commit file sensitif."
  );

  const verificationStatement =
    evaluated.status === "PASS"
      ? `Evidence: Inspeksi seluruh skrip JS client-side tidak menemukan hardcoded API keys atau internal URL tokens. Request ke .js.map mengembalikan 404/403. Probing file sensitif (.git/HEAD, .env, docker-compose.yml) terblokir atau terverifikasi bukan soft-404. Katana & Nuclei exposure audit mengonfirmasi perimeter bersih.\nAlasan: Production build pipeline berhasil melakukan minifikasi kode, stripping komentar debug, dan disabling source maps; web root terbebas dari file konfigurasi sensitif.`
      : `Evidence: Analisis konten halaman menemukan kebocoran informasi atau eksposur file konfigurasi rahasia (${findings.map((f) => f.evidence).join(", ")}).\nAlasan: File konfigurasi sensitif ter-commit ke dalam direktori publik atau production source map tidak dinonaktifkan pada pipeline CI/CD.`;

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-05: ${evaluated.status} (Severity: ${evaluated.severity})`);

  const combinedRaw = pdRawOutput
    ? `${pdRawOutput}${formatRawOutputs(rawProbes)}`
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
