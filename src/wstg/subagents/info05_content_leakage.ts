import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info05ContentLeakage(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-05";
  const title = "Review Webpage Content for Information Leakage";
  const subAgentName = "ContentLeakageSubagent";
  const objective = "Audit HTML source code, developer comments, inline scripts, JavaScript bundles, source maps (.map), dan exposed configs (.git, .env).";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai audit kebocoran konten pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Audit Root HTML comments & inline secrets
  ctx.log("INFO", "Mengambil HTML homepage dan memeriksa komentar developer...");
  const htmlRes = await safeFetch(ctx.targetUrl);
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
      });
      ctx.log("WARN", `Ditemukan ${sensitiveComments.length} komentar berisiko di HTML.`);
    }

    // 2. Extract Script URLs and check for Source Maps (.map)
    const scriptSrcMatches = Array.from(htmlRes.text.matchAll(/<script[^>]+src=["']([^"']+)["']/gi));
    const jsUrls = scriptSrcMatches
      .map((m) => m[1])
      .filter((s) => s.endsWith(".js") || s.includes(".js?"))
      .slice(0, 5); // Check first 5 scripts

    ctx.log("INFO", `Memeriksa ${jsUrls.length} file JavaScript untuk source map (.map)...`);
    for (const src of jsUrls) {
      const fullJsUrl = src.startsWith("http") ? src : `${baseUrl}/${src.replace(/^\//, "")}`;
      const mapUrl = `${fullJsUrl.split("?")[0]}.map`;
      try {
        const mapRes = await safeFetch(mapUrl, { timeoutMs: 5000 });
        if (mapRes.status === 200 && (mapRes.text.includes('"sources"') || mapRes.text.includes('"version"'))) {
          findings.push({
            title: "JavaScript Source Map (.map) Terbuka ke Publik",
            detail: `File source map (${mapUrl}) dapat diakses publik. Penyerang dapat merekonstruksi source code TypeScript/React asli secara penuh.`,
            evidence: `Source Map: ${mapUrl}`,
            severity: "MEDIUM",
            recommendation: "Nonaktifkan opsi 'productionSourceMap' pada konfigurasi bundler (Webpack/Vite/Next.js) atau blokir akses file .map di web server.",
          });
          ctx.log("FAIL", `Source Map terekspos: ${mapUrl}`);
          break;
        }
      } catch {}
    }
  }

  // 3. Probe Critical Exposed Repository & Environment Files
  ctx.log("INFO", "Memeriksa keberadaan exposed .git repository dan file konfigurasi (.env)...");
  const criticalFiles = [
    { path: "/.git/HEAD", pattern: /ref: refs\//, name: "Exposed Git Repository (.git/HEAD)", severity: "CRITICAL" as const },
    { path: "/.env", pattern: /DB_|API_|SECRET|KEY=|PASSWORD=/i, name: "Exposed Environment Config (.env)", severity: "CRITICAL" as const },
    { path: "/.env.local", pattern: /DB_|API_|SECRET|KEY=|PASSWORD=/i, name: "Exposed Environment Config (.env.local)", severity: "CRITICAL" as const },
    { path: "/docker-compose.yml", pattern: /version:|services:/i, name: "Exposed Docker Compose Configuration", severity: "HIGH" as const },
    { path: "/Dockerfile", pattern: /FROM\s+/i, name: "Exposed Dockerfile", severity: "HIGH" as const },
    { path: "/wp-config.php.bak", pattern: /DB_PASSWORD|DB_USER/i, name: "Exposed WordPress Config Backup", severity: "CRITICAL" as const },
  ];

  for (const item of criticalFiles) {
    try {
      const res = await safeFetch(`${baseUrl}${item.path}`, { timeoutMs: 4000 });
      if (res.status === 200 && item.pattern.test(res.text)) {
        findings.push({
          title: `File Konfigurasi Kritis Terekspos: ${item.name}`,
          detail: `File ${item.path} dapat dibaca publik tanpa proteksi dan memuat kredensial atau arsitektur internal.`,
          evidence: `Path: ${item.path} (HTTP 200), Cuplikan: ${res.text.slice(0, 80).replace(/\s+/g, " ")}`,
          severity: item.severity,
          recommendation: `Segera hapus atau blokir file ${item.path} dari document root dan rotasi kredensial yang mungkin bocor.`,
        });
        ctx.log("FAIL", `[KRITIS] ${item.name} TERBUKA di ${item.path}`);
      }
    } catch {}
  }

  const evaluated = evaluateFindings(
    findings,
    "Webpage content bersih. Tidak ditemukan source maps (.map), kebocoran .git, maupun file environment (.env).",
    "Pertahankan proses build minifikasi aman dan pastikan rule .gitignore mencegah commit file sensitif."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-05: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
