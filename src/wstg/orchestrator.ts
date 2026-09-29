import pLimit from "p-limit";
import { WstgChecklistResult, WstgEvent, WstgFinding } from "./types.js";
import { WstgAuditSession, saveAuditSessionToDisk } from "./store.js";
import { WSTG_INFO_SUBAGENTS } from "./subagents/index.js";

export interface WstgLlmConfig {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
}

export class WstgAuditOrchestrator {
  private session: WstgAuditSession;
  private llmConfig: WstgLlmConfig;
  private concurrency: number;

  constructor(session: WstgAuditSession, llmConfig: WstgLlmConfig, concurrency = 2) {
    this.session = session;
    this.llmConfig = llmConfig;
    this.concurrency = concurrency;
  }

  private emit(event: WstgEvent) {
    this.session.eventBus.emit("wstg_event", event);
  }

  public async start(): Promise<void> {
    const startTime = Date.now();
    const total = WSTG_INFO_SUBAGENTS.length;

    console.log(`\n[WSTG Orchestrator] Starting WSTG 4.2 Information Gathering Audit for: ${this.session.targetUrl}`);
    this.emit({
      type: "wstg_start",
      targetUrl: this.session.targetUrl,
      totalChecklists: total,
    });

    const limit = pLimit(this.concurrency);
    let completedCount = 0;
    let passCount = 0;
    let failCount = 0;
    let reviewCount = 0;

    const tasks = WSTG_INFO_SUBAGENTS.map((item) =>
      limit(async () => {
        const { id, name, executor } = item;

        // Subagent log callback
        const log = (level: "INFO" | "WARN" | "PASS" | "FAIL", message: string) => {
          this.emit({
            type: "subagent_log",
            checklistId: id,
            level,
            message,
          });
        };

        const objective =
          item.name === "SearchEngineReconSubagent"
            ? "Identifikasi kebocoran arsip dan indeks pencarian publik"
            : item.name === "WebServerFingerprintSubagent"
            ? "Identifikasi software web server dan sanitasi server banner"
            : item.name === "WebserverMetafilesSubagent"
            ? "Inspeksi robots.txt, sitemap.xml, security.txt, dan mobile deep-links"
            : item.name === "AppEnumerationSubagent"
            ? "Enumerasi sub-aplikasi, console manajemen, dan isolasi vhost"
            : item.name === "ContentLeakageSubagent"
            ? "Audit HTML comments, JS source maps (.map), dan file rahasia (.env, .git)"
            : item.name === "EntryPointsSubagent"
            ? "Pemetaan rute API, GraphQL introspection, dan metode HTTP berisiko"
            : item.name === "ExecutionPathsSubagent"
            ? "Pemetaan alur eksekusi, step-skipping, dan callback webhooks"
            : item.name === "FrameworkFingerprintSubagent"
            ? "Fingerprint framework backend dan proteksi debug routes"
            : item.name === "AppFingerprintSubagent"
            ? "Fingerprint CMS/COTS dan sanitasi file instalasi bawaan"
            : "Pemetaan arsitektur perimeter, WAF, CDN, dan pencegahan leak IP internal";

        this.emit({
          type: "subagent_start",
          checklistId: id,
          subAgent: name,
          objective,
        });

        try {
          const result: WstgChecklistResult = await executor({
            targetUrl: this.session.targetUrl,
            targetDomain: this.session.targetDomain,
            log,
            llmConfig: this.llmConfig,
          });

          this.session.results[id] = result;
          if (result.findings && result.findings.length > 0) {
            this.session.findings.push(...result.findings);
          }

          if (result.status === "PASS") passCount++;
          else if (result.status === "FAIL") failCount++;
          else if (result.status === "REVIEW") reviewCount++;

          this.emit({
            type: "subagent_complete",
            result,
          });
        } catch (err: any) {
          log("FAIL", `Subagent execution error: ${err.message || err}`);
          const fallbackResult: WstgChecklistResult = {
            id,
            title: `Audit ${id}`,
            subAgentName: name,
            objective,
            status: "REVIEW",
            severity: "LOW",
            findings: [
              {
                title: `Subagent Error: ${name}`,
                detail: `Eksekusi subagent mengalami kesalahan: ${err.message || err}`,
                evidence: "Execution Exception",
                severity: "LOW",
                recommendation: "Lakukan verifikasi manual terhadap endpoint target.",
              },
            ],
            evidenceSummary: `Eksekusi subagent gagal: ${err.message}`,
            recommendation: "Verifikasi manual diperlukan.",
            durationMs: 0,
          };
          this.session.results[id] = fallbackResult;
          reviewCount++;
          this.emit({
            type: "subagent_complete",
            result: fallbackResult,
          });
        } finally {
          completedCount++;
          this.emit({
            type: "wstg_metrics",
            completed: completedCount,
            total,
            passCount,
            failCount,
            reviewCount,
          });
        }
      })
    );

    // Wait for all subagents to finish
    await Promise.all(tasks);

    // Generate comprehensive WSTG 4.2 Security Report
    console.log("[WSTG Orchestrator] Generating Executive WSTG 4.2 Audit Report...");
    const report = await this.generateReport((chunk) => {
      this.emit({ type: "wstg_report_chunk", delta: chunk });
    });

    this.session.report = report;
    this.session.status = "COMPLETED";
    this.session.completedAt = new Date().toISOString();

    this.emit({ type: "wstg_report_ready", report });
    this.emit({
      type: "wstg_done",
      summary: {
        total,
        passed: passCount,
        failed: failCount,
        durationMs: Date.now() - startTime,
      },
    });

    saveAuditSessionToDisk(this.session);
    console.log(`[WSTG Orchestrator] Audit completed in ${((Date.now() - startTime) / 1000).toFixed(1)}s.`);
  }

  private async generateReport(onChunk: (chunk: string) => void): Promise<string> {
    const resultsArray = Object.values(this.session.results);
    const passCount = resultsArray.filter((r) => r.status === "PASS").length;
    const failCount = resultsArray.filter((r) => r.status === "FAIL").length;
    const reviewCount = resultsArray.filter((r) => r.status === "REVIEW").length;

    const criticalFindings = this.session.findings.filter((f) => f.severity === "CRITICAL");
    const highFindings = this.session.findings.filter((f) => f.severity === "HIGH");
    const mediumFindings = this.session.findings.filter((f) => f.severity === "MEDIUM");
    const lowFindings = this.session.findings.filter((f) => f.severity === "LOW" || f.severity === "INFORMATIONAL");

    const prompt = `Anda adalah Principal Web Application Security Auditor & OWASP WSTG Specialist.
Buat laporan audit keamanan Information Gathering resmi (OWASP WSTG v4.2) untuk target: **${this.session.targetUrl}** (${this.session.targetDomain}).

### Ringkasan Hasil Uji Sub-Agent:
- Total Checklist Dievaluasi: ${resultsArray.length} (WSTG-INFO-01 s/d WSTG-INFO-10)
- Status: ${passCount} PASS, ${failCount} FAIL, ${reviewCount} REVIEW
- Temuan Kritis (Critical): ${criticalFindings.length}
- Temuan Tinggi (High): ${highFindings.length}
- Temuan Sedang (Medium): ${mediumFindings.length}
- Temuan Rendah (Low/Info): ${lowFindings.length}

### Matriks Temuan per Checklist:
${resultsArray
  .map(
    (r) =>
      `- **[${r.id}] ${r.title}**: Status = ${r.status} (${r.severity})\n  Evidence: ${r.evidenceSummary}\n  Rekomendasi: ${r.recommendation}`
  )
  .join("\n\n")}

### Format Laporan yang Diinginkan:
1. **Executive Summary**: Postur keamanan perimeter target berdasarkan metodologi OWASP WSTG v4.2.
2. **Key Metrics & Compliance Table**: Tabel ringkas status 10 checklist WSTG-INFO.
3. **Critical & High Risk Exposures**: Rincian setiap temuan gagal atau anomali berisiko beserta dampak bisnisnya.
4. **Information Leakage & Hardening Analysis**: Evaluasi konfigurasi header, metadata, dan source code.
5. **Prioritized Strategic Recommendations**: Langkah remediasi taktis yang terurut dari prioritas tertinggi.

Tulis dalam format Markdown yang rapi, profesional, dan padat teknis tanpa basa-basi.`;

    // Try AI call if LLM is configured
    const apiKey = this.llmConfig.apiKey || process.env.LLM_API_KEY || process.env.GEMINI_API_KEY;
    if (apiKey) {
      try {
        let baseUrl = (this.llmConfig.baseUrl || process.env.LLM_BASE_URL || "http://localhost:20128/v1").replace(/\/$/, "");
        if (
          (process.env.RUNNING_IN_DOCKER === "true" || process.env.DOCKER_CONTAINER === "true") &&
          (baseUrl.includes("localhost") || baseUrl.includes("127.0.0.1"))
        ) {
          baseUrl = baseUrl.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal");
        }

        let model = this.llmConfig.model || process.env.LLM_MODEL || "wombo";
        if (model.toLowerCase().includes("wombo")) model = "wombo";

        const res = await fetch(`${baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            model,
            messages: [{ role: "user", content: prompt }],
            stream: true,
            temperature: 0.2,
          }),
        });

        if (res.ok && res.body) {
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let fullText = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const chunk = decoder.decode(value);
            const lines = chunk.split("\n");
            for (const line of lines) {
              if (line.startsWith("data: ") && !line.includes("[DONE]")) {
                try {
                  const json = JSON.parse(line.slice(6));
                  const delta = json.choices?.[0]?.delta?.content;
                  if (delta) {
                    fullText += delta;
                    onChunk(delta);
                  }
                } catch {}
              }
            }
          }

          if (fullText.trim().length > 100) {
            return fullText;
          }
        }
      } catch (err: any) {
        console.error("[WSTG LLM Error]", err.message || err);
      }
    }

    // Heuristic Fallback Report
    const fallbackReport = this.generateHeuristicWstgReport(resultsArray, passCount, failCount, reviewCount);
    // Simulate streaming for smooth UI UX
    const words = fallbackReport.split(" ");
    for (let i = 0; i < words.length; i += 8) {
      const chunk = words.slice(i, i + 8).join(" ") + " ";
      onChunk(chunk);
      await new Promise((r) => setTimeout(r, 20));
    }
    return fallbackReport;
  }

  private generateHeuristicWstgReport(
    results: WstgChecklistResult[],
    passCount: number,
    failCount: number,
    reviewCount: number
  ): string {
    return `# Laporan Audit Keamanan OWASP WSTG v4.2: Information Gathering
Target: **${this.session.targetUrl}** (${this.session.targetDomain})  
*Digenerate secara otonom oleh n4n4ku WSTG Audit Agent*

---

## 1. Executive Summary
Audit keamanan web perimeter berbasis standar **OWASP Web Security Testing Guide (WSTG) v4.2** kategori **Information Gathering** (WSTG-INFO-01 hingga WSTG-INFO-10) telah selesai dilaksanakan. 

Dari total 10 checklist uji coba sub-agent:
- ✅ **Passed**: \`${passCount}\` kontrol keamanan memenuhi standar hardening.
- ❌ **Failed**: \`${failCount}\` kontrol keamanan gagal dan membutuhkan remediasi.
- ⚠️ **Review**: \`${reviewCount}\` kontrol keamanan memerlukan evaluasi arsitektural lanjutan.

---

## 2. Matriks Verifikasi Checklist OWASP WSTG v4.2

| WSTG ID | Checklist Title | Status | Severity | Evidence Summary |
|---|---|---|---|---|
${results
  .map(
    (r) =>
      `| **${r.id}** | ${r.title} | ${r.status === "PASS" ? "✅ PASS" : r.status === "FAIL" ? "❌ FAIL" : "⚠️ REVIEW"} | \`${r.severity}\` | ${r.evidenceSummary.slice(0, 80)}... |`
  )
  .join("\n")}

---

## 3. Rincian Temuan & Bukti Audit

${results
  .map((r) => {
    return `### [${r.id}] ${r.title}
- **Sub-Agent**: \`${r.subAgentName}\`
- **Objective**: ${r.objective}
- **Status Evaluasi**: ${r.status === "PASS" ? "✅ **PASS**" : r.status === "FAIL" ? "❌ **FAIL**" : "⚠️ **REVIEW**"} (Severity: \`${r.severity}\`)
- **Durasi Eksekusi**: \`${r.durationMs}ms\`
- **Evidence / Catatan**: ${r.evidenceSummary}
- **Rekomendasi Remediasi**: ${r.recommendation}
`;
  })
  .join("\n---\n\n")}

---

## 4. Rekomendasi Remediasi Taktis & Hardening
1. **Banner & Header Sanitization**: Sembunyikan atau ganti header respon server (\`Server\`, \`X-Powered-By\`, \`X-AspNet-Version\`) menjadi nilai generik di layer reverse proxy atau CDN.
2. **Metafiles & Robots Policy**: Hindari mencantumkan direktori administratif sensitif di dalam file publik \`robots.txt\`. Terapkan file \`.well-known/security.txt\` sesuai RFC 9116.
3. **Pembersihan Artefak Build & Source Maps**: Nonaktifkan pembuatan source map (\`.map\`) di lingkungan produksi dan pastikan direktori \`.git\` serta file \`.env\` terblokir total dari akses web root.
4. **Pembatasan Metode HTTP & Dokumentasi**: Nonaktifkan metode HTTP \`TRACE\` untuk mencegah XST dan lindungi endpoint dokumentasi Swagger/OpenAPI serta GraphQL introspection dengan autentikasi gateway.
`;
  }
}
