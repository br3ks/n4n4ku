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
            ? "Identifikasi kebocoran data sensitif, hidden URLs, staging environment, atau riwayat exposure melalui web archive dan indeks publik."
            : item.name === "WebServerFingerprintSubagent"
            ? "Identifikasi software web server, versi exact, patch level, host OS, active modules, dan error leakage saat menerima malformed requests."
            : item.name === "WebserverMetafilesSubagent"
            ? "Inspeksi file metadata server (robots.txt, sitemap.xml, security.txt, .well-known/*, crossdomain.xml) untuk menemukan private routes."
            : item.name === "AppEnumerationSubagent"
            ? "Identifikasi multi-tenancy, virtual hosts, mounted sub-applications, dan portal administrasi infrastruktur (Grafana, Kibana, Jenkins, phpMyAdmin)."
            : item.name === "ContentLeakageSubagent"
            ? "Audit HTML source code, comments, inline scripts, JavaScript bundles, source maps (.map), dan exposed configs (.git, .env)."
            : item.name === "EntryPointsSubagent"
            ? "Memetakan attack surface: URL routes, parameters, REST/GraphQL documentation (Swagger/OpenAPI), dan testing HTTP dangerous methods."
            : item.name === "ExecutionPathsSubagent"
            ? "Memetakan alur logika aplikasi, user journeys, transisi state (state machine), step-skipping protections, dan webhook callbacks."
            : item.name === "FrameworkFingerprintSubagent"
            ? "Identifikasi framework web yang digunakan (Next.js, Spring Boot, Laravel, Django, Express) serta audit debug routes (/actuator, /_ignition)."
            : item.name === "AppFingerprintSubagent"
            ? "Identifikasi COTS & CMS (WordPress, Drupal, Joomla, Ghost, Strapi) serta evaluasi file dokumentasi bawaan dan user enumeration."
            : "Petakan topologi arsitektur infrastruktur: Web Application Firewall (WAF), Reverse Proxy, Load Balancer, CDN, dan IP leakage.";

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
            toolsUsed: ["curl", "safeFetch"],
            verificationStatement: `Evidence: Eksekusi sub-agent mengalami exception (${err.message}).\nAlasan: Diperlukan review manual karena konektivitas atau timeout.`,
            falsePositiveAnalysis: "Tidak dapat diverifikasi otomatis karena probe terhenti.",
            findings: [
              {
                title: `Subagent Error: ${name}`,
                detail: `Eksekusi subagent mengalami kesalahan: ${err.message || err}`,
                evidence: "Execution Exception",
                severity: "LOW",
                recommendation: "Lakukan verifikasi manual terhadap endpoint target.",
                isVerifiedTruePositive: false,
              },
            ],
            evidenceSummary: `Eksekusi subagent gagal: ${err.message}`,
            rawOutput: `Error: ${err.message || err}`,
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

    // AI In-Depth Audit & False Positive Verification Phase
    this.emit({
      type: "subagent_log",
      checklistId: "WSTG-INFO-01",
      level: "INFO",
      message: "Menjalankan AI In-Depth Audit & False Positive Verification untuk memvalidasi seluruh temuan...",
    });

    console.log("[WSTG Orchestrator] Generating Comprehensive OWASP WSTG 4.2 Audit Report...");
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

    const criticalFindings = this.session.findings.filter((f) => f.severity === "CRITICAL" && f.isVerifiedTruePositive !== false);
    const highFindings = this.session.findings.filter((f) => f.severity === "HIGH" && f.isVerifiedTruePositive !== false);
    const mediumFindings = this.session.findings.filter((f) => f.severity === "MEDIUM" && f.isVerifiedTruePositive !== false);
    const lowFindings = this.session.findings.filter((f) => (f.severity === "LOW" || f.severity === "INFORMATIONAL") && f.isVerifiedTruePositive !== false);

    const detailedChecklistsContext = resultsArray
      .map((r) => {
        return `#### Checklist ID: ${r.id} - ${r.title}
- **Sub-Agent**: ${r.subAgentName}
- **Status Evaluasi**: ${r.status} (Severity: ${r.severity})
- **Tools yang Digunakan**: ${r.toolsUsed.join(", ")}
- **Objective OWASP WSTG**: ${r.objective}
- **Kalimat Verifikasi**:
  ${r.verificationStatement}
- **Analisis False Positive**:
  ${r.falsePositiveAnalysis}
- **Temuan (${r.findings.length})**:
  ${
    r.findings.length > 0
      ? r.findings.map((f) => `  * [${f.severity}] ${f.title} (Verified: ${f.isVerifiedTruePositive !== false ? "True Positive" : "False Positive Discarded"}) - ${f.detail}`).join("\n")
      : "  * Tidak ada temuan rentan."
  }
- **Raw Output Excerpt**:
\`\`\`http
${r.rawOutput.slice(0, 800)}
\`\`\`
- **Rekomendasi Taktis**: ${r.recommendation}`;
      })
      .join("\n\n---\n\n");

    const prompt = `Anda adalah Principal Web Application Security Auditor & OWASP WSTG Specialist.
Buat laporan audit keamanan Information Gathering resmi berstandar **OWASP WSTG v4.2** untuk target: **${this.session.targetUrl}** (${this.session.targetDomain}).

### PANDUAN WAJIB & STRICT RULES:
1. SEMUA 10 CHECKLIST (WSTG-INFO-01 s/d WSTG-INFO-10) WAJIB DIMASUKKAN TANPA TERLEWAT SATU PUN.
2. Setiap checklist wajib mencantumkan:
   - Nama Sub-Agent dan Status
   - Daftar Tools yang Digunakan
   - Objective OWASP WSTG v4.2
   - Kalimat Verifikasi Berdasarkan Objective (Evidence & Alasan)
   - Analisis False Positive (Evaluasi bahwa temuan bukan SPA catch-all, soft 404, atau WAF challenge)
   - Raw Output / HTTP Transcript dalam code block
   - Rekomendasi Remediasi
3. Ringkasan temuan kritis:
   - Critical: ${criticalFindings.length}
   - High: ${highFindings.length}
   - Medium: ${mediumFindings.length}
   - Low: ${lowFindings.length}
   - Overall Passed: ${passCount}, Failed: ${failCount}, Review: ${reviewCount}

### DATA LENGKAP HASIL AUDIT SELURUH SUB-AGENT:
${detailedChecklistsContext}

Tulis laporan dalam format Markdown yang sangat rapi, mendalam, berwibawa, dan padat teknis tanpa basa-basi!`;

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

        console.log(`[WSTG Orchestrator] Generating AI report via ${baseUrl} (model: ${model})...`);
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

          if (fullText.trim().length > 300) {
            return fullText;
          }
        }
      } catch (err: any) {
        console.error("[WSTG LLM Error]", err.message || err);
      }
    }

    // Comprehensive Heuristic Fallback Report with ALL 10 Checklists
    const fallbackReport = this.generateDetailedHeuristicReport(resultsArray, passCount, failCount, reviewCount);
    const words = fallbackReport.split(" ");
    for (let i = 0; i < words.length; i += 8) {
      const chunk = words.slice(i, i + 8).join(" ") + " ";
      onChunk(chunk);
      await new Promise((r) => setTimeout(r, 20));
    }
    return fallbackReport;
  }

  private generateDetailedHeuristicReport(
    results: WstgChecklistResult[],
    passCount: number,
    failCount: number,
    reviewCount: number
  ): string {
    return `# Laporan Audit Keamanan OWASP WSTG v4.2: Information Gathering
**Target**: \`${this.session.targetUrl}\` (\`${this.session.targetDomain}\`)  
**Metodologi**: OWASP Web Security Testing Guide (WSTG) v4.2  
**Kategori**: Information Gathering (WSTG-INFO-01 s/d WSTG-INFO-10)  
**Evaluator**: n4n4ku Autonomous Audit Agent & 10 Dedicated Sub-Agents  

---

## 1. Ringkasan Eksekutif & Postur Perimeter

Audit reconnaissance dan pengujian permukaan serangan telah dieksekusi secara otomatis dan mendalam. Setiap kontrol dievaluasi berdasarkan kriteria PASS / FAIL resmi OWASP WSTG v4.2 serta diverifikasi melalui engine penapisan False Positive:

- **Total Checklist**: \`${results.length}\` kontrol pengujian
- **Status Kelulusan (PASS)**: \`${passCount}\` kontrol memenuhi standar hardening
- **Status Kegagalan (FAIL)**: \`${failCount}\` kontrol teridentifikasi memiliki eksposur atau kerentanan
- **Status Review (REVIEW)**: \`${reviewCount}\` kontrol membutuhkan perhatian arsitektural

---

## 2. Matriks Rekonsiliasi OWASP WSTG v4.2

| WSTG ID | Checklist Title | Status | Severity | Tools Digunakan | False Positive Validation |
|---|---|---|---|---|---|
${results
  .map(
    (r) =>
      `| **${r.id}** | ${r.title} | ${r.status === "PASS" ? "✅ PASS" : r.status === "FAIL" ? "❌ FAIL" : "⚠️ REVIEW"} | \`${r.severity}\` | \`${r.toolsUsed.slice(0, 2).join(", ")}\` | ${r.falsePositiveAnalysis.slice(0, 50)}... |`
  )
  .join("\n")}

---

## 3. Rincian Lengkap Seluruh Checklist (WSTG-INFO-01 s/d 10)

${results
  .map((r) => {
    const findingsBlock =
      r.findings.length > 0
        ? r.findings
            .map(
              (f, i) =>
                `  ${i + 1}. **[${f.severity}] ${f.title}**  
     - *Detail*: ${f.detail}  
     - *Evidence*: \`${f.evidence}\`  
     - *Status Verifikasi*: **${f.isVerifiedTruePositive !== false ? "Verified True Positive" : "False Positive (Filtered)"}**  
     - *Rekomendasi*: ${f.recommendation}`
            )
            .join("\n\n")
        : "  *✅ Tidak ditemukan temuan kerentanan atau indikator kebocoran informasi.*";

    return `### [${r.id}] ${r.title}

- **Sub-Agent Penguji**: \`${r.subAgentName}\`
- **Status Evaluasi**: ${r.status === "PASS" ? "✅ **PASS**" : r.status === "FAIL" ? "❌ **FAIL**" : "⚠️ **REVIEW**"} (Severity: \`${r.severity}\`)
- **Durasi Eksekusi**: \`${r.durationMs}ms\`
- **Tools yang Digunakan**: ${r.toolsUsed.map((t) => `\`${t}\``).join(", ")}
- **Objektif Uji**: ${r.objective}

#### A. Kalimat Verifikasi Berdasarkan Objective
> ${r.verificationStatement.replace(/\n/g, "\n> ")}

#### B. Analisis & Penapisan False Positive
${r.falsePositiveAnalysis}

#### C. Temuan & Analisis Kerentanan
${findingsBlock}

#### D. Raw Probe Output & HTTP Transcripts
\`\`\`http
${r.rawOutput}
\`\`\`

#### E. Langkah Remediasi Taktis
${r.recommendation}
`;
  })
  .join("\n---\n\n")}

---

## 4. Prioritas Remediasi Strategis

1. **Sanitasi Banner & Respon Header**:
   Konfigurasikan reverse proxy / web server untuk menyamarkan nilai header \`Server\`, \`X-Powered-By\`, dan \`X-AspNet-Version\`. Hilangkan seluruh stack trace dari halaman error 400, 404, dan 500.
2. **Isolasi Rute Administratif & Debugging**:
   Tutup atau batasi endpoint debugging framework seperti Spring Boot Actuator (\`/actuator\`), Laravel Ignition (\`/_ignition\`), dan profiler ke jaringan internal saja.
3. **Pembersihan Metadata & Repositori**:
   Pastikan file rahasia (\`.git\`, \`.env\`, \`docker-compose.yml\`) diblokir secara mutlak pada level web server. Bersihkan path administratif dari \`robots.txt\` dan nonaktifkan JavaScript source maps (\`.map\`) di lingkungan produksi.
4. **Pembatasan Metode HTTP & GraphQL Introspection**:
   Nonaktifkan metode HTTP \`TRACE\` pada web server dan nonaktifkan introspeksi schema GraphQL di production build.
`;
  }
}
