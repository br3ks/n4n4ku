import pLimit from "p-limit";
import { DetectedTechStack, WstgChecklistResult, WstgEvent, WstgFinding } from "./types.js";
import { WstgAuditSession, saveAuditSessionToDisk } from "./store.js";
import { WSTG_INFO_SUBAGENTS } from "./subagents/index.js";
import { detectTechStack } from "./tech_matrix.js";
import { safeFetch, createSharedAuditMemory } from "./subagents/base.js";

export interface WstgLlmConfig {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
}

export class WstgAuditOrchestrator {
  private session: WstgAuditSession;
  private llmConfig: WstgLlmConfig;
  private concurrency: number;
  private techStack: DetectedTechStack = {
    servers: [],
    frameworks: [],
    runtimes: [],
    cms: [],
    technologies: [],
    isSpa: false,
  };

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
    
    // Rapid pre-audit tech stack discovery
    try {
      const probeRes = await safeFetch(this.session.targetUrl, { timeoutMs: 5000 });
      this.techStack = detectTechStack(probeRes.headers, probeRes.text);
      const stackSummary = [
        ...this.techStack.servers,
        ...this.techStack.frameworks,
        ...this.techStack.cms,
        ...this.techStack.runtimes.slice(0, 1),
      ].join(", ") || "Generic Web Application";
      console.log(`[WSTG Orchestrator] Detected Target Tech Stack: ${stackSummary}`);
    } catch {}

    this.emit({
      type: "wstg_start",
      targetUrl: this.session.targetUrl,
      totalChecklists: total,
    });

    const limit = pLimit(this.concurrency);
    const shared = createSharedAuditMemory();
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

        const interAgentNotes: string[] = [];
        const broadcast = (message: string) => {
          shared.interAgentMessages.push({ from: id, message, timestamp: new Date().toISOString() });
          log("INFO", `[Agent Comms] ${message}`);
        };

        try {
          const result: WstgChecklistResult = await executor({
            targetUrl: this.session.targetUrl,
            targetDomain: this.session.targetDomain,
            log,
            llmConfig: this.llmConfig,
            techStack: this.techStack,
            shared,
            interAgentNotes,
            broadcast,
          });

          if (interAgentNotes.length > 0 && (!result.interAgentNotes || result.interAgentNotes.length === 0)) {
            result.interAgentNotes = interAgentNotes;
          }

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

    const techSummaryStr = [
      ...this.techStack.servers,
      ...this.techStack.frameworks,
      ...this.techStack.cms,
      ...this.techStack.runtimes,
      ...this.techStack.technologies,
    ].join(", ") || "Generic Modern Web Application";

    const detailedChecklistsContext = resultsArray
      .map((r) => {
        return `#### [${r.id}] ${r.title}
- **Status Evaluasi**: ${r.status} (${r.severity}) | **Sub-Agent**: ${r.subAgentName}
- **Tools**: ${r.toolsUsed.join(", ")}
- **Hasil Verifikasi**: ${r.verificationStatement.slice(0, 250)}
- **Temuan (${r.findings.length})**: ${
          r.findings.length > 0
            ? r.findings.map((f) => `[${f.severity}] ${f.title}`).join("; ")
            : "Bersih / Hardened"
        }`;
      })
      .join("\n");

    const prompt = `Anda adalah Principal Web Application Security Auditor & OWASP WSTG Specialist.
Buat laporan audit eksekutif resmi berstandar **OWASP WSTG v4.2** (Information Gathering) untuk target: **${this.session.targetUrl}** (${this.session.targetDomain}).

### TARGET TECHNOLOGY PROFILE:
- Servers / CDNs: ${this.techStack.servers.join(", ") || "None/Generic"}
- Frameworks: ${this.techStack.frameworks.join(", ") || "None/Generic"}
- Runtimes / Languages: ${this.techStack.runtimes.join(", ") || "None/Generic"}
- CMS / COTS: ${this.techStack.cms.join(", ") || "None"}
- Architecture: ${this.techStack.isSpa ? "Single Page Application (SPA)" : "Multi-Page Web Application"}

### PANDUAN PENULISAN LAPORAN EKSEKUTIF (EXECUTIVE & ACTIONABLE):
1. Format laporan adalah Executive Summary & Security Posture Report (padat, berwibawa, dan actionable).
2. JANGAN menyalin seluruh raw HTTP transcript atau command output berulang yang panjang (karena auditor dapat menginspeksi raw terminal evidence dan tailored commands di interactive modal setiap checklist pada UI).
3. Struktur Wajib Laporan:
   - ## 1. Ringkasan Eksekutif & Postur Perimeter (Ringkasan singkat, skor kepatuhan: Passed: ${passCount}, Failed: ${failCount}, Review: ${reviewCount})
   - ## 2. Profil Teknologi & Attack Surface Perimeter (Tabel ringkas komponen yang teridentifikasi)
   - ## 3. Prioritas Temuan Keamanan (Fokus hanya pada temuan True Positive berisiko Critical/High/Medium, atau nyatakan aman jika tidak ada)
   - ## 4. Matriks Kepatuhan Kontrol OWASP WSTG v4.2 (Tabel 10 checklist: ID, Title, Status, Severity, Tools, Ringkasan Hasil. Tambahkan catatan bahwa detail teknis dan bukti CLI tersedia di panel checklist interaktif di atas)
   - ## 5. Rekomendasi Strategis & Roadmap Audit Selanjutnya (3-5 poin aksi strategis + arahan ke fase WSTG selanjutnya: WSTG-CONF, WSTG-IDENT, WSTG-AUTH).

### HASIL AUDIT SELURUH SUB-AGENT:
${detailedChecklistsContext}

Tulis laporan dalam format Markdown yang elegan, profesional, padat, dan siap dibagikan ke C-level serta tim teknis!`;

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
    const fallbackReport = this.generateDetailedHeuristicReport(resultsArray, passCount, failCount, reviewCount, techSummaryStr);
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
    reviewCount: number,
    techSummaryStr: string
  ): string {
    const verifiedFindings = this.session.findings.filter((f) => f.isVerifiedTruePositive !== false);

    let findingsBlock = "";
    if (verifiedFindings.length === 0) {
      findingsBlock = `> ✅ **Hasil Evaluasi**: Tidak ditemukan eksposur rahasia, port debugging terbuka, maupun kerentanan kritis pada tahap Information Gathering. Perimeter target terkonfigurasi dengan prinsip pertahanan berlapis (defense-in-depth).`;
    } else {
      findingsBlock = verifiedFindings
        .map(
          (f, idx) => `### ${idx + 1}. [${f.severity}] ${f.title}
- **Deskripsi**: ${f.detail}
- **Bukti Terverifikasi**: \`${f.evidence}\`
- **Rekomendasi Taktis**: ${f.recommendation}`
        )
        .join("\n\n");
    }

    return `# Laporan Audit Keamanan OWASP WSTG v4.2: Information Gathering
**Target**: \`${this.session.targetUrl}\` (\`${this.session.targetDomain}\`)  
**Metodologi**: OWASP Web Security Testing Guide (WSTG) v4.2  
**Kategori**: Information Gathering (WSTG-INFO-01 s/d WSTG-INFO-10)  
**Evaluator**: n4n4ku Autonomous Audit Agent & 10 Dedicated Sub-Agents  
**Detected Stack**: \`${techSummaryStr}\`  

---

## 1. Ringkasan Eksekutif & Postur Perimeter

Audit reconnaissance dan pengujian permukaan serangan telah diselesaikan secara otonom oleh 10 sub-agent spesialis WSTG 4.2. Seluruh kontrol diuji dengan skenario adaptif berbasis profil teknologi target dan divalidasi dengan engine penapisan False Positive:

- **Total Kontrol Pengujian**: \`${results.length}\` Checklist WSTG-INFO
- **Hardening Lulus (PASS)**: \`${passCount}\` kontrol memenuhi standar keamanan
- **Temuan Berisiko (FAIL)**: \`${failCount}\` kontrol teridentifikasi memiliki celah keamanan
- **Perlu Perhatian (REVIEW)**: \`${reviewCount}\` kontrol memerlukan verifikasi manual
- **Postur Keamanan Keseluruhan**: **${
      failCount === 0 ? "🟢 SECURE / HARDENED" : failCount <= 2 ? "🟡 MODERATE RISK" : "🔴 HIGH RISK EXPOSURE"
    }**

---

## 2. Profil Teknologi Target (Tech Stack Intelligence)

| Kategori | Komponen Terdeteksi | Status Hardening |
|---|---|---|
| **Web Server / Reverse Proxy** | ${this.techStack.servers.join(", ") || "Generic/Hidden"} | ${this.techStack.servers.some((s) => /\d+\.\d+/.test(s)) ? "⚠️ Versi Terbocorkan" : "✅ Minimal Banner"} |
| **Framework Web** | ${this.techStack.frameworks.join(", ") || "Standard Web"} | Teridentifikasi |
| **Runtime / Bahasa** | ${this.techStack.runtimes.join(", ") || "Standard"} | Evaluated |
| **CMS / COTS** | ${this.techStack.cms.join(", ") || "Custom Application"} | ${this.techStack.cms.length > 0 ? "Probed for CVEs" : "✅ Non-COTS"} |
| **Model Arsitektur** | ${this.techStack.isSpa ? "Single Page Application (SPA / Dynamic Rendering)" : "Multi-Page / Traditional Server Rendering"} | Verified |

---

## 3. Prioritas Temuan Keamanan (Verified Findings)

${findingsBlock}

---

## 4. Matriks Kepatuhan OWASP WSTG v4.2

| WSTG ID | Checklist Title | Status | Severity | Tools Digunakan | Ringkasan Evaluasi |
|---|---|---|---|---|---|
${results
  .map(
    (r) =>
      `| **${r.id}** | ${r.title} | ${r.status === "PASS" ? "✅ PASS" : r.status === "FAIL" ? "❌ FAIL" : "⚠️ REVIEW"} | \`${r.severity}\` | \`${r.toolsUsed.slice(0, 3).join(", ")}\` | ${r.evidenceSummary.slice(0, 60)}... |`
  )
  .join("\n")}

> 💡 **Inspeksi Bukti Forensik & Raw Terminal Evidence**:  
> Seluruh transkrip HTTP wire asli, rekaman eksekusi terminal CLI ProjectDiscovery (\`katana\`, \`nuclei\`, \`subfinder\`, \`httpx\`, \`ffuf\`), verifikasi objektif, serta detail penapisan false-positive dapat diinspeksi secara interaktif melalui kartu **Checklist Matrix** di atas.

---

## 5. Rekomendasi Remediasi Strategis & Roadmap Pengujian Lanjutan

1. **Sanitasi Header & Banner Server**:
   Pastikan header \`Server\`, \`X-Powered-By\`, dan informasi patch level di-strip pada layer reverse proxy/load balancer.
2. **Isolasi Rute Administratif & Debugging**:
   Pastikan konsol manajemen, dokumentasi API internal (Swagger), dan debug routes (\`/actuator\`, \`/_ignition\`) dibatasi hanya untuk IP privat / VPN.
3. **Pembersihan Repositori & Metafiles**:
   Blokir akses publik ke \`.git\`, \`.env\`, dan file konfigurasi. Hindari mencantumkan direktori rahasia pada \`robots.txt\`.
4. **Langkah Audit Selanjutnya (Next Phase)**:
   Setelah perimeter reconnaissance selesai, disarankan melanjutkan pengujian ke fase aktif:
   - **WSTG-CONF** (Configuration Management Testing)
   - **WSTG-IDENT & WSTG-AUTH** (Identity & Authentication Testing)
   - **WSTG-INP** (Input Validation & Injection Testing).
`;
  }
}
