import { AssetRecord } from "./events.js";
import { ApexDnsSummary } from "../tools/dns.js";

export interface LLMConfig {
  apiKey?: string;
  baseUrl?: string;
  model?: string;
}

export async function generateSecurityReport(
  domain: string,
  dnsSummary: ApexDnsSummary,
  assets: AssetRecord[],
  config: LLMConfig,
  onChunk: (chunk: string) => void
): Promise<string> {
  const apiKey = config.apiKey || process.env.LLM_API_KEY || process.env.GEMINI_API_KEY;
  const model = config.model || process.env.LLM_MODEL || "gemini-2.5-flash";

  // Build compressed telemetry payload
  const activeAssets = assets.filter((a) => a.httpStatus || a.ip);
  const anomalies = assets.filter((a) => a.notes?.length || a.httpStatus === 404 || (a.httpStatus && a.httpStatus >= 400));
  
  const prompt = `Anda adalah Lead Attack Surface Management (ASM) & Red Team Specialist.
Buat laporan Attack Surface Intelligence yang komprehensif, terstruktur, dan profesional untuk target: **${domain}**.

### Ringkasan Telemetri Recon:
- Apex Domain: ${domain}
- Wildcard DNS: ${dnsSummary.hasWildcard ? "Terdeteksi (IP: " + dnsSummary.wildcardIps.join(", ") + ")" : "Tidak Terdeteksi"}
- Name Servers: ${dnsSummary.nsRecords.join(", ") || "N/A"}
- Mail Servers: ${dnsSummary.mxRecords.join(", ") || "N/A"}
- SPF/DMARC/TXT: ${dnsSummary.txtRecords.join(" | ") || "N/A"}
- Total Subdomain Teridentifikasi: ${assets.length}
- Host Aktif (Resolved/HTTP): ${activeAssets.length}

### Sampel Temuan & Aset Menarik:
${assets
  .filter((a) => a.httpStatus || a.cname || (a.notes && a.notes.length > 0))
  .slice(0, 40)
  .map(
    (a) =>
      `- [${a.httpStatus || "DNS"}] ${a.fqdn} -> IP: ${a.ip || "N/A"} | CNAME: ${a.cname || "None"} | Server: ${a.server || "N/A"} | Title: ${a.httpTitle || "None"} ${a.notes?.length ? "| Notes: " + a.notes.join("; ") : ""}`
  )
  .join("\n")}

### Instruksi Format Laporan:
1. **Executive Summary**: Gambaran umum postur keamanan dan eksposur perimeter target.
2. **DNS & Email Security Hygiene**: Evaluasi record NS, MX, SPF, DMARC, dan status Wildcard.
3. **Attack Surface Breakdown**:
   - Web & API Endpoints (Swagger, REST, GraphQL, dll.)
   - Administrative / Internal Interfaces (Login, Portal, Admin)
   - Cloud Infrastructure & Third-Party Dependencies (AWS S3, CloudFront, Azure, dll.)
4. **Temuan Prioritas & Potensi Kerentanan**:
   - Identifikasi risiko seperti Dangling CNAME / Subdomain Takeover, eksposur portal debug/admin, atau konfigurasi terbuka.
5. **Rekomendasi Remediasi Taktis**: 3-5 langkah mitigasi konkret bagi tim Blue Team / SysAdmin target.

Tulis dalam Markdown yang rapi, profesional, dan padat teknis (tanpa basa-basi).`;

  // 1. Try Gemini Native API if key starts with AIza... or default
  if (apiKey) {
    try {
      if (apiKey.startsWith("AIza") || !config.baseUrl) {
        const geminiEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;
        const res = await fetch(geminiEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { temperature: 0.3, maxOutputTokens: 3000 },
          }),
        });

        if (res.ok && res.body) {
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let fullText = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const textChunk = decoder.decode(value);
            const lines = textChunk.split("\n");
            for (const line of lines) {
              if (line.startsWith("data: ")) {
                try {
                  const json = JSON.parse(line.slice(6));
                  const candidateText = json.candidates?.[0]?.content?.parts?.[0]?.text;
                  if (candidateText) {
                    fullText += candidateText;
                    onChunk(candidateText);
                  }
                } catch {}
              }
            }
          }

          if (fullText.trim().length > 100) {
            return fullText;
          }
        }
      } else {
        // OpenAI-compatible endpoint (Ollama / OpenRouter / Groq / OpenAI)
        let baseUrl = (config.baseUrl || "https://api.openai.com/v1").replace(/\/$/, "");
        if (
          (process.env.RUNNING_IN_DOCKER === "true" || process.env.DOCKER_CONTAINER === "true") &&
          (baseUrl.includes("localhost") || baseUrl.includes("127.0.0.1"))
        ) {
          baseUrl = baseUrl.replace("localhost", "host.docker.internal").replace("127.0.0.1", "host.docker.internal");
        }
        let selectedModel = config.model || "wombo";
        if (selectedModel.toLowerCase().includes("wombo")) {
          selectedModel = "wombo";
        }
        console.log(`[LLM] Calling ${baseUrl}/chat/completions (model: ${selectedModel})...`);
        const res = await fetch(`${baseUrl}/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            model: selectedModel,
            messages: [{ role: "user", content: prompt }],
            stream: true,
          }),
        });

        if (res.ok && res.body) {
          const reader = res.body.getReader();
          const decoder = new TextDecoder();
          let fullText = "";

          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            const textChunk = decoder.decode(value);
            const lines = textChunk.split("\n");
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

          if (fullText.trim().length > 50) {
            console.log(`[LLM] AI response successfully generated (${fullText.length} chars).`);
            return fullText;
          }
        } else {
          const errText = await res.text().catch(() => "");
          console.error(`[LLM Error ${res.status}] Failed to call 9router:`, errText);
        }
      }
    } catch (err: any) {
      console.error(`[LLM Exception]`, err.message || err);
    }
  }

  // Built-in Deterministic Heuristic Engine Fallback (Zero external dependency required)
  const report = generateHeuristicReport(domain, dnsSummary, assets, activeAssets, anomalies);
  // Simulate streaming for smooth UI UX
  const words = report.split(" ");
  let accumulated = "";
  for (let i = 0; i < words.length; i += 8) {
    const chunk = words.slice(i, i + 8).join(" ") + " ";
    accumulated += chunk;
    onChunk(chunk);
    await new Promise((r) => setTimeout(r, 25));
  }

  return report;
}

function generateHeuristicReport(
  domain: string,
  dns: ApexDnsSummary,
  allAssets: AssetRecord[],
  activeAssets: AssetRecord[],
  anomalies: AssetRecord[]
): string {
  const hasSpf = dns.txtRecords.some((t) => t.toLowerCase().includes("v=spf1"));
  const hasDmarc = dns.txtRecords.some((t) => t.toLowerCase().includes("v=dmarc1"));

  const swaggerAssets = allAssets.filter((a) => a.httpTitle?.toLowerCase().includes("swagger") || a.notes?.some((n) => n.includes("Swagger")));
  const adminAssets = allAssets.filter((a) => a.httpTitle?.toLowerCase().match(/admin|login|dashboard|portal/));
  const cnameAssets = allAssets.filter((a) => a.cname);

  return `# Laporan Intelijen Attack Surface: ${domain}
*Digenerate oleh n4n4ku Autonomous Recon Engine*

---

## 1. Ringkasan Eksekutif
Reconnaisance perimeter terhadap domain **${domain}** telah selesai dieksekusi secara terotomatisasi. Dari penelusuran Certificate Transparency (CT) logs dan probe resolusi aktif:
- **Total Aset Subdomain Ditemukan**: \`${allAssets.length}\` host
- **Aset Aktif Terverifikasi (Live)**: \`${activeAssets.length}\` host
- **Aset dengan Anomali / Catatan Khusus**: \`${anomalies.length}\` host
- **Status DNS Wildcard**: ${dns.hasWildcard ? `⚠️ **Aktif** (Mengarahkan subdomain acak ke \`${dns.wildcardIps.join(", ")}\`)` : "✅ **Nonaktif** (Clean NXDOMAIN response)"}

---

## 2. Higienitas DNS & Konfigurasi Email
- **Name Servers**: ${dns.nsRecords.map((n) => `\`${n}\``).join(", ") || "*Tidak terdeteksi*"}
- **Mail Exchange (MX)**: ${dns.mxRecords.map((m) => `\`${m}\``).join(", ") || "*Tidak ada MX record*"}
- **Proteksi SPF (Sender Policy Framework)**: ${hasSpf ? "✅ **Dikonfigurasi**" : "⚠️ **Tidak Terdeteksi** (Risiko email spoofing)"}
- **Status DMARC**: ${hasDmarc ? "✅ **Dikonfigurasi**" : "⚠️ **Tidak Terdeteksi** (Kebijakan autentikasi email lemah)"}

---

## 3. Pemetaan Permukaan Serangan (Attack Surface)

### A. Endpoint API & Dokumentasi
${
  swaggerAssets.length > 0
    ? swaggerAssets.map((a) => `- ⚠️ **${a.fqdn}** (${a.url}): Ditemukan dokumentasi API terbuka (\`${a.httpTitle}\`).`).join("\n")
    : "- Tidak ditemukan portal dokumentasi Swagger / OpenAPI terbuka di root endpoint."
}

### B. Portal Administratif & Login
${
  adminAssets.length > 0
    ? adminAssets.map((a) => `- 🔒 **${a.fqdn}** [HTTP ${a.httpStatus}]: \`${a.httpTitle}\` (${a.server || "Server: Generic"}).`).join("\n")
    : "- Tidak ditemukan portal login atau panel administratif eksplisit pada root subdomain."
}

### C. Ketergantungan Layanan Cloud (CNAME Mapping)
${
  cnameAssets.length > 0
    ? cnameAssets
        .slice(0, 15)
        .map((a) => `- **${a.fqdn}** ➔ CNAME: \`${a.cname}\` ${a.notes?.length ? `(${a.notes.join(", ")})` : ""}`)
        .join("\n")
    : "- Tidak terdeteksi delegasi CNAME eksternal yang signifikan."
}

---

## 4. Analisis Risiko & Temuan Kritis
1. **Risiko Subdomain Takeover**:
   ${
     cnameAssets.some((a) => a.notes?.some((n) => n.includes("Dangling") || n.includes("AWS S3") || n.includes("GitHub Pages")))
       ? "Ditemukan CNAME yang mengarah ke penyedia cloud pihak ketiga (S3/CloudFront/Pages). Verifikasi bahwa bucket atau entitas target masih dimiliki secara sah untuk mencegah klaim sepihak."
       : "Tidak terdeteksi dangling DNS pointer yang mengarah ke resource cloud tak terdaftar."
   }
2. **Eksposur Server Header**:
   Beberapa host mengembalikan header server terperinci (${Array.from(new Set(activeAssets.map((a) => a.server).filter(Boolean))).slice(0, 4).join(", ") || "None"}). Rekomendasikan penyamaran banner server untuk menyulitkan profiling otomatis.

---

## 5. Rekomendasi Remediasi
1. **Pembersihan DNS Usang**: Hapus DNS record subdomain dev/staging yang sudah tidak beroperasi untuk mencegah takeover.
2. **Perketat Kebijakan Email**: Terapkan DMARC dengan kebijakan minimal \`p=quarantine\` atau \`p=reject\` bila belum aktif.
3. **Isolasi Interface Internal**: Batasi akses ke portal login, monitoring, dan API swagger menggunakan IP Whitelisting atau VPN/Zero-Trust Access.
`;
}
