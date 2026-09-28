import { EventEmitter } from "node:events";
import { AgentEvent, AssetRecord, AgentPhase } from "./events.js";
import { isValidDomain, normalizeDomain } from "../core/scope.js";
import { resolveApexDns, resolveHost, ApexDnsSummary } from "../tools/dns.js";
import { queryCrtSh } from "../tools/ct.js";
import { probeHost } from "../tools/http.js";
import { runParallelWithProgress } from "../tools/runner.js";
import { callLlmReActStep, ReActLlmResponse } from "./llm_react.js";
import { generateSecurityReport, LLMConfig } from "./llm.js";

export interface ScanSession {
  id: string;
  targetDomain: string;
  status: "RUNNING" | "COMPLETED" | "FAILED";
  startedAt: string;
  completedAt?: string;
  assets: AssetRecord[];
  dnsSummary?: ApexDnsSummary;
  report?: string;
  eventBus: EventEmitter;
}

export class ReconOrchestrator {
  private session: ScanSession;
  private llmConfig: LLMConfig;
  private dnsConcurrency: number;
  private httpConcurrency: number;

  constructor(
    session: ScanSession,
    llmConfig: LLMConfig = {},
    dnsConcurrency = 25,
    httpConcurrency = 15
  ) {
    this.session = session;
    this.llmConfig = llmConfig;
    this.dnsConcurrency = dnsConcurrency;
    this.httpConcurrency = httpConcurrency;
  }

  private emit(event: AgentEvent) {
    this.session.eventBus.emit("event", event);
  }

  private thought(content: string) {
    this.emit({
      type: "thought",
      content,
      timestamp: new Date().toLocaleTimeString(),
    });
  }

  public async start(): Promise<void> {
    const rawTarget = this.session.targetDomain;
    const domain = normalizeDomain(rawTarget);
    const startTime = Date.now();

    try {
      this.emit({ phase: "SCOPE_VALIDATION", type: "phase", message: "Memvalidasi scope & menginisialisasi AI Agent..." });
      this.thought(`Memulai inisialisasi AI Recon Agent (n4n4ku) untuk target: [${domain}].`);

      if (!isValidDomain(domain)) {
        throw new Error(`Domain '${rawTarget}' tidak valid.`);
      }

      this.thought(`Scope disetujui: [*.${domain}]. Mengalihkan kendali eksekusi ke model AI (Autonomous ReAct Loop)...`);

      const assetsMap = new Map<string, AssetRecord>();
      let wildcardSet = new Set<string>();

      // Initial ReAct conversation messages
      const messages: any[] = [
        {
          role: "system",
          content: `Anda adalah n4n4ku, AI Agent spesialis Attack Surface Management (ASM) & Red Team Reconnaissance otonom.
Target yang sedang Anda audit: ${domain}.
Scope: *.${domain} dan ${domain}.

Anda memiliki wewenang penuh untuk merencanakan dan mengeksekusi recon secara bertahap menggunakan function calls yang tersedia:
1. 'get_apex_dns': Audit DNS apex (NS, MX, SPF, DMARC, SOA) & deteksi Wildcard DNS.
2. 'discover_subdomains_ct': Panen daftar subdomain historis dan aktif via Certificate Transparency (crt.sh).
3. 'resolve_subdomain_batch': Resolving DNS massal untuk menemukan IP aktif & deteksi CNAME pihak ketiga.
4. 'probe_http_batch': Probe HTTP/HTTPS untuk mengekstrak status, banner server, tech stack, dan anomali.
5. 'inspect_takeover_risk': Cek mendalam jika ada CNAME mencurigakan (S3, CloudFront, Azure, GitHub).

Aturan Kerja:
- Berikan penalaran singkat (thought) mengapa Anda memilih tool tertentu sebelum memanggilnya.
- Lakukan recon langkah demi langkah secara logis.
- Setelah data dirasa cukup, susun Laporan Akhir Attack Surface Management lengkap dalam Markdown (tanpa memanggil tool lagi).`
        },
        {
          role: "user",
          content: `Mulai recon otonom sekarang untuk domain: ${domain}. Jalankan langkah pertama Anda.`
        }
      ];

      const maxSteps = 8;
      let step = 0;
      let finalReport = "";

      while (step < maxSteps) {
        step++;
        this.emit({
          phase: "AI_ANALYSIS",
          type: "phase",
          message: `AI Agent Berpikir (Langkah ${step}/${maxSteps})...`
        });

        let stepResponse: ReActLlmResponse | undefined;
        try {
          stepResponse = await callLlmReActStep(
            messages,
            this.llmConfig,
            (chunk) => {
              if (step >= 4) {
                this.emit({ type: "report_chunk", delta: chunk });
              }
            }
          );
        } catch (err: any) {
          this.thought(`Koneksi function-calling gagal (${err.message}). Beralih ke fallback pipeline.`);
          break;
        }

        // Tampilkan monolog pemikiran AI ke terminal web
        if (stepResponse.content && stepResponse.content.trim()) {
          this.thought(stepResponse.content.trim());
        }

        // Jika AI tidak memanggil tool lagi, berarti AI telah menghasilkan Laporan Final!
        if (!stepResponse.toolCalls || stepResponse.toolCalls.length === 0) {
          if (stepResponse.content && stepResponse.content.length > 200) {
            finalReport = stepResponse.content;
            this.thought("AI Agent telah menyelesaikan seluruh investigasi dan menyusun laporan final.");
            break;
          } else {
            messages.push({
              role: "assistant",
              content: stepResponse.content || ""
            });
            messages.push({
              role: "user",
              content: "Lanjutkan investigasi atau panggil tool berikutnya."
            });
            continue;
          }
        }

        // AI meminta pemanggilan satu atau beberapa tools
        const assistantToolMsg: any = {
          role: "assistant",
          content: stepResponse.content || null,
          tool_calls: stepResponse.toolCalls.map((tc) => ({
            id: tc.id,
            type: "function",
            function: {
              name: tc.name,
              arguments: JSON.stringify(tc.arguments)
            }
          }))
        };
        messages.push(assistantToolMsg);

        // Eksekusi tiap tool yang dipanggil AI
        for (const tc of stepResponse.toolCalls) {
          const toolName = tc.name;
          const args = tc.arguments || {};
          let toolResult: any = {};

          this.thought(`AI memutuskan mengeksekusi tool [${toolName}] dengan argumen: ${JSON.stringify(args)}`);

          if (toolName === "get_apex_dns") {
            this.emit({ phase: "PASSIVE_RECON", type: "phase", message: "AI mengeksekusi Apex DNS & Wildcard Audit..." });
            const dns = await resolveApexDns(args.domain || domain);
            this.session.dnsSummary = dns;
            wildcardSet = new Set(dns.wildcardIps);

            toolResult = {
              hasWildcard: dns.hasWildcard,
              wildcardIps: dns.wildcardIps,
              nsRecords: dns.nsRecords,
              mxRecords: dns.mxRecords,
              txtRecords: dns.txtRecords,
              aRecords: dns.aRecords
            };

            if (dns.hasWildcard) {
              this.emit({
                type: "highlight",
                level: "WARN",
                title: "Wildcard DNS Aktif",
                message: `Wildcard IP terdeteksi: ${dns.wildcardIps.join(", ")}`
              });
            }
          } else if (toolName === "discover_subdomains_ct") {
            this.emit({ phase: "PASSIVE_RECON", type: "phase", message: "AI memanen CT Logs (crt.sh)..." });
            const subs = await queryCrtSh(args.domain || domain);
            for (const s of subs) {
              if (!assetsMap.has(s)) assetsMap.set(s, { fqdn: s });
            }
            toolResult = {
              totalFound: subs.length,
              sample: subs.slice(0, 30)
            };
            this.emit({
              type: "metrics",
              subdomainsTotal: assetsMap.size,
              hostsAlive: Array.from(assetsMap.values()).filter((a) => a.ip).length,
              httpAlive: Array.from(assetsMap.values()).filter((a) => a.httpStatus).length,
              anomalies: Array.from(assetsMap.values()).filter((a) => a.notes?.length).length
            });
          } else if (toolName === "resolve_subdomain_batch") {
            this.emit({ phase: "DNS_VERIFICATION", type: "phase", message: "AI menjalankan Resolving DNS massal..." });
            const toResolve: string[] = args.subdomains || Array.from(assetsMap.keys()).slice(0, 50);

            const resolved = await runParallelWithProgress({
              items: toResolve,
              concurrency: this.dnsConcurrency,
              workerFn: async (fqdn) => resolveHost(fqdn, wildcardSet),
              onStart: (total, conc) => {
                this.emit({ type: "tool_start", tool: "AI DNS Resolver", targetCount: total, concurrency: conc });
              },
              onProgress: (comp, tot, item, res) => {
                this.emit({ type: "tool_progress", tool: "AI DNS Resolver", completed: comp, total: tot, current: item });
                if (res && (res.ip || res.cname)) {
                  const asset: AssetRecord = {
                    fqdn: res.fqdn,
                    ip: res.ip,
                    cname: res.cname,
                    isWildcard: res.isWildcard,
                    notes: res.notes
                  };
                  assetsMap.set(res.fqdn, asset);
                  this.emit({ type: "asset_found", asset });
                }
              }
            });

            const alive = resolved.filter((r) => r.ip && !r.isWildcard);
            toolResult = {
              totalResolved: resolved.length,
              aliveCount: alive.length,
              cnamePointers: resolved.filter((r) => r.cname).map((r) => ({ fqdn: r.fqdn, cname: r.cname, notes: r.notes }))
            };

            this.emit({
              type: "metrics",
              subdomainsTotal: assetsMap.size,
              hostsAlive: Array.from(assetsMap.values()).filter((a) => a.ip).length,
              httpAlive: Array.from(assetsMap.values()).filter((a) => a.httpStatus).length,
              anomalies: Array.from(assetsMap.values()).filter((a) => a.notes?.length).length
            });
          } else if (toolName === "probe_http_batch") {
            this.emit({ phase: "HTTP_PROBING", type: "phase", message: "AI menjalankan HTTP & Tech Stack Probing..." });
            const toProbe: string[] = args.hosts || Array.from(assetsMap.values()).filter((a) => a.ip).map((a) => a.fqdn).slice(0, 30);

            const probed = await runParallelWithProgress({
              items: toProbe,
              concurrency: this.httpConcurrency,
              workerFn: async (fqdn) => probeHost(fqdn),
              onStart: (total, conc) => {
                this.emit({ type: "tool_start", tool: "AI HTTP Prober", targetCount: total, concurrency: conc });
              },
              onProgress: (comp, tot, item, res) => {
                this.emit({ type: "tool_progress", tool: "AI HTTP Prober", completed: comp, total: tot, current: item });
                if (res) {
                  const existing = assetsMap.get(res.fqdn) || { fqdn: res.fqdn };
                  existing.httpStatus = res.status;
                  existing.httpTitle = res.title;
                  existing.server = res.server;
                  existing.techs = res.techs;
                  existing.url = res.url;
                  if (res.anomalies.length > 0) {
                    existing.notes = [...(existing.notes || []), ...res.anomalies];
                    this.emit({
                      type: "highlight",
                      level: "WARN",
                      title: "Anomali Web Teridentifikasi",
                      message: `${res.fqdn} [${res.status}]: ${res.anomalies.join(", ")}`
                    });
                  }
                  assetsMap.set(res.fqdn, existing);
                  this.emit({ type: "asset_found", asset: existing });
                }
              }
            });

            toolResult = {
              probedCount: probed.length,
              liveHttpCount: probed.filter((p) => p.status).length,
              anomalies: probed.filter((p) => p.anomalies.length > 0).map((p) => ({ fqdn: p.fqdn, anomalies: p.anomalies }))
            };

            this.emit({
              type: "metrics",
              subdomainsTotal: assetsMap.size,
              hostsAlive: Array.from(assetsMap.values()).filter((a) => a.ip).length,
              httpAlive: Array.from(assetsMap.values()).filter((a) => a.httpStatus).length,
              anomalies: Array.from(assetsMap.values()).filter((a) => a.notes?.length).length
            });
          } else if (toolName === "inspect_takeover_risk") {
            const probe = await probeHost(args.fqdn);
            toolResult = {
              fqdn: args.fqdn,
              cname: args.cname,
              httpStatus: probe?.status,
              bodySample: probe?.title || "No title",
              isDangling: probe?.status === 404
            };
            if (probe?.status === 404) {
              this.emit({
                type: "highlight",
                level: "CRITICAL",
                title: "Potensi Subdomain Takeover Dikonfirmasi",
                message: `${args.fqdn} mengarah ke ${args.cname} dan mengembalikan HTTP 404!`
              });
            }
          }

          // Kirim observasi kembali ke conversation history AI
          messages.push({
            role: "tool",
            tool_call_id: tc.id,
            content: JSON.stringify(toolResult)
          });
        }
      }

      this.session.assets = Array.from(assetsMap.values());

      // Jika loop selesai dan belum ada report, minta AI menyusun laporan akhir
      if (!finalReport) {
        this.emit({ phase: "AI_ANALYSIS", type: "phase", message: "AI Agent sedang menyusun Laporan Akhir Attack Surface..." });
        this.thought("Menyusun Laporan Akhir Attack Surface Intelligence Report berdasarkan temuan ReAct...");

        finalReport = await generateSecurityReport(
          domain,
          this.session.dnsSummary || { aRecords: [], nsRecords: [], mxRecords: [], txtRecords: [], hasWildcard: false, wildcardIps: [] },
          this.session.assets,
          this.llmConfig,
          (chunk) => {
            this.emit({ type: "report_chunk", delta: chunk });
          }
        );
      }

      this.session.report = finalReport;
      this.emit({ type: "report_ready", fullReport: finalReport });

      const durationMs = Date.now() - startTime;
      this.session.status = "COMPLETED";
      this.session.completedAt = new Date().toISOString();

      this.emit({ phase: "COMPLETED", type: "phase", message: "Recon selesai." });
      this.thought(`Siklus otonom ReAct n4n4ku selesai dalam ${(durationMs / 1000).toFixed(1)} detik.`);
      this.emit({
        type: "done",
        summary: {
          totalFound: assetsMap.size,
          totalAlive: Array.from(assetsMap.values()).filter((a) => a.ip).length,
          durationMs
        }
      });
    } catch (err: any) {
      this.session.status = "FAILED";
      this.emit({ phase: "FAILED", type: "phase", message: err.message || "Eksekusi gagal." });
      this.emit({ type: "error", message: err.message || "Unknown error occurred" });
      this.thought(`Terjadi kesalahan kritis: ${err.message}`);
    }
  }
}
