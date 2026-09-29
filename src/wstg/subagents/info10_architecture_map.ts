import { WstgChecklistResult, WstgFinding } from "../types.js";
import { SubagentContext, evaluateFindings, safeFetch } from "./base.js";

export async function info10MapArchitecture(ctx: SubagentContext): Promise<WstgChecklistResult> {
  const start = Date.now();
  const id = "WSTG-INFO-10";
  const title = "Map Application Architecture";
  const subAgentName = "ArchitectureMapSubagent";
  const objective = "Petakan topologi arsitektur infrastruktur: Web Application Firewall (WAF), Reverse Proxy, Load Balancer, API Gateway, CDN, dan internal IP/topology leakage.";

  const baseUrl = ctx.targetUrl.replace(/\/$/, "");
  ctx.log("INFO", `Memulai pemetaan arsitektur perimeter dan WAF/CDN pada: ${baseUrl}`);

  const findings: WstgFinding[] = [];

  // 1. Inspect Edge & Cloud Headers on Root
  ctx.log("INFO", "Menganalisis header edge routing dan proteksi reverse proxy...");
  const rootRes = await safeFetch(ctx.targetUrl);

  const edgeHeaders = [
    { name: "Cloudflare", header: "cf-ray" },
    { name: "AWS CloudFront", header: "x-amz-cf-id" },
    { name: "Akamai Edge", header: "x-akamai-transformed" },
    { name: "Fastly CDN", header: "x-served-by" },
    { name: "Azure Front Door", header: "x-azure-ref" },
    { name: "Kong API Gateway", header: "x-kong-upstream-latency" },
    { name: "Envoy Proxy / Istio", header: "x-envoy-upstream-service-time" },
  ];

  const detectedEdgeTech: string[] = [];
  for (const eh of edgeHeaders) {
    const val = rootRes.headers.get(eh.header);
    if (val) {
      detectedEdgeTech.push(eh.name);
      ctx.log("INFO", `Komponen infrastruktur teridentifikasi: ${eh.name} (${eh.header}: ${val.slice(0, 30)}...)`);

      if (eh.name === "Envoy Proxy / Istio") {
        findings.push({
          title: "Header Debug Envoy Upstream Bocor",
          detail: `Header 'x-envoy-upstream-service-time: ${val}' membocorkan bahwa aplikasi berjalan di atas Envoy/Istio microservice mesh.`,
          evidence: `x-envoy-upstream-service-time: ${val}`,
          severity: "INFORMATIONAL",
          recommendation: "Hapus header upstream service time pada edge ingress controller produksi.",
        });
      }
    }
  }

  // 2. Check for Internal IP Leakage in Headers
  ctx.log("INFO", "Memeriksa indikator kebocoran alamat IP privat (RFC 1918) pada header...");
  const allHeadersStr = Array.from(rootRes.headers.entries())
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");

  const privateIpMatch = allHeadersStr.match(/(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/);
  if (privateIpMatch) {
    findings.push({
      title: "Header Respon Membocorkan Alamat IP Internal (RFC 1918)",
      detail: `Header respon web server membocorkan IP privat backend: ${privateIpMatch[0]}. Ini membantu penyerang memetakan topologi jaringan internal.`,
      evidence: `Internal IP terdeteksi: ${privateIpMatch[0]}`,
      severity: "MEDIUM",
      recommendation: "Sanitasi seluruh header respon di reverse proxy untuk menghapus IP backend internal (seperti X-Backend-Server atau X-Forwarded-Server).",
    });
    ctx.log("FAIL", `Kebocorkan IP internal terdeteksi: ${privateIpMatch[0]}`);
  } else {
    ctx.log("PASS", "Tidak ditemukan kebocoran IP privat (RFC 1918) pada header respon.");
  }

  // 3. Provoke WAF Blocking Signature (Benign XSS / Script probe)
  ctx.log("INFO", "Menguji keberadaan Web Application Firewall (WAF) dengan safe probe pattern...");
  try {
    const wafProbeUrl = `${baseUrl}/?probe=<script>alert(1)</script>`;
    const wafRes = await safeFetch(wafProbeUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SAL4WAKU-Audit/1.0",
      },
      timeoutMs: 5000,
    });

    if (wafRes.status === 403 || wafRes.status === 406 || wafRes.status === 429) {
      ctx.log("PASS", `WAF aktif mendeteksi dan memblokir payload probe (HTTP ${wafRes.status}).`);
    } else {
      ctx.log("INFO", `Respon probe URL menghasilkan HTTP ${wafRes.status} (WAF mungkin beroperasi dalam mode log-only atau payload diabaikan).`);
    }
  } catch {}

  const evaluated = evaluateFindings(
    findings,
    `Topologi arsitektur aman. Terproteksi oleh layer reverse proxy/CDN (${
      detectedEdgeTech.join(", ") || "Generic Gateway"
    }) tanpa membocorkan IP internal.`,
    "Pertahankan proteksi WAF dan pastikan header backend internal selalu disaring di layer terluar."
  );

  ctx.log(evaluated.status === "PASS" ? "PASS" : "WARN", `Hasil akhir WSTG-INFO-10: ${evaluated.status} (Severity: ${evaluated.severity})`);

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
