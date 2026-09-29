import assert from "node:assert";
import { WSTG_INFO_SUBAGENTS } from "../src/wstg/subagents/index.js";

async function runSelfCheck() {
  console.log("--- Running WSTG 4.2 Sub-Agents Self-Check ---");
  
  assert.strictEqual(WSTG_INFO_SUBAGENTS.length, 10, "Harus ada tepat 10 sub-agents WSTG-INFO");
  
  const expectedIds = [
    "WSTG-INFO-01",
    "WSTG-INFO-02",
    "WSTG-INFO-03",
    "WSTG-INFO-04",
    "WSTG-INFO-05",
    "WSTG-INFO-06",
    "WSTG-INFO-07",
    "WSTG-INFO-08",
    "WSTG-INFO-09",
    "WSTG-INFO-10",
  ];

  for (let i = 0; i < expectedIds.length; i++) {
    const sub = WSTG_INFO_SUBAGENTS[i];
    assert.strictEqual(sub.id, expectedIds[i], `Checklist ID ${expectedIds[i]} harus sesuai`);
    assert(typeof sub.executor === "function", `Executor untuk ${sub.id} harus fungsi`);
    console.log(`✓ [${sub.id}] ${sub.name} terverifikasi`);
  }

  // Test executing WSTG-INFO-02 with dummy logger
  const logs: string[] = [];
  const testTarget = "http://localhost:3000";
  const dummyCtx = {
    targetUrl: testTarget,
    targetDomain: "localhost",
    log: (level: string, msg: string) => logs.push(`[${level}] ${msg}`),
    llmConfig: {},
  };

  console.log("Testing subagent execution (WSTG-INFO-02)...");
  const res = await WSTG_INFO_SUBAGENTS[1].executor(dummyCtx);
  assert.strictEqual(res.id, "WSTG-INFO-02");
  assert(res.status === "PASS" || res.status === "FAIL" || res.status === "REVIEW");
  assert(typeof res.durationMs === "number");
  assert(Array.isArray(res.toolsUsed) && res.toolsUsed.length > 0, "toolsUsed harus array tidak kosong");
  assert(typeof res.verificationStatement === "string" && res.verificationStatement.length > 20, "verificationStatement harus terisi");
  assert(typeof res.falsePositiveAnalysis === "string" && res.falsePositiveAnalysis.length > 10, "falsePositiveAnalysis harus terisi");
  assert(typeof res.rawOutput === "string" && res.rawOutput.length > 10, "rawOutput harus terisi");
  assert(typeof res.adaptiveScenario === "string" && res.adaptiveScenario.length > 10, "adaptiveScenario harus terisi");
  assert(Array.isArray(res.tailoredOneliners) && res.tailoredOneliners.length > 0, "tailoredOneliners harus terisi");
  console.log(`✓ WSTG-INFO-02 executed successfully -> Status: ${res.status}, Tools: ${res.toolsUsed.join(", ")}`);
  console.log(`✓ Adaptive Scenario: ${res.adaptiveScenario.slice(0, 60)}...`);
  console.log(`✓ Tailored Oneliners: ${res.tailoredOneliners.length} commands generated`);

  // Test Tech Stack Detection
  console.log("\nTesting Tech Stack Detection Engine...");
  const { detectTechStack } = await import("../src/wstg/tech_matrix.js");
  const tech = detectTechStack(
    new Headers({ server: "nginx/1.24.0", "x-powered-by": "Next.js", "set-cookie": "laravel_session=xyz;" }),
    '<div id="__NEXT_DATA__"></div>'
  );
  assert(tech.servers.some((s) => s.includes("nginx")), "Nginx harus terdeteksi");
  assert(tech.frameworks.includes("Next.js"), "Next.js harus terdeteksi");
  assert(tech.frameworks.includes("Laravel"), "Laravel harus terdeteksi");
  assert.strictEqual(tech.isSpa, true, "isSpa harus true untuk Next.js");
  console.log("✓ Tech Stack Detection verified successfully:", tech);

  // Test Fuzzer Helpers
  console.log("\nTesting Fuzzer Wordlist & ffuf Engine...");
  const { buildAdaptiveWordlist, checkFfufAvailable } = await import("../src/wstg/fuzzer.js");
  const words = buildAdaptiveWordlist(tech);
  assert(words.includes("admin"), "Wordlist harus memuat admin");
  assert(words.includes("_next/static"), "Wordlist Next.js harus memuat _next/static");
  assert(words.includes("_ignition/health-check"), "Wordlist Laravel harus memuat _ignition");
  console.log(`✓ Adaptive Wordlist generated: ${words.length} items`);

  // Test ProjectDiscovery Suite Integration
  console.log("\nTesting ProjectDiscovery Suite (Katana, Nuclei, Subfinder)...");
  const { runKatanaCrawler, runNucleiInfoAudit, runSubfinderRecon } = await import("../src/wstg/projectdiscovery.js");
  
  const katanaRes = await runKatanaCrawler("http://localhost:3000", { maxDepth: 1 });
  assert.strictEqual(katanaRes.tool, "katana");
  assert(katanaRes.rawOutput.includes("katana -u"), "Output Katana harus memuat banner CLI otentik");
  console.log("✓ Katana Crawler Engine verified successfully:", katanaRes.engine);

  const nucleiRes = await runNucleiInfoAudit("http://localhost:3000", tech, "tech");
  assert.strictEqual(nucleiRes.tool, "nuclei");
  assert(nucleiRes.rawOutput.includes("nuclei -u"), "Output Nuclei harus memuat banner CLI otentik");
  console.log("✓ Nuclei Audit Engine verified successfully:", nucleiRes.engine);

  const subfinderRes = await runSubfinderRecon("localhost");
  assert.strictEqual(subfinderRes.tool, "subfinder");
  assert(subfinderRes.rawOutput.includes("subfinder -d"), "Output Subfinder harus memuat banner CLI otentik");
  console.log("✓ Subfinder Engine verified successfully:", subfinderRes.engine);

  console.log("\n✅ ALL WSTG 4.2 SUB-AGENTS & PROJECTDISCOVERY ENGINES VERIFIED SUCCESSFULLY!\n");
}

runSelfCheck().catch((err) => {
  console.error("❌ Self-check failed:", err);
  process.exit(1);
});
