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
  console.log(`✓ WSTG-INFO-02 executed successfully -> Status: ${res.status}, Logs emitted: ${logs.length}`);

  console.log("\n✅ ALL WSTG 4.2 SUB-AGENTS VERIFIED SUCCESSFULLY!\n");
}

runSelfCheck().catch((err) => {
  console.error("❌ Self-check failed:", err);
  process.exit(1);
});
