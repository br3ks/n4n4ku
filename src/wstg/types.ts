export type WstgInfoId =
  | "WSTG-INFO-01"
  | "WSTG-INFO-02"
  | "WSTG-INFO-03"
  | "WSTG-INFO-04"
  | "WSTG-INFO-05"
  | "WSTG-INFO-06"
  | "WSTG-INFO-07"
  | "WSTG-INFO-08"
  | "WSTG-INFO-09"
  | "WSTG-INFO-10";

export type WstgStatus = "PASS" | "FAIL" | "REVIEW" | "SKIP" | "RUNNING" | "PENDING";
export type WstgSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL" | "NONE";

export interface WstgFinding {
  title: string;
  detail: string;
  evidence: string;
  severity: WstgSeverity;
  recommendation: string;
  isVerifiedTruePositive?: boolean;
  falsePositiveCheck?: string;
}

export interface TailoredOneliner {
  tool: "ffuf" | "dirsearch" | "curl" | "nmap";
  command: string;
  description: string;
  category: "directory-fuzzing" | "api-discovery" | "technology-audit" | "vulnerability-probe";
}

export interface DetectedTechStack {
  servers: string[];
  frameworks: string[];
  runtimes: string[];
  cms: string[];
  technologies: string[];
  isSpa: boolean;
  catchAllEnabled?: boolean;
}

export interface WstgChecklistResult {
  id: WstgInfoId;
  title: string;
  subAgentName: string;
  objective: string;
  status: WstgStatus;
  severity: WstgSeverity;
  toolsUsed: string[];
  verificationStatement: string;
  falsePositiveAnalysis: string;
  adaptiveScenario?: string;
  tailoredOneliners?: TailoredOneliner[];
  findings: WstgFinding[];
  evidenceSummary: string;
  rawOutput: string;
  recommendation: string;
  durationMs: number;
}

export type WstgEvent =
  | { type: "wstg_start"; targetUrl: string; totalChecklists: number }
  | { type: "subagent_start"; checklistId: WstgInfoId; subAgent: string; objective: string }
  | { type: "subagent_log"; checklistId: WstgInfoId; level: "INFO" | "WARN" | "PASS" | "FAIL"; message: string }
  | { type: "subagent_complete"; result: WstgChecklistResult }
  | { type: "wstg_metrics"; completed: number; total: number; passCount: number; failCount: number; reviewCount: number }
  | { type: "wstg_report_chunk"; delta: string }
  | { type: "wstg_report_ready"; report: string }
  | { type: "wstg_done"; summary: { total: number; passed: number; failed: number; durationMs: number } }
  | { type: "wstg_error"; message: string };
