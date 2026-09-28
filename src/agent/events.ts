export type AgentPhase = 
  | "INITIALIZING" 
  | "SCOPE_VALIDATION" 
  | "PASSIVE_RECON" 
  | "DNS_VERIFICATION" 
  | "HTTP_PROBING" 
  | "AI_ANALYSIS" 
  | "COMPLETED" 
  | "FAILED";

export interface AssetRecord {
  fqdn: string;
  ip?: string;
  cname?: string;
  httpStatus?: number;
  httpTitle?: string;
  server?: string;
  techs?: string[];
  isWildcard?: boolean;
  notes?: string[];
  url?: string;
}

export type AgentEvent =
  | { type: "phase"; phase: AgentPhase; message: string }
  | { type: "thought"; content: string; timestamp: string }
  | { type: "tool_start"; tool: string; targetCount: number; concurrency: number }
  | { type: "tool_progress"; tool: string; completed: number; total: number; current: string }
  | { type: "asset_found"; asset: AssetRecord }
  | { type: "highlight"; level: "INFO" | "WARN" | "CRITICAL"; title: string; message: string }
  | { type: "metrics"; subdomainsTotal: number; hostsAlive: number; httpAlive: number; anomalies: number }
  | { type: "report_chunk"; delta: string }
  | { type: "report_ready"; fullReport: string }
  | { type: "done"; summary: { totalFound: number; totalAlive: number; durationMs: number } }
  | { type: "error"; message: string };
