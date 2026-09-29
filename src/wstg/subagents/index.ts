import { WstgInfoId } from "../types.js";
import { SubagentExecutor } from "./base.js";
import { info01SearchEngineRecon } from "./info01_search_engine.js";
import { info02WebServerFingerprint } from "./info02_server_fingerprint.js";
import { info03ReviewMetafiles } from "./info03_review_metafiles.js";
import { info04EnumerateApplications } from "./info04_enumerate_apps.js";
import { info05ContentLeakage } from "./info05_content_leakage.js";
import { info06IdentifyEntryPoints } from "./info06_entry_points.js";
import { info07MapExecutionPaths } from "./info07_execution_paths.js";
import { info08FingerprintFramework } from "./info08_framework_fingerprint.js";
import { info09FingerprintWebApp } from "./info09_app_fingerprint.js";
import { info10MapArchitecture } from "./info10_architecture_map.js";

export const WSTG_INFO_SUBAGENTS: Array<{
  id: WstgInfoId;
  name: string;
  executor: SubagentExecutor;
}> = [
  { id: "WSTG-INFO-01", name: "SearchEngineReconSubagent", executor: info01SearchEngineRecon },
  { id: "WSTG-INFO-02", name: "WebServerFingerprintSubagent", executor: info02WebServerFingerprint },
  { id: "WSTG-INFO-03", name: "WebserverMetafilesSubagent", executor: info03ReviewMetafiles },
  { id: "WSTG-INFO-04", name: "AppEnumerationSubagent", executor: info04EnumerateApplications },
  { id: "WSTG-INFO-05", name: "ContentLeakageSubagent", executor: info05ContentLeakage },
  { id: "WSTG-INFO-06", name: "EntryPointsSubagent", executor: info06IdentifyEntryPoints },
  { id: "WSTG-INFO-07", name: "ExecutionPathsSubagent", executor: info07MapExecutionPaths },
  { id: "WSTG-INFO-08", name: "FrameworkFingerprintSubagent", executor: info08FingerprintFramework },
  { id: "WSTG-INFO-09", name: "AppFingerprintSubagent", executor: info09FingerprintWebApp },
  { id: "WSTG-INFO-10", name: "ArchitectureMapSubagent", executor: info10MapArchitecture },
];

export {
  info01SearchEngineRecon,
  info02WebServerFingerprint,
  info03ReviewMetafiles,
  info04EnumerateApplications,
  info05ContentLeakage,
  info06IdentifyEntryPoints,
  info07MapExecutionPaths,
  info08FingerprintFramework,
  info09FingerprintWebApp,
  info10MapArchitecture,
};
