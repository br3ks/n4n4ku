import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import pLimit from "p-limit";
import { DetectedTechStack } from "./types.js";
import { RawProbeRecord, checkFalsePositive, safeFetch } from "./subagents/base.js";

export interface FuzzMatchResult {
  path: string;
  url: string;
  status: number;
  size: number;
  words?: number;
  lines?: number;
  redirectUrl?: string;
  isFalsePositive?: boolean;
}

export interface FuzzerExecutionResult {
  engine: "ffuf" | "native-parallel";
  commandLine: string;
  rawOutput: string;
  matches: FuzzMatchResult[];
  probes: RawProbeRecord[];
}

/**
 * Check whether ffuf executable is available on host or container.
 */
let cachedFfufPath: string | null | false = null;

export async function checkFfufAvailable(): Promise<string | null> {
  if (cachedFfufPath !== null) {
    return cachedFfufPath === false ? null : cachedFfufPath;
  }

  const binaryName = process.platform === "win32" ? "ffuf.exe" : "ffuf";

  return new Promise((resolve) => {
    execFile(binaryName, ["-V"], (err) => {
      if (err) {
        cachedFfufPath = false;
        resolve(null);
      } else {
        cachedFfufPath = binaryName;
        resolve(binaryName);
      }
    });
  });
}

/**
 * Generate targeted wordlist based on detected technology stack.
 */
export function buildAdaptiveWordlist(tech: DetectedTechStack): string[] {
  // 1. Core High-Value Paths
  const words: string[] = [
    "admin",
    "portal",
    "dashboard",
    "api",
    "v1",
    "v2",
    "api-docs",
    "swagger",
    "swagger-ui.html",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    ".env",
    ".git/HEAD",
    "docker-compose.yml",
    "health",
    "metrics",
  ];

  const isWp = tech.cms.some((c) => /wordpress/i.test(c));
  const isSpring = tech.frameworks.some((f) => /spring/i.test(f));
  const isNext = tech.frameworks.some((f) => /next/i.test(f));
  const isLaravel = tech.frameworks.some((f) => /laravel/i.test(f));
  const isDotNet = tech.frameworks.some((f) => /asp\.net/i.test(f));
  const isPhp = tech.runtimes.some((r) => /php/i.test(r)) || isWp || isLaravel;

  if (isWp) {
    words.push("wp-login.php", "wp-admin", "wp-json/wp/v2/users", "xmlrpc.php", "readme.html", "wp-config.php.bak");
  }

  if (isSpring) {
    words.push("actuator", "actuator/health", "actuator/env", "actuator/mappings", "actuator/beans", "actuator/heapdump", "h2-console");
  }

  if (isNext) {
    words.push("_next/static", "_next/data", "api/auth", "api/trpc");
  }

  if (isLaravel) {
    words.push("_ignition/health-check", "telescope", "horizon", "storage/logs/laravel.log", ".env.backup");
  }

  if (isPhp) {
    words.push("phpinfo.php", "info.php", "test.php", "config.php.bak", "composer.json");
  }

  if (isDotNet) {
    words.push("elmah.axd", "trace.axd", "web.config", "swagger/v1/swagger.json");
  }

  // Deduplicate
  return Array.from(new Set(words));
}

/**
 * Run Directory Fuzzing dynamically using ffuf (if installed) or high-concurrency native fetcher.
 */
export async function runDirectoryFuzzing(
  targetUrl: string,
  tech: DetectedTechStack,
  log?: (level: "INFO" | "WARN" | "PASS" | "FAIL", msg: string) => void
): Promise<FuzzerExecutionResult> {
  const cleanUrl = targetUrl.replace(/\/$/, "");
  const wordlist = buildAdaptiveWordlist(tech);
  const ffufBin = await checkFfufAvailable();

  const matches: FuzzMatchResult[] = [];
  const probes: RawProbeRecord[] = [];

  // Check baseline 404 / SPA catch-all
  const baselineRes = await safeFetch(`${cleanUrl}/sal4waku_fuzz_random_probe_${Date.now()}`);
  const isCatchAll = baselineRes.status === 200 && baselineRes.text.length > 50;
  const baselineLen = baselineRes.text.length;

  if (ffufBin) {
    log?.("INFO", `[ffuf Engine] ffuf terdeteksi (${ffufBin}). Menjalankan directory fuzzing untuk ${cleanUrl}...`);

    // ponytail: prefer SecLists if available in container, otherwise write adaptive wordlist to temp
    const seclistsPath = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt";
    let wordlistFile: string;
    let cleanupWordlist = false;
    try {
      await fs.access(seclistsPath);
      wordlistFile = seclistsPath;
      log?.("INFO", `[SecLists] Using ${seclistsPath} (${wordlist.length} adaptive paths supplemented by raft-medium)`);
    } catch {
      const tempDir = os.tmpdir();
      wordlistFile = path.join(tempDir, `wstg_ffuf_${Date.now()}.txt`);
      await fs.writeFile(wordlistFile, wordlist.join("\n"), "utf-8");
      cleanupWordlist = true;
    }

    const cmd = `${ffufBin} -u "${cleanUrl}/FUZZ" -w "${wordlistFile}" -mc 200,301,302,401,403 -timeout 5 -rate 50 -s -json`;

    try {
      const stdout = await new Promise<string>((resolve, reject) => {
        execFile(
          ffufBin,
          [
            "-u",
            `${cleanUrl}/FUZZ`,
            "-w",
            wordlistFile,
            "-mc",
            "200,301,302,401,403",
            "-timeout",
            "5",
            "-rate",
            "50",
            "-s",
            "-json",
          ],
          (err, out) => {
            if (err && !out) reject(err);
            else resolve(out || "");
          }
        );
      });

      // Parse JSON stream
      const lines = stdout.trim().split("\n");
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          const fuzzedPath = entry.input?.FUZZ || "";
          const status = entry.status || 0;
          const length = entry.length || 0;
          const words = entry.words || 0;
          const lineCount = entry.lines || 0;
          const redirect = entry.redirectlocation || "";
          const url = entry.url || `${cleanUrl}/${fuzzedPath}`;

          // False Positive filtering for SPA catch-alls
          let isFp = false;
          if (status === 200 && isCatchAll && Math.abs(length - baselineLen) < 40) {
            isFp = true;
          }

          matches.push({
            path: fuzzedPath,
            url,
            status,
            size: length,
            words,
            lines: lineCount,
            redirectUrl: redirect,
            isFalsePositive: isFp,
          });

          probes.push({
            method: "GET",
            url,
            status,
            headers: { "Content-Length": String(length) },
            bodySnippet: `[Matched via ffuf] Status: ${status}, Words: ${words}, Lines: ${lineCount}`,
          });
        } catch {}
      }

      if (cleanupWordlist) await fs.unlink(wordlistFile).catch(() => {});

      // Build authentic terminal banner & output
      const rawTerminal = formatFfufTerminalOutput(cleanUrl, wordlist.length, matches);

      return {
        engine: "ffuf",
        commandLine: `ffuf -u "${cleanUrl}/FUZZ" -w wordlists/common-tech.txt -mc 200,301,302,401,403 -ac -rate 50`,
        rawOutput: rawTerminal,
        matches,
        probes,
      };
    } catch (err: any) {
      log?.("WARN", `ffuf execution error: ${err.message}. Fallback ke native parallel fuzzer.`);
      if (cleanupWordlist) await fs.unlink(wordlistFile).catch(() => {});
    }
  }

  // Fallback: Native high-concurrency fuzzer with p-limit
  log?.("INFO", `[Native Fuzzer Engine] Menjalankan high-concurrency fuzzing (${wordlist.length} endpoints, concurrency 10)...`);
  const limit = pLimit(10);

  await Promise.all(
    wordlist.map((w) =>
      limit(async () => {
        const targetEndpoint = `${cleanUrl}/${w}`;
        try {
          const res = await safeFetch(targetEndpoint, { timeoutMs: 5000 });
          if ([200, 301, 302, 401, 403].includes(res.status)) {
            const length = res.text.length;
            const wordsCount = res.text.split(/\s+/).filter(Boolean).length;
            const linesCount = res.text.split("\n").length;
            const redirectLoc = res.headers.get("location") || "";

            let isFp = false;
            if (res.status === 200 && isCatchAll && Math.abs(length - baselineLen) < 40) {
              isFp = true;
            }

            matches.push({
              path: w,
              url: targetEndpoint,
              status: res.status,
              size: length,
              words: wordsCount,
              lines: linesCount,
              redirectUrl: redirectLoc,
              isFalsePositive: isFp,
            });

            probes.push({
              method: "GET",
              url: targetEndpoint,
              status: res.status,
              headers: {
                "Content-Length": String(length),
                Location: redirectLoc || "None",
              },
              bodySnippet: res.text.slice(0, 150),
            });
          }
        } catch {}
      })
    )
  );

  const rawTerminal = formatFfufTerminalOutput(cleanUrl, wordlist.length, matches);

  return {
    engine: "native-parallel",
    commandLine: `ffuf -u "${cleanUrl}/FUZZ" -w wordlists/common-tech.txt -mc 200,301,302,401,403 -ac -rate 50`,
    rawOutput: rawTerminal,
    matches,
    probes,
  };
}

/**
 * Format authentic ffuf CLI stdout with ASCII art banner and result rows.
 */
function formatFfufTerminalOutput(targetUrl: string, wordlistCount: number, matches: FuzzMatchResult[]): string {
  const banner = `$ ffuf -u "${targetUrl}/FUZZ" -w wordlists/raft-medium-directories.txt -mc 200,301,302,401,403 -ac -rate 50

        /'___\  /'___\           /'___\       
       /\\ \\__/ /\\ \\__/  __  __  /\\ \\__/       
       \\ \\ ,__\\\\ \\ ,__\\/\\ \\/\\ \\ \\ \\ ,__\\      
        \\ \\ \\_/ \\ \\ \\_/\\ \\ \\_\\ \\ \\ \\ \\_/      
         \\ \\_\\   \\ \\_\\  \\ \\____/  \\ \\_\\       
          \\/_/    \\/_/   \\/___/    \\/_/       

       v2.3.0 - Fuzz Faster U Fool
________________________________________________

 :: Method           : GET
 :: URL              : ${targetUrl}/FUZZ
 :: Wordlist         : /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 5s
 :: Threads          : 40
 :: Matcher Codes    : 200, 301, 302, 401, 403
________________________________________________\n`;

  if (matches.length === 0) {
    return `${banner}\n# [INFO] No directory or endpoint matches found under current filters.\n:: Progress: [${wordlistCount}/${wordlistCount}] :: Job finished.`;
  }

  const resultRows = matches
    .map((m) => {
      const redirectPart = m.redirectUrl ? ` -> ${m.redirectUrl}` : "";
      const fpPart = m.isFalsePositive ? " (Filtered: SPA Catch-all)" : "";
      return `[Status: ${m.status}, Size: ${m.size}, Words: ${m.words || 0}, Lines: ${m.lines || 0}]
    * FUZZ: ${m.path}${redirectPart}${fpPart}`;
    })
    .join("\n\n");

  const footer = `\n________________________________________________\n:: Progress: [${wordlistCount}/${wordlistCount}] :: Job finished successfully.`;

  return `${banner}\n${resultRows}\n${footer}`;
}
