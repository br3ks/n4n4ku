import { isSubdomainInScope, normalizeDomain } from "../core/scope.js";

interface CrtShEntry {
  name_value?: string;
  common_name?: string;
}

export async function queryCrtSh(targetDomain: string): Promise<string[]> {
  const domain = normalizeDomain(targetDomain);
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
  const subdomains = new Set<string>();
  subdomains.add(domain);

  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(15000),
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json",
      },
    });

    if (!res.ok) {
      return Array.from(subdomains);
    }

    const data = (await res.json()) as CrtShEntry[];
    if (Array.isArray(data)) {
      for (const entry of data) {
        const rawNames = [entry.name_value, entry.common_name].filter(Boolean) as string[];
        for (const raw of rawNames) {
          const lines = raw.split("\n");
          for (const line of lines) {
            let candidate = line.trim().toLowerCase();
            if (candidate.startsWith("*.")) {
              candidate = candidate.slice(2);
            }
            if (candidate && isSubdomainInScope(candidate, domain)) {
              subdomains.add(candidate);
            }
          }
        }
      }
    }
  } catch (err: any) {
    // Graceful error recovery: return what we have (at least root)
  }

  return Array.from(subdomains);
}
