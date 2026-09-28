export function normalizeDomain(input: string): string {
  let cleaned = input.trim().toLowerCase();
  cleaned = cleaned.replace(/^(?:https?:\/\/)?/i, "");
  cleaned = cleaned.split("/")[0].split(":")[0];
  return cleaned;
}

export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > 253) return false;
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

export function isSubdomainInScope(subdomain: string, rootDomain: string): boolean {
  const normSub = normalizeDomain(subdomain);
  const normRoot = normalizeDomain(rootDomain);
  if (normSub === normRoot) return true;
  return normSub.endsWith(`.${normRoot}`);
}
