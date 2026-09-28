import dns from "node:dns/promises";

export interface ApexDnsSummary {
  aRecords: string[];
  nsRecords: string[];
  mxRecords: string[];
  txtRecords: string[];
  soaRecord?: string;
  hasWildcard: boolean;
  wildcardIps: string[];
}

export interface ResolvedHostInfo {
  fqdn: string;
  ip?: string;
  allIps?: string[];
  cname?: string;
  isWildcard: boolean;
  notes: string[];
}

const CLOUD_CNAME_PATTERNS = [
  { pattern: /\.s3(?:-website)?(?:-[\w-]+)?\.amazonaws\.com/i, provider: "AWS S3 Bucket" },
  { pattern: /\.cloudfront\.net/i, provider: "AWS CloudFront" },
  { pattern: /\.elasticbeanstalk\.com/i, provider: "AWS Elastic Beanstalk" },
  { pattern: /\.azurewebsites\.net/i, provider: "Azure Web App" },
  { pattern: /\.trafficmanager\.net/i, provider: "Azure Traffic Manager" },
  { pattern: /\.blob\.core\.windows\.net/i, provider: "Azure Blob Storage" },
  { pattern: /\.github\.io/i, provider: "GitHub Pages" },
  { pattern: /\.herokuapp\.com/i, provider: "Heroku" },
  { pattern: /\.myshopify\.com/i, provider: "Shopify" },
  { pattern: /\.fastly\.net/i, provider: "Fastly CDN" },
  { pattern: /\.zendesk\.com/i, provider: "Zendesk" },
  { pattern: /\.wpengine\.com/i, provider: "WPEngine" },
  { pattern: /\.pantheonsite\.io/i, provider: "Pantheon" },
];

export async function checkWildcardDns(domain: string): Promise<{ hasWildcard: boolean; ips: string[] }> {
  const testSub = `n4n4ku-rnd-${Math.random().toString(36).slice(2, 10)}.${domain}`;
  try {
    const ips = await dns.resolve4(testSub);
    if (ips && ips.length > 0) {
      return { hasWildcard: true, ips };
    }
  } catch {
    // Normal case: NXDOMAIN
  }
  return { hasWildcard: false, ips: [] };
}

export async function resolveApexDns(domain: string): Promise<ApexDnsSummary> {
  const result: ApexDnsSummary = {
    aRecords: [],
    nsRecords: [],
    mxRecords: [],
    txtRecords: [],
    hasWildcard: false,
    wildcardIps: [],
  };

  const tasks = [
    dns.resolve4(domain).then((r) => (result.aRecords = r)).catch(() => {}),
    dns.resolveNs(domain).then((r) => (result.nsRecords = r)).catch(() => {}),
    dns.resolveMx(domain).then((r) => (result.mxRecords = r.map((m) => `${m.exchange} (${m.priority})`))).catch(() => {}),
    dns.resolveTxt(domain).then((r) => (result.txtRecords = r.map((t) => t.join(" ")))).catch(() => {}),
    dns.resolveSoa(domain).then((r) => (result.soaRecord = `${r.nsname} (${r.hostmaster})`)).catch(() => {}),
    checkWildcardDns(domain).then((w) => {
      result.hasWildcard = w.hasWildcard;
      result.wildcardIps = w.ips;
    }).catch(() => {}),
  ];

  await Promise.all(tasks);
  return result;
}

export async function resolveHost(
  fqdn: string,
  wildcardIpsSet: Set<string>
): Promise<ResolvedHostInfo | null> {
  const notes: string[] = [];
  let ip: string | undefined;
  let allIps: string[] = [];
  let cname: string | undefined;
  let isWildcard = false;

  try {
    const cnames = await dns.resolveCname(fqdn).catch(() => []);
    if (cnames && cnames.length > 0) {
      cname = cnames[0];
      for (const item of CLOUD_CNAME_PATTERNS) {
        if (item.pattern.test(cname)) {
          notes.push(`Points to ${item.provider} (${cname})`);
          break;
        }
      }
    }
  } catch {}

  try {
    allIps = await dns.resolve4(fqdn);
    if (allIps.length > 0) {
      ip = allIps[0];
      if (wildcardIpsSet.size > 0 && allIps.some((addr) => wildcardIpsSet.has(addr))) {
        isWildcard = true;
        notes.push("Matches Wildcard DNS IP");
      }
    }
  } catch {
    // If has CNAME but no A record, might be dangling / NXDOMAIN
    if (cname) {
      notes.push("CNAME resolved but A record is NXDOMAIN (Dangling candidate)");
      return { fqdn, cname, isWildcard: false, notes };
    }
    return null;
  }

  return {
    fqdn,
    ip,
    allIps,
    cname,
    isWildcard,
    notes,
  };
}
