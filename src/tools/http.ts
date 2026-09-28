export interface HttpProbeResult {
  fqdn: string;
  url: string;
  status: number;
  title?: string;
  server?: string;
  techs: string[];
  redirectUrl?: string;
  anomalies: string[];
}

const TECH_FINGERPRINTS = [
  { name: "WordPress", pattern: /wp-content|wp-includes|wordpress/i },
  { name: "Next.js", pattern: /__NEXT_DATA__|next\/dist/i },
  { name: "React", pattern: /react-root|data-reactroot|_reactRootContainer/i },
  { name: "Vue.js", pattern: /data-v-|__vue__/i },
  { name: "Angular", pattern: /ng-version|ng-app/i },
  { name: "Laravel", pattern: /laravel_session|XSRF-TOKEN.*laravel/i },
  { name: "Django", pattern: /csrfmiddlewaretoken/i },
  { name: "Swagger / OpenAPI", pattern: /swagger-ui|api documentation|openapi\.json/i },
  { name: "Grafana", pattern: /grafana/i },
  { name: "Jenkins", pattern: /jenkins/i },
  { name: "Kibana", pattern: /kibana/i },
  { name: "Cloudflare", header: "cf-ray" },
  { name: "PHP", header: "x-powered-by", headerPattern: /php/i },
  { name: "Express", header: "x-powered-by", headerPattern: /express/i },
  { name: "ASP.NET", header: "x-powered-by", headerPattern: /asp\.net/i },
];

export async function probeHost(fqdn: string, timeoutMs = 6000): Promise<HttpProbeResult | null> {
  const protocols = ["https://", "http://"];

  for (const proto of protocols) {
    const targetUrl = `${proto}${fqdn}`;
    try {
      const res = await fetch(targetUrl, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });

      const status = res.status;
      const headers = res.headers;
      const server = headers.get("server") || undefined;
      const redirectUrl = headers.get("location") || undefined;

      let bodyText = "";
      try {
        const text = await res.text();
        bodyText = text.slice(0, 100000); // Read up to first 100KB
      } catch {}

      // Title extraction
      let title: string | undefined;
      const titleMatch = bodyText.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
      if (titleMatch) {
        title = titleMatch[1].replace(/\s+/g, " ").trim().slice(0, 120);
      }

      // Tech detection
      const techs: string[] = [];
      if (server) techs.push(server.split("/")[0]);

      for (const fp of TECH_FINGERPRINTS) {
        if (fp.header) {
          const val = headers.get(fp.header);
          if (val && (!fp.headerPattern || fp.headerPattern.test(val))) {
            techs.push(fp.name);
          }
        }
        if (fp.pattern && fp.pattern.test(bodyText)) {
          techs.push(fp.name);
        }
      }

      // Anomaly detection
      const anomalies: string[] = [];
      const lowTitle = (title || "").toLowerCase();
      const lowBody = bodyText.toLowerCase();

      if (lowTitle.includes("swagger") || lowBody.includes("swagger-ui")) {
        anomalies.push("Exposed Swagger / API Documentation");
      }
      if (lowTitle.includes("admin") || lowTitle.includes("dashboard") || lowTitle.includes("login")) {
        anomalies.push(`Administrative Portal (${title})`);
      }
      if (lowBody.includes("nosuchbucket") || lowBody.includes("the specified bucket does not exist")) {
        anomalies.push("Dangling Storage: NoSuchBucket response detected");
      }
      if (lowTitle.includes("index of /") || lowBody.includes("directory listing")) {
        anomalies.push("Directory Listing Enabled (Information Disclosure)");
      }
      if (lowBody.includes("jenkins") || lowTitle.includes("jenkins")) {
        anomalies.push("Exposed CI/CD Portal (Jenkins)");
      }
      if (lowTitle.includes("grafana") || lowTitle.includes("kibana")) {
        anomalies.push("Exposed Monitoring Dashboard");
      }

      return {
        fqdn,
        url: targetUrl,
        status,
        title,
        server,
        techs: Array.from(new Set(techs)),
        redirectUrl,
        anomalies,
      };
    } catch {
      // Continue to next protocol (e.g. try http if https failed)
    }
  }

  return null;
}
