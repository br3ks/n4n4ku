import { DetectedTechStack, TailoredOneliner, WstgInfoId } from "./types.js";

/**
 * Intelligent Tech Stack Profiler for OWASP WSTG Information Gathering.
 * Analyzes HTTP response headers, HTML DOM structures, script paths, and session cookies.
 */
export function detectTechStack(
  headers: Headers | Record<string, string>,
  body: string = "",
  cookieHeader: string = ""
): DetectedTechStack {
  const getHeader = (name: string): string => {
    if (typeof (headers as any).get === "function") {
      return (headers as Headers).get(name) || "";
    }
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === lower) return v as string;
    }
    return "";
  };

  const serverHeader = getHeader("server");
  const poweredBy = getHeader("x-powered-by");
  const aspnetVer = getHeader("x-aspnet-version");
  const setCookie = cookieHeader || getHeader("set-cookie");

  const servers: string[] = [];
  const frameworks: string[] = [];
  const runtimes: string[] = [];
  const cms: string[] = [];
  const technologies: string[] = [];

  // 1. Web Servers & Proxies
  if (serverHeader) {
    if (/nginx/i.test(serverHeader)) servers.push(serverHeader.includes("/") ? serverHeader : "Nginx");
    if (/apache/i.test(serverHeader)) servers.push(serverHeader.includes("/") ? serverHeader : "Apache HTTP Server");
    if (/cloudflare/i.test(serverHeader)) servers.push("Cloudflare Edge Reverse Proxy");
    if (/microsoft-iis/i.test(serverHeader)) servers.push(serverHeader);
    if (/caddy/i.test(serverHeader)) servers.push("Caddy Web Server");
    if (/litespeed/i.test(serverHeader)) servers.push("LiteSpeed");
    if (servers.length === 0) servers.push(serverHeader);
  }

  // 2. Frameworks & Runtimes from Headers / Powered-By
  if (poweredBy) {
    if (/express/i.test(poweredBy)) {
      frameworks.push("Express.js");
      runtimes.push("Node.js");
    }
    if (/next\.js/i.test(poweredBy)) {
      frameworks.push("Next.js");
      runtimes.push("Node.js");
    }
    if (/php/i.test(poweredBy)) runtimes.push(poweredBy);
    if (/asp\.net/i.test(poweredBy)) {
      frameworks.push("ASP.NET");
      runtimes.push(".NET CLR");
    }
  }

  if (aspnetVer) {
    frameworks.push(`ASP.NET v${aspnetVer}`);
    runtimes.push(".NET");
  }

  // 3. Cookie Signatures
  if (/laravel_session|XSRF-TOKEN/i.test(setCookie)) {
    frameworks.push("Laravel");
    runtimes.push("PHP");
  }
  if (/JSESSIONID/i.test(setCookie)) {
    frameworks.push("Spring Boot / Java EE");
    runtimes.push("Java JVM");
  }
  if (/connect\.sid/i.test(setCookie)) {
    frameworks.push("Express.js");
    runtimes.push("Node.js");
  }
  if (/csrftoken|sessionid/i.test(setCookie) && !frameworks.includes("Django")) {
    frameworks.push("Django");
    runtimes.push("Python");
  }
  if (/ASP\.NET_SessionId|\.AspNetCore/i.test(setCookie)) {
    frameworks.push("ASP.NET Core");
    runtimes.push(".NET");
  }
  if (/wp-settings|wordpress_logged_in/i.test(setCookie)) {
    cms.push("WordPress");
    runtimes.push("PHP");
  }

  // 4. HTML DOM & Assets Inspection
  if (body) {
    // Next.js
    if (body.includes("/_next/") || body.includes("__NEXT_DATA__")) {
      if (!frameworks.includes("Next.js")) frameworks.push("Next.js");
      if (!technologies.includes("React")) technologies.push("React");
      if (!runtimes.includes("Node.js")) runtimes.push("Node.js");
    }
    // Nuxt / Vue
    if (body.includes("__NUXT__") || body.includes("/_nuxt/")) {
      if (!frameworks.includes("Nuxt.js")) frameworks.push("Nuxt.js");
      if (!technologies.push("Vue.js")) technologies.push("Vue.js");
    }
    // WordPress
    if (body.includes("/wp-content/") || body.includes("/wp-includes/")) {
      if (!cms.includes("WordPress")) cms.push("WordPress");
      if (!runtimes.includes("PHP")) runtimes.push("PHP");
    }
    // Drupal
    if (body.includes("Drupal.settings") || body.includes("/sites/default/files/")) {
      if (!cms.includes("Drupal")) cms.push("Drupal");
      if (!runtimes.includes("PHP")) runtimes.push("PHP");
    }
    // Tailwind CSS
    if (body.includes("tailwindcss") || /class="[^"]*(flex|grid|hidden|px-|py-|text-)[^"]*"/i.test(body)) {
      technologies.push("Tailwind CSS");
    }
    // Meta Generator Tag
    const metaGen = body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
    if (metaGen && metaGen[1]) {
      const gen = metaGen[1];
      if (/wordpress/i.test(gen) && !cms.includes("WordPress")) cms.push(gen);
      else if (/drupal/i.test(gen) && !cms.includes("Drupal")) cms.push(gen);
      else if (/joomla/i.test(gen) && !cms.includes("Joomla")) cms.push(gen);
      else technologies.push(gen);
    }
  }

  // Deduplicate arrays
  const uniq = (arr: string[]) => Array.from(new Set(arr));

  const isSpa =
    frameworks.includes("Next.js") ||
    frameworks.includes("Nuxt.js") ||
    technologies.includes("React") ||
    technologies.includes("Vue.js") ||
    body.includes('<div id="root">') ||
    body.includes('<div id="app">');

  return {
    servers: uniq(servers),
    frameworks: uniq(frameworks),
    runtimes: uniq(runtimes),
    cms: uniq(cms),
    technologies: uniq(technologies),
    isSpa,
  };
}

/**
 * Generate Adaptive Scenario & Custom Oneliners (ffuf, dirsearch, curl) tailored for the target tech stack.
 */
export function getAdaptiveScenario(
  id: WstgInfoId,
  tech: DetectedTechStack,
  targetUrl: string
): { scenario: string; tailoredOneliners: TailoredOneliner[] } {
  const cleanUrl = targetUrl.replace(/\/$/, "");
  const host = new URL(targetUrl).hostname;
  const isWp = tech.cms.some((c) => /wordpress/i.test(c));
  const isSpring = tech.frameworks.some((f) => /spring/i.test(f));
  const isNext = tech.frameworks.some((f) => /next/i.test(f));
  const isLaravel = tech.frameworks.some((f) => /laravel/i.test(f));
  const isDotNet = tech.frameworks.some((f) => /asp\.net/i.test(f));
  const isPhp = tech.runtimes.some((r) => /php/i.test(r)) || isWp || isLaravel;

  const stackSummary = [
    ...tech.servers,
    ...tech.frameworks,
    ...tech.cms,
    ...tech.runtimes.slice(0, 1),
  ].join(" + ") || "Generic Modern Web";

  let scenario = "";
  const oneliners: TailoredOneliner[] = [];

  switch (id) {
    case "WSTG-INFO-01":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Memetakan arsip publik, snapshot CDX historis, dan kebocoran endpoint repositori/staging (${tech.isSpa ? "Prioritaskan endpoint API & assets bundle" : "Prioritaskan direct server files & dynamic queries"}).`;
      oneliners.push({
        tool: "curl",
        command: `curl -s -k "https://web.archive.org/cdx/search/cdx?url=${host}/*&output=json&limit=100&fl=original,statuscode" | jq -r '.[][0]' | grep -E '\\.(env|bak|sql|tar|zip|config)$'`,
        description: "Filter arsip Wayback Machine untuk file backup dan konfigurasi sensitif",
        category: "technology-audit",
      });
      break;

    case "WSTG-INFO-02":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Fingerprint daemon server origin vs edge proxy. Mengirim probe metode non-standar (BADMETHOD/TRACE) untuk memicu error page disclosure serta memverifikasi server_tokens header.`;
      oneliners.push({
        tool: "curl",
        command: `curl -sI -k "${cleanUrl}" -H "User-Agent: Mozilla/5.0" | grep -Ei "(Server|X-Powered-By|X-AspNet|Via|CF-RAY)"`,
        description: "Ekstrak header identifikasi server, proxy, dan backend runtime",
        category: "technology-audit",
      });
      break;

    case "WSTG-INFO-03":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Fuzzing metadata metafiles, RFC standard directories (.well-known/*, security.txt, sitemap.xml), dan file indexing policies (robots.txt, crossdomain.xml).`;
      oneliners.push({
        tool: "ffuf",
        command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302,403 -ac -rate 30 << 'EOF'\nrobots.txt\nsitemap.xml\n.well-known/security.txt\n.well-known/openid-configuration\ncrossdomain.xml\nclientaccesspolicy.xml\nEOF`,
        description: "Fuzzing cepat daftar file metadata standar dan rute tersembunyi dengan ffuf",
        category: "directory-fuzzing",
      });
      break;

    case "WSTG-INFO-04":
      if (isSpring) {
        scenario = `Target terdeteksi menggunakan Spring Boot. Skenario adaptif: Enumerasi konsol monitoring Java (Actuator, H2-Console, Eureka, Swagger-UI, Admin Server) dan multi-tenant virtual host discovery.`;
      } else if (isWp) {
        scenario = `Target terdeteksi menggunakan WordPress CMS. Skenario adaptif: Enumerasi antarmuka administratif COTS (/wp-admin/, /phpmyadmin/), portal monitoring, dan multi-site tenant host routing.`;
      } else if (isNext) {
        scenario = `Target terdeteksi menggunakan Next.js / Node. Skenario adaptif: Enumerasi sub-aplikasi yang terpasang di reverse proxy, portal internal (Grafana, Kibana, Jenkins), dan routing sub-domain dev/staging.`;
      } else {
        scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Memeriksa multi-tenancy, mounted administrative apps (Grafana, Jenkins, phpMyAdmin), dan host-header virtual host routing.`;
      }
      oneliners.push({
        tool: "ffuf",
        command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302,401,403 -ac -rate 40 << 'EOF'\nadmin\nportal\ngrafana\njenkins\nkibana\nphpmyadmin\nswagger\napi-docs\nEOF`,
        description: "Fuzzing mount-points aplikasi manajemen infrastruktur menggunakan ffuf",
        category: "directory-fuzzing",
      });
      break;

    case "WSTG-INFO-05":
      if (isNext) {
        scenario = `Target Next.js: Skenario adaptif berfokus pada hunting JavaScript sourcemaps (.js.map), client build manifests (_buildManifest.js), NEXT_DATA JSON payload exposure, dan file .env / .git terbuka.`;
      } else if (isLaravel) {
        scenario = `Target Laravel: Skenario adaptif berfokus pada audit exposed .env file, storage/logs/laravel.log, composer.json/lock, dan Ignition debug handler.`;
      } else {
        scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Hunting kebocoran konfigurasi (.env, .git/HEAD, docker-compose.yml, backup file .bak/.sql), HTML comments, dan JavaScript sourcemaps.`;
      }
      oneliners.push({
        tool: "ffuf",
        command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302,403 -ac -rate 40 << 'EOF'\n.env\n.git/HEAD\n.git/config\ndocker-compose.yml\npackage.json\ncomposer.json\nweb.config\nbackup.zip\nEOF`,
        description: "Fuzzing kebocoran file konfigurasi dan source code repository menggunakan ffuf",
        category: "directory-fuzzing",
      });
      oneliners.push({
        tool: "dirsearch",
        command: `python3 dirsearch.py -u "${cleanUrl}" -e env,git,bak,zip,sql,json,yml -x 404,500 -t 30 --random-agent`,
        description: "Dirsearch audit multi-ekstensi file backup dan source code repository",
        category: "directory-fuzzing",
      });
      break;

    case "WSTG-INFO-06":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Active Directory Fuzzing via ffuf/dirsearch, attack surface mapping, REST/GraphQL documentation discovery, dan testing HTTP methods berisiko (TRACE/OPTIONS/PUT).`;
      oneliners.push({
        tool: "ffuf",
        command: `ffuf -u "${cleanUrl}/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,401,403 -ac -rate 50 -H "User-Agent: Mozilla/5.0"`,
        description: "Deep Directory Fuzzing profesional dengan ffuf (SecLists + Auto-Calibration Soft-404)",
        category: "directory-fuzzing",
      });
      oneliners.push({
        tool: "dirsearch",
        command: `python3 dirsearch.py -u "${cleanUrl}" -e ${isPhp ? "php,html,json,txt" : isDotNet ? "aspx,ashx,json,xml" : "html,js,json,txt"} -x 404,500 -t 40 --random-agent`,
        description: "Deep Directory Fuzzing profesional dengan dirsearch multi-ekstensi",
        category: "directory-fuzzing",
      });
      oneliners.push({
        tool: "curl",
        command: `curl -s -k -X TRACE "${cleanUrl}" -I | head -n 5`,
        description: "Pengujian Cross-Site Tracing (XST) via HTTP TRACE method",
        category: "vulnerability-probe",
      });
      break;

    case "WSTG-INFO-07":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Memetakan user journeys, flow autentikasi/registrasi, endpoint API multi-step, dan logika transisi state untuk potensi parameter tampering.`;
      oneliners.push({
        tool: "ffuf",
        command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302,401 -ac << 'EOF'\nlogin\nregister\nforgot-password\nreset-password\ncheckout\ncart\nprofile\naccount\napi/v1/user\nEOF`,
        description: "Fuzzing alur bisnis kritis dan transisi state aplikasi",
        category: "api-discovery",
      });
      break;

    case "WSTG-INFO-08":
      if (isSpring) {
        scenario = `Target Spring Boot: Skenario adaptif berfokus pada probing rute Actuator (/actuator/env, /actuator/heapdump, /actuator/mappings, /actuator/logfile), validasi false-positive SPA, dan error trace JVM.`;
        oneliners.push({
          tool: "ffuf",
          command: `ffuf -u "${cleanUrl}/actuator/FUZZ" -w - -mc 200,401,403 << 'EOF'\nenv\nhealth\nmappings\nheapdump\nbeans\nlogfile\nmetrics\nsessions\nEOF`,
          description: "Dedicated ffuf fuzzing untuk Spring Boot Actuator endpoints",
          category: "vulnerability-probe",
        });
      } else if (isLaravel) {
        scenario = `Target Laravel: Skenario adaptif berfokus pada probing /_ignition/health-check, /telescope, /horizon, /nova, rute profiler, dan leak Laravel session cookies.`;
        oneliners.push({
          tool: "ffuf",
          command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,302,403 << 'EOF'\n_ignition/health-check\ntelescope\nhorizon\nnova\n_debugbar\nEOF`,
          description: "Dedicated ffuf fuzzing untuk Laravel debug handlers & profiler",
          category: "vulnerability-probe",
        });
      } else if (isNext) {
        scenario = `Target Next.js: Skenario adaptif berfokus pada analisis client bundles, Next.js Server Action identifiers, API routes (api/*), dan bypass middleware headers (x-middleware-prefetch).`;
        oneliners.push({
          tool: "curl",
          command: `curl -s -k "${cleanUrl}/_next/static/development/_devMiddlewareManifest.json" -I`,
          description: "Pemeriksaan apakah Next.js berjalan dalam mode development",
          category: "technology-audit",
        });
      } else {
        scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Menganalisis cookie signatures, header framework, rute debugging umum, dan banner runtime.`;
        oneliners.push({
          tool: "ffuf",
          command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302,401,403 << 'EOF'\nactuator/health\n_ignition/health-check\n_profiler/\ntelescope/\nswagger-ui.html\nEOF`,
          description: "Fuzzing konsol debug lintas framework",
          category: "vulnerability-probe",
        });
      }
      break;

    case "WSTG-INFO-09":
      if (isWp) {
        scenario = `Target WordPress: Skenario adaptif mengeksekusi enumerasi plugin populer (/wp-content/plugins/*), REST API user enumeration (/wp-json/wp/v2/users), uji XML-RPC multicall, dan file dokumentasi bawaan (readme.html).`;
        oneliners.push({
          tool: "ffuf",
          command: `ffuf -u "${cleanUrl}/wp-content/plugins/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -mc 200,301,302,403 -rate 50`,
          description: "Fuzzing direktori plugin WordPress dengan ffuf",
          category: "directory-fuzzing",
        });
        oneliners.push({
          tool: "curl",
          command: `curl -s -k "${cleanUrl}/wp-json/wp/v2/users" | jq '.[].slug'`,
          description: "User enumeration via WordPress REST API",
          category: "technology-audit",
        });
      } else {
        scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Audit aplikasi COTS/CMS (WordPress, Drupal, Joomla, Strapi, Ghost, Keycloak) serta sanitasi tag meta generator dan file dokumentasi instalasi.`;
        oneliners.push({
          tool: "ffuf",
          command: `ffuf -u "${cleanUrl}/FUZZ" -w - -mc 200,301,302 << 'EOF'\nwp-login.php\nreadme.html\nadministrator/\nuser/login\nadmin/login\nghost/\nstrapi/\nEOF`,
          description: "Fuzzing interface login dan dokumentasi CMS populer",
          category: "directory-fuzzing",
        });
      }
      break;

    case "WSTG-INFO-10":
      scenario = `Target stack: [${stackSummary}]. Skenario adaptif: Pemetaan edge reverse proxy (Cloudflare/Nginx), Web Application Firewall (WAF), load balancing headers, dan pengujian origin IP disclosure via direct Host bypass.`;
      oneliners.push({
        tool: "curl",
        command: `curl -sI -k "${cleanUrl}" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Real-IP: 127.0.0.1"`,
        description: "Pengujian respon header terhadap reverse proxy bypass headers",
        category: "technology-audit",
      });
      break;
  }

  return { scenario, tailoredOneliners: oneliners };
}
