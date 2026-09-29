// ==========================================
// n4n4ku Web Cockpit (Recon & WSTG 4.2)
// ==========================================

// Initialize Lucide Icons
lucide.createIcons();

// --- STATE MANAGEMENT ---
let currentScanId = null;
let reconEventSource = null;
let reconTimerInterval = null;
let reconTimerStart = null;
let reconReportMarkdown = "";
let allAssets = [];

let currentAuditId = null;
let wstgEventSource = null;
let wstgTimerInterval = null;
let wstgTimerStart = null;
let wstgReportMarkdown = "";
let allChecklistResults = {};
let allFindings = [];

// Static Checklist Metadata
const CHECKLIST_METADATA = [
  { id: "WSTG-INFO-01", name: "SearchEngineReconSubagent", title: "Conduct Search Engine Discovery and Reconnaissance", objective: "Identifikasi kebocoran data sensitif, hidden URLs, staging environment, atau credentials melalui web archive dan search engines." },
  { id: "WSTG-INFO-02", name: "WebServerFingerprintSubagent", title: "Fingerprint Web Server", objective: "Identifikasi software web server, versi exact, patch level, host OS, active modules, dan error leakage saat menerima malformed requests." },
  { id: "WSTG-INFO-03", name: "WebserverMetafilesSubagent", title: "Review Webserver Metafiles", objective: "Inspeksi file metadata server (robots.txt, sitemap.xml, security.txt, .well-known/*, crossdomain.xml) untuk menemukan private routes." },
  { id: "WSTG-INFO-04", name: "AppEnumerationSubagent", title: "Enumerate Applications on Webserver", objective: "Identifikasi multi-tenancy, virtual hosts, mounted sub-applications, dan portal administrasi infrastruktur (Grafana, Jenkins, phpMyAdmin)." },
  { id: "WSTG-INFO-05", name: "ContentLeakageSubagent", title: "Review Webpage Content for Information Leakage", objective: "Audit HTML source code, comments, inline scripts, JavaScript bundles, source maps (.map), dan exposed configs (.git, .env)." },
  { id: "WSTG-INFO-06", name: "EntryPointsSubagent", title: "Identify Application Entry Points", objective: "Memetakan attack surface: URL routes, parameters, REST/GraphQL documentation (Swagger/OpenAPI), dan testing HTTP dangerous methods." },
  { id: "WSTG-INFO-07", name: "ExecutionPathsSubagent", title: "Map Execution Paths Through Application", objective: "Memetakan alur logika aplikasi, user journeys, transisi state (state machine), step-skipping protections, dan webhook callbacks." },
  { id: "WSTG-INFO-08", name: "FrameworkFingerprintSubagent", title: "Fingerprint Web Application Framework", objective: "Identifikasi framework web yang digunakan (Next.js, Spring Boot, Laravel, Django, Express) serta audit debug routes (/actuator, /_ignition)." },
  { id: "WSTG-INFO-09", name: "AppFingerprintSubagent", title: "Fingerprint Web Application", objective: "Identifikasi COTS & CMS (WordPress, Drupal, Joomla, Ghost, Strapi) serta evaluasi file dokumentasi bawaan dan user enumeration." },
  { id: "WSTG-INFO-10", name: "ArchitectureMapSubagent", title: "Map Application Architecture", objective: "Petakan topologi arsitektur infrastruktur: Web Application Firewall (WAF), Reverse Proxy, Load Balancer, CDN, dan IP leakage." },
];

// --- DOM ELEMENTS: NAVIGATION & TABS ---
const tabReconBtn = document.getElementById("tabReconBtn");
const tabWstgBtn = document.getElementById("tabWstgBtn");
const reconView = document.getElementById("reconView");
const wstgView = document.getElementById("wstgView");
const scanForm = document.getElementById("scanForm");
const wstgForm = document.getElementById("wstgForm");

// --- DOM ELEMENTS: RECON VIEW ---
const domainInput = document.getElementById("domainInput");
const concurrencyInput = document.getElementById("concurrencyInput");
const startBtn = document.getElementById("startBtn");
const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");
const timerDisplay = document.getElementById("timerDisplay");

const metricSubdomains = document.getElementById("metricSubdomains");
const metricAlive = document.getElementById("metricAlive");
const metricHttp = document.getElementById("metricHttp");
const metricAnomalies = document.getElementById("metricAnomalies");

const pipelineStepper = document.getElementById("pipelineStepper");
const activeToolName = document.getElementById("activeToolName");
const activeToolProgress = document.getElementById("activeToolProgress");
const toolProgressBar = document.getElementById("toolProgressBar");
const activeToolItem = document.getElementById("activeToolItem");

const terminalStream = document.getElementById("terminalStream");
const clearLogsBtn = document.getElementById("clearLogsBtn");
const assetsTableBody = document.getElementById("assetsTableBody");
const assetFilter = document.getElementById("assetFilter");

const reportContainer = document.getElementById("reportContainer");
const copyReportBtn = document.getElementById("copyReportBtn");
const downloadReportBtn = document.getElementById("downloadReportBtn");

// --- DOM ELEMENTS: WSTG VIEW ---
const wstgUrlInput = document.getElementById("wstgUrlInput");
const wstgConcurrencyInput = document.getElementById("wstgConcurrencyInput");
const wstgStartBtn = document.getElementById("wstgStartBtn");
const wstgStatusBadge = document.getElementById("wstgStatusBadge");
const wstgStatusText = document.getElementById("wstgStatusText");
const wstgTimerDisplay = document.getElementById("wstgTimerDisplay");

const wstgMetricTotal = document.getElementById("wstgMetricTotal");
const wstgMetricPass = document.getElementById("wstgMetricPass");
const wstgMetricFail = document.getElementById("wstgMetricFail");
const wstgMetricReview = document.getElementById("wstgMetricReview");

const wstgChecklistContainer = document.getElementById("wstgChecklistContainer");
const wstgTerminalStream = document.getElementById("wstgTerminalStream");
const wstgClearLogsBtn = document.getElementById("wstgClearLogsBtn");
const findingsContainer = document.getElementById("findingsContainer");
const findingsCountBadge = document.getElementById("findingsCountBadge");

const wstgReportContainer = document.getElementById("wstgReportContainer");
const wstgCopyReportBtn = document.getElementById("wstgCopyReportBtn");
const wstgDownloadReportBtn = document.getElementById("wstgDownloadReportBtn");

// Modal
const checklistModal = document.getElementById("checklistModal");
const modalIdBadge = document.getElementById("modalIdBadge");
const modalTitle = document.getElementById("modalTitle");
const modalBody = document.getElementById("modalBody");
const modalCloseBtn = document.getElementById("modalCloseBtn");

// --- TAB SWITCHING ---
tabReconBtn.addEventListener("click", () => {
  tabReconBtn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold font-mono transition-all bg-emerald-500 text-slate-950 shadow-[0_0_12px_rgba(16,185,129,0.3)] cursor-pointer";
  tabWstgBtn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold font-mono transition-all text-slate-400 hover:text-white cursor-pointer";
  
  scanForm.classList.remove("hidden");
  scanForm.classList.add("flex");
  wstgForm.classList.add("hidden");
  wstgForm.classList.remove("flex");

  reconView.classList.remove("hidden");
  reconView.classList.add("flex");
  wstgView.classList.add("hidden");
  wstgView.classList.remove("flex");
});

tabWstgBtn.addEventListener("click", () => {
  tabWstgBtn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold font-mono transition-all bg-cyan-500 text-slate-950 shadow-[0_0_12px_rgba(6,182,212,0.3)] cursor-pointer";
  tabReconBtn.className = "flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold font-mono transition-all text-slate-400 hover:text-white cursor-pointer";
  
  wstgForm.classList.remove("hidden");
  wstgForm.classList.add("flex");
  scanForm.classList.add("hidden");
  scanForm.classList.remove("flex");

  wstgView.classList.remove("hidden");
  wstgView.classList.add("flex");
  reconView.classList.add("hidden");
  reconView.classList.remove("flex");
});

// Helper: Format Time Duration
function formatDuration(ms) {
  const secs = Math.floor(ms / 1000);
  const m = Math.floor(secs / 60).toString().padStart(2, "0");
  const s = (secs % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ==========================================
// 1. DOMAIN RECON FUNCTIONALITY
// ==========================================

function startReconTimer() {
  reconTimerStart = Date.now();
  clearInterval(reconTimerInterval);
  reconTimerInterval = setInterval(() => {
    const elapsed = Date.now() - reconTimerStart;
    timerDisplay.textContent = `⏱️ ${formatDuration(elapsed)}`;
  }, 1000);
}

function stopReconTimer() {
  clearInterval(reconTimerInterval);
}

function setReconStatus(status, colorClass = "bg-slate-800 text-slate-400 border-slate-700", dotClass = "bg-slate-500") {
  statusBadge.className = `flex items-center gap-1.5 px-3 py-1.5 rounded-full border font-mono text-xs whitespace-nowrap ${colorClass}`;
  statusBadge.innerHTML = `<span class="w-2 h-2 rounded-full ${dotClass}"></span><span id="statusText">${status}</span>`;
}

function appendReconLog(lineHtml) {
  const div = document.createElement("div");
  div.className = "leading-relaxed break-words";
  div.innerHTML = lineHtml;
  terminalStream.appendChild(div);
  terminalStream.scrollTop = terminalStream.scrollHeight;
}

clearLogsBtn.addEventListener("click", () => {
  terminalStream.innerHTML = "";
});

function updateStepper(currentPhase) {
  const stepItems = pipelineStepper.querySelectorAll(".step-item");
  let foundCurrent = false;

  stepItems.forEach((el) => {
    const p = el.getAttribute("data-phase");
    if (p === currentPhase) {
      el.classList.add("active");
      el.classList.remove("completed");
      foundCurrent = true;
    } else if (!foundCurrent) {
      el.classList.remove("active");
      el.classList.add("completed");
      el.querySelector(".step-icon").innerHTML = "✓";
    } else {
      el.classList.remove("active", "completed");
    }
  });

  if (currentPhase === "COMPLETED") {
    stepItems.forEach((el) => {
      el.classList.remove("active");
      el.classList.add("completed");
      el.querySelector(".step-icon").innerHTML = "✓";
    });
  }
}

scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) return;

  const conc = Number(concurrencyInput.value) || 25;

  if (reconEventSource) reconEventSource.close();
  terminalStream.innerHTML = "";
  assetsTableBody.innerHTML = "";
  reportContainer.innerHTML = `<div class="text-slate-500 font-mono text-xs text-center py-12">Mengumpulkan telemetri &amp; memulai recon...</div>`;
  reconReportMarkdown = "";
  allAssets = [];

  metricSubdomains.textContent = "0";
  metricAlive.textContent = "0";
  metricHttp.textContent = "0";
  metricAnomalies.textContent = "0";

  setReconStatus("RECON RUNNING", "bg-emerald-950/60 text-emerald-400 border-emerald-800", "bg-emerald-400 animate-ping");
  startBtn.disabled = true;
  domainInput.disabled = true;
  startReconTimer();

  appendReconLog(`<span class="text-emerald-400 font-bold">[INIT]</span> Menyiapkan misi recon untuk domain: <span class="text-white underline">${domain}</span>`);

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        domain,
        dnsConcurrency: conc,
        httpConcurrency: Math.max(10, Math.floor(conc * 0.6)),
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Gagal memulai scan");

    currentScanId = data.scanId;
    connectReconEventStream(currentScanId);
  } catch (err) {
    appendReconLog(`<span class="text-red-400 font-bold">[ERROR]</span> ${err.message}`);
    setReconStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
    startBtn.disabled = false;
    domainInput.disabled = false;
    stopReconTimer();
  }
});

function connectReconEventStream(scanId) {
  reconEventSource = new EventSource(`/api/scan/${scanId}/stream`);

  reconEventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleReconEvent(data);
    } catch (e) {}
  };
}

function handleReconEvent(evt) {
  switch (evt.type) {
    case "snapshot":
      if (evt.report) {
        reconReportMarkdown = evt.report;
        reportContainer.innerHTML = marked.parse(reconReportMarkdown);
      }
      break;

    case "phase":
      updateStepper(evt.phase);
      appendReconLog(`<span class="text-indigo-400 font-semibold">&gt;&gt; PHASE:</span> <span class="text-slate-300 font-bold">${evt.message}</span>`);
      break;

    case "thought":
      appendReconLog(`<span class="text-blue-400 font-bold">[BRAIN]</span> <span class="text-blue-200/90">${evt.content}</span>`);
      break;

    case "tool_start":
      activeToolName.textContent = evt.tool;
      activeToolProgress.textContent = `0/${evt.targetCount}`;
      toolProgressBar.style.width = `0%`;
      activeToolItem.textContent = `Workers active: ${evt.concurrency}`;
      appendReconLog(`<span class="text-cyan-400 font-bold">[TOOL]</span> Eksekusi <span class="text-white">${evt.tool}</span> pada ${evt.targetCount} target`);
      break;

    case "tool_progress":
      const pct = Math.round((evt.completed / evt.total) * 100);
      activeToolProgress.textContent = `${evt.completed}/${evt.total} (${pct}%)`;
      toolProgressBar.style.width = `${pct}%`;
      activeToolItem.textContent = `Target: ${evt.current}`;
      break;

    case "asset_found":
      insertOrUpdateAssetRow(evt.asset);
      break;

    case "highlight":
      const color = evt.level === "CRITICAL" ? "text-red-400 bg-red-950/40 border-red-800" : "text-amber-400 bg-amber-950/40 border-amber-800";
      appendReconLog(`<div class="p-2 rounded border ${color} my-1 font-mono text-xs">
        <span class="font-bold">[ALERT: ${evt.title}]</span> ${evt.message}
      </div>`);
      break;

    case "metrics":
      metricSubdomains.textContent = evt.subdomainsTotal;
      metricAlive.textContent = evt.hostsAlive;
      metricHttp.textContent = evt.httpAlive;
      metricAnomalies.textContent = evt.anomalies;
      break;

    case "report_chunk":
      reconReportMarkdown += evt.delta;
      reportContainer.innerHTML = marked.parse(reconReportMarkdown);
      break;

    case "report_ready":
      reconReportMarkdown = evt.fullReport;
      reportContainer.innerHTML = marked.parse(reconReportMarkdown);
      break;

    case "done":
      stopReconTimer();
      setReconStatus("COMPLETED", "bg-emerald-950 text-emerald-400 border-emerald-800", "bg-emerald-400");
      startBtn.disabled = false;
      domainInput.disabled = false;
      updateStepper("COMPLETED");
      activeToolName.textContent = "Selesai";
      activeToolProgress.textContent = "100%";
      toolProgressBar.style.width = "100%";
      activeToolItem.textContent = `Total durasi: ${(evt.summary.durationMs / 1000).toFixed(1)}s`;
      appendReconLog(`<span class="text-emerald-400 font-bold">[COMPLETED]</span> Misi recon dituntaskan dalam ${(evt.summary.durationMs / 1000).toFixed(1)} detik.`);
      if (reconEventSource) reconEventSource.close();
      break;

    case "error":
      stopReconTimer();
      setReconStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
      startBtn.disabled = false;
      domainInput.disabled = false;
      appendReconLog(`<span class="text-red-400 font-bold">[FATAL]</span> ${evt.message}`);
      if (reconEventSource) reconEventSource.close();
      break;
  }
}

function insertOrUpdateAssetRow(asset) {
  const existingIdx = allAssets.findIndex((a) => a.fqdn === asset.fqdn);
  if (existingIdx >= 0) {
    allAssets[existingIdx] = { ...allAssets[existingIdx], ...asset };
  } else {
    allAssets.push(asset);
  }
  renderAssetsTable();
}

function renderAssetsTable() {
  const query = (assetFilter.value || "").trim().toLowerCase();
  const filtered = allAssets.filter((a) => {
    if (!query) return true;
    return (
      a.fqdn.toLowerCase().includes(query) ||
      (a.ip && a.ip.includes(query)) ||
      (a.httpTitle && a.httpTitle.toLowerCase().includes(query)) ||
      (a.server && a.server.toLowerCase().includes(query))
    );
  });

  if (filtered.length === 0) {
    assetsTableBody.innerHTML = `<tr><td colspan="3" class="px-4 py-8 text-center text-slate-600">Tidak ada aset cocok dengan filter.</td></tr>`;
    return;
  }

  filtered.sort((a, b) => {
    if (a.httpStatus && !b.httpStatus) return -1;
    if (!a.httpStatus && b.httpStatus) return 1;
    if (a.ip && !b.ip) return -1;
    if (!a.ip && b.ip) return 1;
    return a.fqdn.localeCompare(b.fqdn);
  });

  assetsTableBody.innerHTML = filtered
    .slice(0, 150)
    .map((a) => {
      let statusBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 border border-slate-700">DNS</span>`;
      if (a.httpStatus) {
        let badgeColor = "bg-slate-800 text-slate-300";
        if (a.httpStatus >= 200 && a.httpStatus < 300) badgeColor = "bg-emerald-950 text-emerald-300 border border-emerald-800";
        else if (a.httpStatus >= 300 && a.httpStatus < 400) badgeColor = "bg-cyan-950 text-cyan-300 border border-cyan-800";
        else if (a.httpStatus === 403 || a.httpStatus === 401) badgeColor = "bg-amber-950 text-amber-300 border border-amber-800";
        else if (a.httpStatus >= 400) badgeColor = "bg-red-950 text-red-300 border border-red-800";

        statusBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold ${badgeColor}">${a.httpStatus}</span>`;
      }

      const linkUrl = a.url || `https://${a.fqdn}`;
      const titleSnippet = a.httpTitle ? `<p class="text-[11px] text-slate-400 truncate max-w-[200px]">${escapeHtml(a.httpTitle)}</p>` : "";
      const techPills = (a.techs || []).slice(0, 2).map((t) => `<span class="text-[9px] px-1 rounded bg-slate-800 text-slate-400">${t}</span>`).join(" ");

      return `
        <tr class="hover:bg-[#13192c] transition">
          <td class="px-3 py-2.5 whitespace-nowrap">${statusBadge}</td>
          <td class="px-3 py-2.5">
            <a href="${linkUrl}" target="_blank" rel="noopener noreferrer" class="text-white hover:text-emerald-400 font-semibold truncate block max-w-[220px]">
              ${a.fqdn}
            </a>
            ${titleSnippet}
          </td>
          <td class="px-3 py-2.5 text-[11px] text-slate-400">
            <div>${a.ip || (a.cname ? `<span class="text-cyan-400">CNAME</span>` : "-")}</div>
            <div class="mt-0.5 flex gap-1 flex-wrap">${techPills}</div>
          </td>
        </tr>
      `;
    })
    .join("");
}

assetFilter.addEventListener("input", renderAssetsTable);

copyReportBtn.addEventListener("click", () => {
  if (!reconReportMarkdown) return;
  navigator.clipboard.writeText(reconReportMarkdown);
  const oldText = copyReportBtn.innerHTML;
  copyReportBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5"></i><span>Copied!</span>`;
  lucide.createIcons();
  setTimeout(() => {
    copyReportBtn.innerHTML = oldText;
    lucide.createIcons();
  }, 2000);
});

downloadReportBtn.addEventListener("click", () => {
  if (!reconReportMarkdown) return;
  const blob = new Blob([reconReportMarkdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `n4n4ku-recon-${domainInput.value || "report"}.md`;
  a.click();
  URL.revokeObjectURL(url);
});

// ==========================================
// 2. OWASP WSTG 4.2 AUDIT FUNCTIONALITY
// ==========================================

function startWstgTimer() {
  wstgTimerStart = Date.now();
  clearInterval(wstgTimerInterval);
  wstgTimerInterval = setInterval(() => {
    const elapsed = Date.now() - wstgTimerStart;
    wstgTimerDisplay.textContent = `⏱️ ${formatDuration(elapsed)}`;
  }, 1000);
}

function stopWstgTimer() {
  clearInterval(wstgTimerInterval);
}

function setWstgStatus(status, colorClass = "bg-slate-800 text-slate-400 border-slate-700", dotClass = "bg-slate-500") {
  wstgStatusBadge.className = `flex items-center gap-1.5 px-3 py-1.5 rounded-full border font-mono text-xs whitespace-nowrap ${colorClass}`;
  wstgStatusBadge.innerHTML = `<span class="w-2 h-2 rounded-full ${dotClass}"></span><span id="wstgStatusText">${status}</span>`;
}

function appendWstgLog(level, checklistId, message) {
  let badgeColor = "bg-slate-800 text-slate-400 border-slate-700";
  if (level === "PASS") badgeColor = "bg-emerald-950 text-emerald-400 border-emerald-800";
  else if (level === "FAIL") badgeColor = "bg-red-950 text-red-400 border-red-800";
  else if (level === "WARN") badgeColor = "bg-amber-950 text-amber-400 border-amber-800";
  else if (level === "INFO") badgeColor = "bg-cyan-950 text-cyan-400 border-cyan-800";

  const div = document.createElement("div");
  div.className = "leading-relaxed break-words font-mono text-xs py-0.5";
  div.innerHTML = `<span class="px-1.5 py-0.2 rounded border text-[10px] font-bold ${badgeColor}">${checklistId}</span> <span class="text-slate-300">${escapeHtml(message)}</span>`;
  wstgTerminalStream.appendChild(div);
  wstgTerminalStream.scrollTop = wstgTerminalStream.scrollHeight;
}

wstgClearLogsBtn.addEventListener("click", () => {
  wstgTerminalStream.innerHTML = "";
});

// Render Initial Checklist Cards
function initChecklistCards() {
  wstgChecklistContainer.innerHTML = CHECKLIST_METADATA.map((meta) => {
    return `
      <div id="card_${meta.id}" class="checklist-card bg-[#12182b] hover:bg-[#161e36] border border-[#1e263d] rounded-lg p-3 transition cursor-pointer" onclick="openChecklistModal('${meta.id}')">
        <div class="flex items-center justify-between gap-2">
          <div class="flex items-center gap-2">
            <span class="font-mono font-bold text-xs text-white">${meta.id}</span>
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">${meta.name}</span>
          </div>
          <div id="badge_${meta.id}" class="flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800/80 text-slate-400 border border-slate-700">
            <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
            <span>PENDING</span>
          </div>
        </div>
        <p class="text-xs text-slate-300 font-semibold mt-1">${meta.title}</p>
        <p id="summary_${meta.id}" class="text-[11px] text-slate-400 truncate mt-0.5">${meta.objective}</p>
        <div class="flex items-center justify-between mt-2 pt-2 border-t border-[#1e263d]/50 text-[10px] text-slate-500 font-mono">
          <span id="severity_${meta.id}">Severity: —</span>
          <span id="duration_${meta.id}">⏱️ 0ms</span>
        </div>
      </div>
    `;
  }).join("");
}

// Update Checklist Card on Start
function updateCardStart(checklistId, subAgent) {
  const card = document.getElementById(`card_${checklistId}`);
  const badge = document.getElementById(`badge_${checklistId}`);
  if (card && badge) {
    card.classList.add("border-cyan-500/50");
    badge.className = "flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800";
    badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span><span>RUNNING</span>`;
  }
}

// Update Checklist Card on Complete
function updateCardComplete(result) {
  allChecklistResults[result.id] = result;
  const card = document.getElementById(`card_${result.id}`);
  const badge = document.getElementById(`badge_${result.id}`);
  const summary = document.getElementById(`summary_${result.id}`);
  const severityEl = document.getElementById(`severity_${result.id}`);
  const durationEl = document.getElementById(`duration_${result.id}`);

  if (card && badge) {
    card.classList.remove("border-cyan-500/50");

    let badgeClass = "bg-slate-800 text-slate-400 border-slate-700";
    let dotClass = "bg-slate-400";
    if (result.status === "PASS") {
      badgeClass = "bg-emerald-950 text-emerald-300 border border-emerald-800";
      dotClass = "bg-emerald-400";
      card.classList.add("border-emerald-900/40");
    } else if (result.status === "FAIL") {
      badgeClass = "bg-red-950 text-red-300 border border-red-800";
      dotClass = "bg-red-400";
      card.classList.add("border-red-900/40");
    } else if (result.status === "REVIEW") {
      badgeClass = "bg-amber-950 text-amber-300 border border-amber-800";
      dotClass = "bg-amber-400";
      card.classList.add("border-amber-900/40");
    }

    badge.className = `flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-mono ${badgeClass}`;
    badge.innerHTML = `<span class="w-1.5 h-1.5 rounded-full ${dotClass}"></span><span>${result.status}</span>`;

    if (summary) summary.textContent = result.evidenceSummary || result.objective;
    if (severityEl) {
      let sevColor = "text-slate-400";
      if (result.severity === "CRITICAL") sevColor = "text-red-400 font-bold";
      else if (result.severity === "HIGH") sevColor = "text-orange-400 font-bold";
      else if (result.severity === "MEDIUM") sevColor = "text-amber-400";
      else if (result.severity === "LOW") sevColor = "text-yellow-400";
      severityEl.innerHTML = `Severity: <span class="${sevColor}">${result.severity}</span>`;
    }
    if (durationEl) durationEl.textContent = `⏱️ ${result.durationMs}ms`;
  }
}

// Render Findings Ledger
function renderFindings() {
  findingsCountBadge.textContent = `${allFindings.length} Items`;
  if (allFindings.length === 0) {
    findingsContainer.innerHTML = `<div class="text-slate-600 font-mono text-xs text-center py-12">Belum ada temuan berisiko.</div>`;
    return;
  }

  findingsContainer.innerHTML = allFindings.map((f) => {
    let sevBadge = "bg-slate-800 text-slate-300 border-slate-700";
    if (f.severity === "CRITICAL") sevBadge = "bg-red-950 text-red-300 border-red-800";
    else if (f.severity === "HIGH") sevBadge = "bg-orange-950 text-orange-300 border-orange-800";
    else if (f.severity === "MEDIUM") sevBadge = "bg-amber-950 text-amber-300 border-amber-800";
    else if (f.severity === "LOW") sevBadge = "bg-yellow-950 text-yellow-300 border-yellow-800";

    return `
      <div class="bg-[#12182b] border border-[#1e263d] rounded-lg p-3 font-mono text-xs space-y-1.5">
        <div class="flex items-center justify-between gap-2">
          <span class="px-1.5 py-0.5 rounded text-[10px] font-bold border ${sevBadge}">${f.severity}</span>
        </div>
        <p class="font-bold text-white leading-snug">${escapeHtml(f.title)}</p>
        <p class="text-[11px] text-slate-400 leading-relaxed">${escapeHtml(f.detail)}</p>
        ${f.evidence ? `<div class="p-1.5 rounded bg-black/40 border border-slate-800/80 text-[10px] text-cyan-300 truncate">${escapeHtml(f.evidence)}</div>` : ""}
      </div>
    `;
  }).join("");
}

// WSTG Form Submission
wstgForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = wstgUrlInput.value.trim();
  if (!url) return;

  const conc = Number(wstgConcurrencyInput.value) || 2;

  if (wstgEventSource) wstgEventSource.close();
  wstgTerminalStream.innerHTML = "";
  wstgReportContainer.innerHTML = `<div class="text-slate-500 font-mono text-xs text-center py-12">Menginisialisasi 10 sub-agent WSTG 4.2...</div>`;
  wstgReportMarkdown = "";
  allChecklistResults = {};
  allFindings = [];

  initChecklistCards();
  renderFindings();

  wstgMetricPass.textContent = "0";
  wstgMetricFail.textContent = "0";
  wstgMetricReview.textContent = "0";

  setWstgStatus("AUDIT RUNNING", "bg-cyan-950/60 text-cyan-400 border-cyan-800", "bg-cyan-400 animate-ping");
  wstgStartBtn.disabled = true;
  wstgUrlInput.disabled = true;
  startWstgTimer();

  appendWstgLog("INFO", "ORCHESTRATOR", `Memulai audit OWASP WSTG v4.2 Information Gathering pada: ${url}`);

  try {
    const res = await fetch("/api/wstg/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url,
        concurrency: conc,
      }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Gagal memulai audit WSTG");

    currentAuditId = data.auditId;
    connectWstgEventStream(currentAuditId);
  } catch (err) {
    appendWstgLog("FAIL", "ERROR", err.message);
    setWstgStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
    wstgStartBtn.disabled = false;
    wstgUrlInput.disabled = false;
    stopWstgTimer();
  }
});

function connectWstgEventStream(auditId) {
  wstgEventSource = new EventSource(`/api/wstg/audit/${auditId}/stream`);

  wstgEventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleWstgEvent(data);
    } catch (e) {}
  };
}

function handleWstgEvent(evt) {
  switch (evt.type) {
    case "snapshot":
      if (evt.results) {
        Object.values(evt.results).forEach((r) => updateCardComplete(r));
      }
      if (evt.findings) {
        allFindings = evt.findings;
        renderFindings();
      }
      if (evt.report) {
        wstgReportMarkdown = evt.report;
        wstgReportContainer.innerHTML = marked.parse(wstgReportMarkdown);
      }
      break;

    case "wstg_start":
      appendWstgLog("INFO", "INIT", `Audit dimulai untuk ${evt.targetUrl} (${evt.totalChecklists} checklist).`);
      break;

    case "subagent_start":
      updateCardStart(evt.checklistId, evt.subAgent);
      appendWstgLog("INFO", evt.checklistId, `[${evt.subAgent}] ${evt.objective}`);
      break;

    case "subagent_log":
      appendWstgLog(evt.level, evt.checklistId, evt.message);
      break;

    case "subagent_complete":
      updateCardComplete(evt.result);
      if (evt.result.findings && evt.result.findings.length > 0) {
        allFindings.push(...evt.result.findings);
        renderFindings();
      }
      appendWstgLog(
        evt.result.status === "PASS" ? "PASS" : "WARN",
        evt.result.id,
        `Selesai: ${evt.result.status} (${evt.result.severity}) dalam ${evt.result.durationMs}ms`
      );
      break;

    case "wstg_metrics":
      wstgMetricPass.textContent = evt.passCount;
      wstgMetricFail.textContent = evt.failCount;
      wstgMetricReview.textContent = evt.reviewCount;
      break;

    case "wstg_report_chunk":
      wstgReportMarkdown += evt.delta;
      wstgReportContainer.innerHTML = marked.parse(wstgReportMarkdown);
      break;

    case "wstg_report_ready":
      wstgReportMarkdown = evt.report;
      wstgReportContainer.innerHTML = marked.parse(wstgReportMarkdown);
      break;

    case "wstg_done":
      stopWstgTimer();
      setWstgStatus("COMPLETED", "bg-cyan-950 text-cyan-400 border-cyan-800", "bg-cyan-400");
      wstgStartBtn.disabled = false;
      wstgUrlInput.disabled = false;
      appendWstgLog("PASS", "COMPLETED", `Audit tuntas dalam ${(evt.summary.durationMs / 1000).toFixed(1)} detik. Laporan siap.`);
      if (wstgEventSource) wstgEventSource.close();
      break;

    case "wstg_error":
      stopWstgTimer();
      setWstgStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
      wstgStartBtn.disabled = false;
      wstgUrlInput.disabled = false;
      appendWstgLog("FAIL", "FATAL", evt.message);
      if (wstgEventSource) wstgEventSource.close();
      break;
  }
}

// Open Modal Details for a Checklist
window.openChecklistModal = function (checklistId) {
  const meta = CHECKLIST_METADATA.find((m) => m.id === checklistId);
  const result = allChecklistResults[checklistId];

  modalIdBadge.textContent = checklistId;
  modalTitle.textContent = meta ? meta.title : checklistId;

  if (!result) {
    modalBody.innerHTML = `
      <div class="space-y-3">
        <p class="text-slate-400"><strong class="text-white">Sub-Agent:</strong> ${meta ? meta.name : "-"}</p>
        <p class="text-slate-400"><strong class="text-white">Objective:</strong> ${meta ? meta.objective : "-"}</p>
        <div class="p-3 rounded bg-slate-900 border border-slate-800 text-slate-500">
          Checklist ini belum selesai dieksekusi atau masih berstatus PENDING.
        </div>
      </div>
    `;
  } else {
    let findingsHtml = "";
    if (result.findings && result.findings.length > 0) {
      findingsHtml = result.findings
        .map(
          (f) => `
          <div class="p-3 rounded-lg bg-[#161e36] border border-[#232c47] space-y-1.5 my-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-white">${escapeHtml(f.title)}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-amber-300 border border-slate-700">${f.severity}</span>
            </div>
            <p class="text-slate-300 text-[11px]">${escapeHtml(f.detail)}</p>
            ${f.evidence ? `<div class="p-2 rounded bg-black/50 text-cyan-300 font-mono text-[10px] break-all">${escapeHtml(f.evidence)}</div>` : ""}
            <p class="text-emerald-400 text-[11px]"><strong>Rekomendasi:</strong> ${escapeHtml(f.recommendation)}</p>
          </div>
        `
        )
        .join("");
    } else {
      findingsHtml = `<p class="text-emerald-400 italic">✅ Tidak ditemukan kerentanan atau indikator kebocoran informasi.</p>`;
    }

    modalBody.innerHTML = `
      <div class="space-y-4">
        <!-- Subagent & Status Header -->
        <div class="flex items-center justify-between pb-2 border-b border-[#1e263d]">
          <div>
            <p class="text-slate-400"><strong class="text-white">Sub-Agent:</strong> ${escapeHtml(result.subAgentName)}</p>
            <p class="text-slate-400 mt-0.5"><strong class="text-white">Durasi:</strong> ${result.durationMs}ms</p>
          </div>
          <span class="px-2.5 py-1 rounded text-xs font-bold ${
            result.status === "PASS"
              ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
              : result.status === "FAIL"
              ? "bg-red-950 text-red-300 border border-red-800"
              : "bg-amber-950 text-amber-300 border border-amber-800"
          }">${result.status} (${result.severity})</span>
        </div>

        <!-- Objective -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1">Objektif OWASP WSTG v4.2:</h4>
          <p class="text-slate-300 leading-relaxed">${escapeHtml(result.objective)}</p>
        </div>

        <!-- Tools Used -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1.5">Tools yang Digunakan:</h4>
          <div class="flex flex-wrap gap-1.5">
            ${(result.toolsUsed || ["curl", "httpx"]).map((t) => `<span class="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px] font-mono">${escapeHtml(t)}</span>`).join("")}
          </div>
        </div>

        <!-- Kalimat Verifikasi Berdasarkan Objective -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1">Kalimat Verifikasi (Objective-Based):</h4>
          <div class="p-3 rounded-lg bg-[#0a0e19] border border-[#1e263d] text-emerald-300 leading-relaxed whitespace-pre-line font-mono text-[11px]">
            ${escapeHtml(result.verificationStatement || "Verifikasi berhasil diselesaikan.")}
          </div>
        </div>

        <!-- Analisis False Positive -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1 flex items-center gap-1.5">
            <span>Analisis &amp; Penapisan False Positive:</span>
          </h4>
          <div class="p-2.5 rounded bg-[#12182b] border border-[#232c47] text-cyan-300/90 text-[11px] leading-relaxed">
            🛡️ ${escapeHtml(result.falsePositiveAnalysis || "Pemeriksaan false positive selesai.")}
          </div>
        </div>

        <!-- Findings List -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1">Daftar Temuan (${(result.findings || []).length}):</h4>
          ${findingsHtml}
        </div>

        <!-- Raw Probe Output -->
        <div>
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1">Raw Probe Output (HTTP Transcripts):</h4>
          <pre class="p-3 rounded-lg bg-[#080c16] border border-[#1e263d] text-slate-300 font-mono text-[10px] overflow-x-auto max-h-48 scrollbar-thin select-all">${escapeHtml(result.rawOutput || "Tidak ada raw probe tercatat.")}</pre>
        </div>

        <!-- Rekomendasi Remediasi -->
        <div class="pt-2 border-t border-[#1e263d]">
          <h4 class="font-bold text-xs uppercase tracking-wider text-slate-400 mb-1">Rekomendasi Remediasi Taktis:</h4>
          <p class="text-slate-300 leading-relaxed">${escapeHtml(result.recommendation)}</p>
        </div>
      </div>
    `;
  }

  checklistModal.classList.remove("hidden");
};

modalCloseBtn.addEventListener("click", () => {
  checklistModal.classList.add("hidden");
});

checklistModal.addEventListener("click", (e) => {
  if (e.target === checklistModal) {
    checklistModal.classList.add("hidden");
  }
});

wstgCopyReportBtn.addEventListener("click", () => {
  if (!wstgReportMarkdown) return;
  navigator.clipboard.writeText(wstgReportMarkdown);
  const oldText = wstgCopyReportBtn.innerHTML;
  wstgCopyReportBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5"></i><span>Copied!</span>`;
  lucide.createIcons();
  setTimeout(() => {
    wstgCopyReportBtn.innerHTML = oldText;
    lucide.createIcons();
  }, 2000);
});

wstgDownloadReportBtn.addEventListener("click", () => {
  if (!wstgReportMarkdown) return;
  const blob = new Blob([wstgReportMarkdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `OWASP-WSTG-4.2-Audit-${wstgUrlInput.value.replace(/[^a-zA-Z0-9]/g, "_") || "report"}.md`;
  a.click();
  URL.revokeObjectURL(url);
});

// Initialize on page load
initChecklistCards();
