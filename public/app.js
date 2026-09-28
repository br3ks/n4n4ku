// Initialize Lucide Icons
lucide.createIcons();

let currentScanId = null;
let eventSource = null;
let timerInterval = null;
let timerStart = null;
let fullReportMarkdown = "";
let allAssets = [];

// DOM Elements
const scanForm = document.getElementById("scanForm");
const domainInput = document.getElementById("domainInput");
const concurrencyInput = document.getElementById("concurrencyInput");
const startBtn = document.getElementById("startBtn");
const statusBadge = document.getElementById("statusBadge");
const statusText = document.getElementById("statusText");
const timerDisplay = document.getElementById("timerDisplay");

// Metrics
const metricSubdomains = document.getElementById("metricSubdomains");
const metricAlive = document.getElementById("metricAlive");
const metricHttp = document.getElementById("metricHttp");
const metricAnomalies = document.getElementById("metricAnomalies");

// Telemetry & Stepper
const pipelineStepper = document.getElementById("pipelineStepper");
const activeToolName = document.getElementById("activeToolName");
const activeToolProgress = document.getElementById("activeToolProgress");
const toolProgressBar = document.getElementById("toolProgressBar");
const activeToolItem = document.getElementById("activeToolItem");

// Terminal & Assets
const terminalStream = document.getElementById("terminalStream");
const clearLogsBtn = document.getElementById("clearLogsBtn");
const assetsTableBody = document.getElementById("assetsTableBody");
const assetFilter = document.getElementById("assetFilter");

// Report
const reportContainer = document.getElementById("reportContainer");
const copyReportBtn = document.getElementById("copyReportBtn");
const downloadReportBtn = document.getElementById("downloadReportBtn");

// Helper: Format Time
function formatDuration(ms) {
  const secs = Math.floor(ms / 1000);
  const m = Math.floor(secs / 60).toString().padStart(2, "0");
  const s = (secs % 60).toString().padStart(2, "0");
  return `${m}:${s}`;
}

// Timer Functions
function startTimer() {
  timerStart = Date.now();
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const elapsed = Date.now() - timerStart;
    timerDisplay.textContent = `⏱️ ${formatDuration(elapsed)}`;
  }, 1000);
}

function stopTimer() {
  clearInterval(timerInterval);
}

// Status Badge Helper
function setStatus(status, colorClass = "bg-slate-800 text-slate-400 border-slate-700", dotClass = "bg-slate-500") {
  statusBadge.className = `flex items-center gap-1.5 px-3 py-1.5 rounded-full border ${colorClass}`;
  statusBadge.innerHTML = `<span class="w-2 h-2 rounded-full ${dotClass}"></span><span id="statusText">${status}</span>`;
}

// Terminal Log Helper
function appendLog(lineHtml) {
  const div = document.createElement("div");
  div.className = "leading-relaxed break-words";
  div.innerHTML = lineHtml;
  terminalStream.appendChild(div);
  terminalStream.scrollTop = terminalStream.scrollHeight;
}

// Clear Terminal
clearLogsBtn.addEventListener("click", () => {
  terminalStream.innerHTML = "";
});

// Stepper Phase Helper
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

// Form Submission
scanForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const domain = domainInput.value.trim();
  if (!domain) return;

  const conc = Number(concurrencyInput.value) || 25;

  // Reset UI
  if (eventSource) eventSource.close();
  terminalStream.innerHTML = "";
  assetsTableBody.innerHTML = "";
  reportContainer.innerHTML = `<div class="text-slate-500 font-mono text-xs text-center py-12">Mengumpulkan telemetri &amp; memulai recon...</div>`;
  fullReportMarkdown = "";
  allAssets = [];

  metricSubdomains.textContent = "0";
  metricAlive.textContent = "0";
  metricHttp.textContent = "0";
  metricAnomalies.textContent = "0";

  setStatus("RECON RUNNING", "bg-emerald-950/60 text-emerald-400 border-emerald-800", "bg-emerald-400 animate-ping");
  startBtn.disabled = true;
  domainInput.disabled = true;
  startTimer();

  appendLog(`<span class="text-emerald-400 font-bold">[INIT]</span> Menyiapkan misi recon untuk domain: <span class="text-white underline">${domain}</span>`);

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
    if (!res.ok) {
      throw new Error(data.error || "Gagal memulai scan");
    }

    currentScanId = data.scanId;
    connectEventStream(currentScanId);
  } catch (err) {
    appendLog(`<span class="text-red-400 font-bold">[ERROR]</span> ${err.message}`);
    setStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
    startBtn.disabled = false;
    domainInput.disabled = false;
    stopTimer();
  }
});

// Connect Server-Sent Events
function connectEventStream(scanId) {
  eventSource = new EventSource(`/api/scan/${scanId}/stream`);

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      handleServerEvent(data);
    } catch (e) {
      // Ignored heartbeat
    }
  };

  eventSource.onerror = () => {
    // Network reconnect automatically
  };
}

// Event Dispatcher
function handleServerEvent(evt) {
  switch (evt.type) {
    case "snapshot":
      if (evt.report) {
        fullReportMarkdown = evt.report;
        reportContainer.innerHTML = marked.parse(fullReportMarkdown);
      }
      break;

    case "phase":
      updateStepper(evt.phase);
      appendLog(`<span class="text-indigo-400 font-semibold">&gt;&gt; PHASE:</span> <span class="text-slate-300 font-bold">${evt.message}</span>`);
      break;

    case "thought":
      appendLog(`<span class="text-blue-400 font-bold">[BRAIN]</span> <span class="text-blue-200/90">${evt.content}</span>`);
      break;

    case "tool_start":
      activeToolName.textContent = evt.tool;
      activeToolProgress.textContent = `0/${evt.targetCount}`;
      toolProgressBar.style.width = `0%`;
      activeToolItem.textContent = `Workers active: ${evt.concurrency}`;
      appendLog(`<span class="text-cyan-400 font-bold">[TOOL]</span> Eksekusi <span class="text-white">${evt.tool}</span> pada ${evt.targetCount} target (konkurensi: ${evt.concurrency})`);
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
      appendLog(`<div class="p-2 rounded border ${color} my-1">
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
      fullReportMarkdown += evt.delta;
      reportContainer.innerHTML = marked.parse(fullReportMarkdown);
      break;

    case "report_ready":
      fullReportMarkdown = evt.fullReport;
      reportContainer.innerHTML = marked.parse(fullReportMarkdown);
      break;

    case "done":
      stopTimer();
      setStatus("COMPLETED", "bg-emerald-950 text-emerald-400 border-emerald-800", "bg-emerald-400");
      startBtn.disabled = false;
      domainInput.disabled = false;
      updateStepper("COMPLETED");
      activeToolName.textContent = "Selesai";
      activeToolProgress.textContent = "100%";
      toolProgressBar.style.width = "100%";
      activeToolItem.textContent = `Total durasi: ${(evt.summary.durationMs / 1000).toFixed(1)}s`;
      appendLog(`<span class="text-emerald-400 font-bold">[COMPLETED]</span> Misi recon berhasil dituntaskan dalam ${(evt.summary.durationMs / 1000).toFixed(1)} detik.`);
      if (eventSource) eventSource.close();
      break;

    case "error":
      stopTimer();
      setStatus("FAILED", "bg-red-950 text-red-400 border-red-800", "bg-red-400");
      startBtn.disabled = false;
      domainInput.disabled = false;
      appendLog(`<span class="text-red-400 font-bold">[FATAL]</span> ${evt.message}`);
      if (eventSource) eventSource.close();
      break;
  }
}

// Insert / Update Asset Row in Matrix Table
function insertOrUpdateAssetRow(asset) {
  const existingIdx = allAssets.findIndex((a) => a.fqdn === asset.fqdn);
  if (existingIdx >= 0) {
    allAssets[existingIdx] = { ...allAssets[existingIdx], ...asset };
  } else {
    allAssets.push(asset);
  }
  renderAssetsTable();
}

// Render Asset Matrix Table
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

  // Sort: alive HTTP first, then resolved IP, then unresolved
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

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

assetFilter.addEventListener("input", renderAssetsTable);

// Copy & Download Markdown
copyReportBtn.addEventListener("click", () => {
  if (!fullReportMarkdown) return;
  navigator.clipboard.writeText(fullReportMarkdown);
  const oldText = copyReportBtn.innerHTML;
  copyReportBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5"></i><span>Copied!</span>`;
  lucide.createIcons();
  setTimeout(() => {
    copyReportBtn.innerHTML = oldText;
    lucide.createIcons();
  }, 2000);
});

downloadReportBtn.addEventListener("click", () => {
  if (!fullReportMarkdown) return;
  const blob = new Blob([fullReportMarkdown], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `n4n4ku-recon-${domainInput.value || "report"}.md`;
  a.click();
  URL.revokeObjectURL(url);
});
