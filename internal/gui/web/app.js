"use strict";

const token = new URLSearchParams(location.search).get("t") || "";
const $ = (id) => document.getElementById(id);
let info = { nativeDialogs: false };
let currentReport = null;
let pollTimer = null;

const STATUS = {
  encrypted: { label: "Verschlüsselt", icon: "lock" },
  clearkey: { label: "Clear Key – ungeschützt", icon: "key" },
  partial: { label: "Teilweise verschlüsselt", icon: "half" },
  suspected: { label: "Vermutlich verschlüsselt", icon: "question" },
  plain: { label: "Nicht verschlüsselt", icon: "unlock" },
  empty: { label: "Leer", icon: "empty" },
  unknown: { label: "Unbekannt", icon: "question" },
};

const ICONS = {
  lock: '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  unlock: '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/></svg>',
  key: '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L20 3M16 7l3 3M14 9l2 2"/></svg>',
  half: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 3v18" /><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"/></svg>',
  question: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.6.3-1 .9-1 1.6V14M12 17.5v.01"/></svg>',
  empty: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" stroke-dasharray="3 3"/></svg>',
  chev: '<svg viewBox="0 0 24 24" class="chev"><path d="M6 9l6 6 6-6"/></svg>',
};

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function humanSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 2 : 1).replace(".", ",") + " " + u[i];
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Token": token, "Content-Type": "application/json", ...(opts.headers || {}) } });
  return res.json();
}

function show(view) {
  for (const v of ["viewStart", "viewProgress", "viewResult"]) $(v).hidden = v !== view;
  window.scrollTo(0, 0);
}

function toast(msg, ms = 3500) {
  const t = $("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), ms);
}

/* ---------- Theme ---------- */
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
try { applyTheme(localStorage.getItem("theme")); } catch (e) {}
$("themeBtn").onclick = () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("theme", next); } catch (e) {}
};

/* ---------- Zuletzt verwendet ---------- */
function loadRecent() {
  try { return JSON.parse(localStorage.getItem("recent") || "[]"); } catch (e) { return []; }
}
function saveRecent(path, status) {
  let r = loadRecent().filter((x) => x.path !== path);
  r.unshift({ path, status, at: Date.now() });
  r = r.slice(0, 6);
  try { localStorage.setItem("recent", JSON.stringify(r)); } catch (e) {}
}
function renderRecent() {
  const r = loadRecent();
  $("recentBox").hidden = r.length === 0;
  $("recentList").innerHTML = r.map((x, i) => `
    <li><button type="button" data-i="${i}">
      <span class="r-path" title="${esc(x.path)}">${esc(x.path)}</span>
      <span class="badge s-${esc(x.status)}" style="background:color-mix(in srgb,var(--c) 14%,transparent)">${esc(STATUS[x.status]?.label || "")}</span>
    </button></li>`).join("");
  $("recentList").querySelectorAll("button").forEach((b) => {
    b.onclick = () => { $("pathInput").value = r[+b.dataset.i].path; startAnalysis(); };
  });
}

/* ---------- Start ---------- */
$("browseBtn").onclick = async () => {
  if (!info.nativeDialogs) { $("pathInput").focus(); toast("Bitte den Pfad zum Image eingeben."); return; }
  const r = await api("/api/browse", { method: "POST" });
  if (r.error) { showStartError(r.error); return; }
  if (r.path) { $("pathInput").value = r.path; startAnalysis(); }
};
$("analyzeBtn").onclick = () => startAnalysis();
$("pathInput").addEventListener("keydown", (e) => { if (e.key === "Enter") startAnalysis(); });
$("newBtn").onclick = () => { renderRecent(); show("viewStart"); };
$("cancelBtn").onclick = () => api("/api/cancel", { method: "POST" });

// Drag & Drop in das Fenster liefert keinen Dateipfad – Navigation verhindern.
["dragover", "drop"].forEach((ev) => window.addEventListener(ev, (e) => {
  e.preventDefault();
  if (ev === "drop") toast("Bitte „Image auswählen …“ verwenden oder das Image direkt auf EncDetect.exe ziehen.", 5000);
}));

function showStartError(msg) {
  const e = $("startError");
  e.textContent = msg;
  e.hidden = !msg;
}

async function startAnalysis() {
  const path = $("pathInput").value.trim().replace(/^"+|"+$/g, "");
  showStartError("");
  if (!path) { showStartError("Bitte zuerst ein Image auswählen."); return; }
  const r = await api("/api/analyze", { method: "POST", body: JSON.stringify({ path }) });
  if (r.error) { showStartError(r.error); show("viewStart"); return; }
  $("progressFile").textContent = path;
  $("progressMsg").textContent = "Image wird geöffnet …";
  $("progressBar").style.width = "2%";
  show("viewProgress");
  poll(path);
}

function poll(path) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    let s;
    try { s = await api("/api/status"); } catch (e) { poll(path); return; }
    if (s.error) { show("viewStart"); showStartError(s.error); return; }
    $("progressMsg").textContent = s.message || "";
    $("progressBar").style.width = Math.max(2, Math.round((s.progress || 0) * 100)) + "%";
    if (s.running || !s.report) { poll(path); return; }
    currentReport = s.report;
    saveRecent(path, s.report.overall);
    renderReport(s.report);
    show("viewResult");
  }, 150);
}

/* ---------- Ergebnis ---------- */
function kvRows(list, cls = "") {
  return (list || []).map((d) => {
    let rowCls = "";
    if (/Clear Key geprüft/.test(d.key)) rowCls = "highlight-row";
    if (/FVEK|UUID|GUID/.test(d.key)) rowCls += " key-row";
    return `<div class="${rowCls}" style="display:contents"><dt>${esc(d.key)}</dt><dd class="${cls}">${esc(d.value)}</dd></div>`;
  }).join("");
}

function badge(status) {
  const s = STATUS[status] || STATUS.unknown;
  return `<span class="badge s-${status}" style="background:color-mix(in srgb,var(--c) 14%,transparent)">${ICONS[s.icon]}${esc(s.label)}</span>`;
}

function entropySvg(e) {
  const p = e.profile || [];
  if (p.length < 2) return "";
  const w = 600, h = 70;
  const pts = p.map((v, i) => `${(i / (p.length - 1)) * w},${h - (v / 8) * (h - 6) - 3}`).join(" ");
  return `<div class="entropy">
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" role="img" aria-label="Entropieverlauf">
      <rect x="0" y="0" width="${w}" height="${h}" rx="8" fill="var(--bg2)"/>
      <line x1="0" x2="${w}" y1="${h - (7.9 / 8) * (h - 6) - 3}" y2="${h - (7.9 / 8) * (h - 6) - 3}" stroke="var(--c)" stroke-opacity=".35" stroke-dasharray="4 4" stroke-width="1"/>
      <polyline points="${pts}" fill="none" stroke="var(--c)" stroke-width="1.8" vector-effect="non-scaling-stroke"/>
    </svg>
    <div class="ent-caption">Entropieverlauf über das Volume (0–8 Bit/Byte, gestrichelt: Schwelle für Zufallsdaten) · Ø ${e.avgEntropy.toFixed(3).replace(".", ",")} Bit/Byte · ${e.randomBlocks} von ${e.samples - e.zeroBlocks} Datenstichproben zufällig · ${e.zeroBlocks} leer</div>
  </div>`;
}

function renderReport(r) {
  const st = STATUS[r.overall] || STATUS.unknown;
  const v = $("verdict");
  v.className = `verdict card s-${r.overall}`;
  v.style.background = "";
  v.innerHTML = `
    <div class="verdict-icon">${ICONS[st.icon]}</div>
    <div>
      <h2>${esc(r.overallText)}</h2>
      <p>${esc(r.overallSummary)}</p>
      <div class="file">${esc(r.path)}</div>
    </div>`;

  const imgInfo = [
    { key: "Datei", value: r.fileName },
    { key: "Format", value: r.format },
    { key: "Größe", value: `${humanSize(r.size)} (${r.size.toLocaleString("de-DE")} Bytes)` },
    { key: "Partitionsschema", value: r.partitionScheme },
    ...(r.meta || []).filter((m) => m.key !== "Datei"),
  ];
  $("imageInfo").innerHTML = kvRows(imgInfo);

  // Datenträger-Karte
  const total = r.volumes.reduce((a, x) => a + x.size, 0) || 1;
  $("diskMap").innerHTML = r.volumes.map((x) => {
    const pct = Math.max(2, (x.size / total) * 100);
    return `<button class="seg s-${x.status}" style="flex:${pct} 1 0" title="${esc(x.label)}: ${esc(x.statusText)} – ${esc(x.scheme)} (${humanSize(x.size)})" data-vol="${x.index}">${x.index}</button>`;
  }).join("");
  const used = [...new Set(r.volumes.map((x) => x.status))];
  $("legend").innerHTML = used.map((s) => `<span><i class="dot s-${s}"></i>${esc(STATUS[s]?.label || s)}</span>`).join("");
  $("diskNotes").innerHTML =
    (r.diskNotes || []).map((n) => `<div class="disknote">${esc(n)}</div>`).join("") +
    (r.warnings || []).map((n) => `<div class="disknote warn">${esc(n)}</div>`).join("");
  $("diskMap").querySelectorAll(".seg").forEach((b) => {
    b.onclick = () => {
      const el = document.querySelector(`.volume[data-vol="${b.dataset.vol}"]`);
      el.classList.add("open");
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    };
  });

  // Volumes
  const interesting = (s) => ["encrypted", "clearkey", "partial", "suspected"].includes(s);
  $("volumes").innerHTML = r.volumes.map((x) => `
    <div class="card volume s-${x.status} ${interesting(x.status) || r.volumes.length === 1 ? "open" : ""}" data-vol="${x.index}" style="background:var(--card)">
      <div class="vol-head">
        <div class="vol-num">${x.index}</div>
        <div class="vol-main">
          <div class="vol-title"><h3>${esc(x.scheme || x.label)}</h3>${badge(x.status)}</div>
          <div class="vol-meta">${esc(x.label)}${x.partName ? " „" + esc(x.partName) + "“" : ""} · ${humanSize(x.size)} · Offset ${x.offset.toLocaleString("de-DE")} · ${esc(x.partType || "")}</div>
          <div class="vol-summary">${esc(x.summary)}</div>
        </div>
        <div class="vol-side">
          ${x.algorithm ? `<div class="algo-label">Algorithmus</div><div class="algo">${esc(x.algorithm)}</div>` : ""}
          <div class="conf">Konfidenz ${x.confidence} %<div class="conf-bar"><i style="width:${x.confidence}%"></i></div></div>
          ${ICONS.chev}
        </div>
      </div>
      <div class="vol-body">
        ${x.details && x.details.length ? `<dl class="kv">${kvRows(x.details)}</dl>` : ""}
        ${(x.sub || []).map((s) => `
          <div class="sub s-${s.status}" style="background:var(--bg)">
            <div class="sub-head">${esc(s.name)} ${badge(s.status)}</div>
            <div style="margin-top:4px">${esc(s.summary)}</div>
            ${s.details && s.details.length ? `<dl class="kv">${kvRows(s.details)}</dl>` : ""}
          </div>`).join("")}
        ${x.entropy ? entropySvg(x.entropy) : ""}
        ${x.notes && x.notes.length ? `<ul class="notes">${x.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : ""}
      </div>
    </div>`).join("");
  $("volumes").querySelectorAll(".vol-head").forEach((h) => {
    h.onclick = () => h.parentElement.classList.toggle("open");
  });
  $("footerNote").textContent = `EncDetect ${r.version} · Analyse in ${r.durationMs} ms · ${new Date(r.started).toLocaleString("de-DE")} · Das Image wurde nur lesend geöffnet.`;
}

document.querySelectorAll("[data-export]").forEach((b) => {
  b.onclick = async () => {
    const fmt = b.dataset.export;
    if (!info.nativeDialogs) {
      location.href = `/api/download?format=${fmt}&t=${encodeURIComponent(token)}`;
      return;
    }
    const r = await api(`/api/export?format=${fmt}`, { method: "POST" });
    if (r.error) toast("Fehler: " + r.error, 6000);
    else if (r.saved) toast("Gespeichert: " + r.saved, 5000);
  };
});

/* ---------- Init ---------- */
(async () => {
  try {
    info = await api("/api/info");
  } catch (e) {
    showStartError("Verbindung zum Analyse-Dienst fehlgeschlagen.");
    return;
  }
  $("version").textContent = "Version " + info.version;
  if (!info.nativeDialogs) {
    $("browseBtn").querySelector(".drop-main").textContent = "Pfad zum Image unten eingeben";
  }
  renderRecent();
  if (info.initialPath) {
    $("pathInput").value = info.initialPath;
    startAnalysis();
  }
  // Lebenszeichen für den Browser-Modus
  setInterval(() => api("/api/info").catch(() => {}), 20000);
})();
