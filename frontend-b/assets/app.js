/* ============================================================
   Shared app logic for Frontend Developer B's pages.
   No backend yet — everything here is mock data / local state,
   shaped to match the API contracts in the project brief so
   swapping in real fetch() calls later is a drop-in job.

   Real endpoints this file is written to plug into later:
     POST /email/upload        -> uploadEmail()
     POST /email/analyze       -> runAnalysis()
     GET  /report/:id          -> getReport()
     GET  /report/download/:id -> downloadReportPdf()
     GET  /history             -> listHistory()
     DELETE /history/:id       -> deleteHistoryItem()
     PUT  /settings            -> saveSettings()
   ============================================================ */

const VERDICTS = {
  safe:     { label: "Safe",     color: "var(--safe)",    class: "badge-safe" },
  spam:     { label: "Spam",     color: "var(--spam)",    class: "badge-spam" },
  phishing: { label: "Phishing", color: "var(--phish)",   class: "badge-phishing" },
  malware:  { label: "Malware",  color: "var(--malware)", class: "badge-malware" },
};

/* ---- Mock "database" (stands in for MongoDB collections) ---- */
const MOCK_HISTORY = [
  { id: "rpt_9042", subject: "Your PayPal account has been limited",       sender: "service@paypal-security.com", verdict: "phishing", risk: 91, confidence: 95, date: "2026-08-25T09:14:00" },
  { id: "rpt_9041", subject: "Q3 marketing budget — final numbers",        sender: "priya.raman@company.com",     verdict: "safe",     risk: 4,  confidence: 98, date: "2026-08-25T08:02:00" },
  { id: "rpt_9040", subject: "You have won! Claim your prize now",         sender: "promo@luckydraw-rewards.net", verdict: "spam",     risk: 58, confidence: 88, date: "2026-08-24T19:41:00" },
  { id: "rpt_9039", subject: "Invoice_2026_08.zip attached",               sender: "billing@invoice-secure-pay.com", verdict: "malware", risk: 97, confidence: 99, date: "2026-08-24T14:20:00" },
  { id: "rpt_9038", subject: "Team standup notes",                         sender: "manoj@company.com",           verdict: "safe",     risk: 2,  confidence: 99, date: "2026-08-23T10:05:00" },
  { id: "rpt_9037", subject: "Urgent: verify your mailbox in 24 hours",    sender: "it-helpdesk@mail-verify-now.com", verdict: "phishing", risk: 87, confidence: 93, date: "2026-08-22T16:30:00" },
];

const MOCK_REPORT = {
  id: "rpt_9042",
  subject: "Your PayPal account has been limited",
  sender: "service@paypal-security.com",
  receiver: "you@company.com",
  date: "2026-08-25T09:14:00",
  verdict: "phishing",
  risk: 91,
  confidence: 95,
  reasons: [
    { title: "SPF authentication failed", detail: "Sending domain does not authorize this mail server.", severity: "malware" },
    { title: "Urgent language detected", detail: "Body uses high-pressure phrasing (\"act now\", \"24 hours\").", severity: "phish" },
    { title: "Suspicious URL", detail: "Link domain was registered 2 days ago and mimics a known brand.", severity: "phish" },
    { title: "Lookalike domain", detail: "paypal-security.com is not an official PayPal domain.", severity: "spam" },
  ],
  iocs: [
    { type: "Domain", value: "paypal-security.com" },
    { type: "URL", value: "hxxp://paypal-security.com/verify-login" },
    { type: "IP", value: "185.212.44.19" },
  ],
  recommendations: ["Do not click any links in this email", "Block sender domain", "Report to security team", "Delete email"],
  body: "Dear Customer,\n\nWe have detected unusual activity on your account. Your access has been limited until you verify your identity. Click the link below within 24 hours to restore full access.\n\nVerify Now: hxxp://paypal-security.com/verify-login\n\nFailure to verify will result in permanent suspension.\n\nPayPal Security Team",
  links: ["hxxp://paypal-security.com/verify-login", "hxxp://bit.ly/3xJ9k2A"],
  attachments: [],
  headers: [
    ["Return-Path", "<bounce@paypal-security.com>"],
    ["Received-SPF", "fail (paypal-security.com)"],
    ["DKIM-Signature", "none"],
    ["X-Originating-IP", "185.212.44.19"],
  ],
  ips: ["185.212.44.19"],
};

/* ---- helpers ---- */
function verdictMeta(key) { return VERDICTS[key] || VERDICTS.safe; }

function badgeHtml(verdict) {
  const v = verdictMeta(verdict);
  return `<span class="badge ${v.class}">${v.label}</span>`;
}

function fmtDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " · " +
         d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

function riskColor(risk) {
  if (risk >= 80) return "var(--malware)";
  if (risk >= 50) return "var(--phish)";
  if (risk >= 25) return "var(--spam)";
  return "var(--safe)";
}

/* Draws the signature circular risk gauge into a container */
function renderGauge(containerEl, risk, size = 132) {
  const r = 52, c = 2 * Math.PI * r;
  const offset = c - (risk / 100) * c;
  const color = riskColor(risk);
  containerEl.innerHTML = `
    <div class="gauge" style="width:${size}px;height:${size}px;">
      <svg width="${size}" height="${size}" viewBox="0 0 120 120">
        <circle class="gauge-track" cx="60" cy="60" r="${r}"></circle>
        <circle class="gauge-fill" cx="60" cy="60" r="${r}"
          stroke="${color}"
          stroke-dasharray="${c}"
          stroke-dashoffset="${c}"></circle>
      </svg>
      <div class="gauge-num">
        <strong style="color:${color}">${risk}</strong>
        <span>Risk / 100</span>
      </div>
    </div>`;
  // animate after paint
  requestAnimationFrame(() => {
    const fill = containerEl.querySelector(".gauge-fill");
    requestAnimationFrame(() => { fill.style.strokeDashoffset = offset; });
  });
}

/* Toast notification (replaces alert()) */
function notify(message, tone = "signal") {
  let host = document.getElementById("toast-host");
  if (!host) {
    host = document.createElement("div");
    host.id = "toast-host";
    host.style.cssText = "position:fixed;bottom:20px;right:20px;display:flex;flex-direction:column;gap:8px;z-index:999;";
    document.body.appendChild(host);
  }
  const colors = { signal: "var(--signal)", safe: "var(--safe)", malware: "var(--malware)" };
  const t = document.createElement("div");
  t.style.cssText = `background:var(--panel-raised);border:1px solid var(--border);border-left:3px solid ${colors[tone] || colors.signal};color:var(--text-hi);padding:11px 15px;border-radius:8px;font-size:13px;box-shadow:0 8px 24px rgba(0,0,0,0.4);max-width:280px;`;
  t.textContent = message;
  host.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .3s"; setTimeout(() => t.remove(), 300); }, 3200);
}

/* Tabs wiring: any .tabs with data-tab-group + .tab-panel with matching data-panel */
function wireTabs(root = document) {
  root.querySelectorAll(".tabs").forEach(tabbar => {
    const group = tabbar.dataset.tabGroup;
    tabbar.querySelectorAll(".tab").forEach(tab => {
      tab.addEventListener("click", () => {
        tabbar.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
        tab.classList.add("active");
        document.querySelectorAll(`.tab-panel[data-group="${group}"]`).forEach(p => p.classList.remove("active"));
        document.querySelector(`.tab-panel[data-group="${group}"][data-panel="${tab.dataset.tab}"]`)?.classList.add("active");
      });
    });
  });
}

/* Dropzone wiring: pass element + callback(file) */
function wireDropzone(el, onFile) {
  const input = el.querySelector("input[type=file]");
  el.addEventListener("click", () => input?.click());
  input?.addEventListener("change", () => { if (input.files[0]) onFile(input.files[0]); });
  ["dragenter", "dragover"].forEach(evt =>
    el.addEventListener(evt, e => { e.preventDefault(); el.classList.add("drag-over"); }));
  ["dragleave", "drop"].forEach(evt =>
    el.addEventListener(evt, e => { e.preventDefault(); el.classList.remove("drag-over"); }));
  el.addEventListener("drop", e => {
    const file = e.dataTransfer.files[0];
    if (file) onFile(file);
  });
}

/* Mimics POST /report/download/:id — opens a print-styled window.
   Swap for a real PDF (e.g. jsPDF or a backend-generated file) later. */
function downloadReportPdf(reportId) {
  notify(`Preparing PDF for ${reportId}…`, "signal");
  setTimeout(() => window.print(), 400);
}

function highlightActiveNav() {
  const page = document.body.dataset.page;
  document.querySelectorAll(".nav-link").forEach(a => {
    a.classList.toggle("active", a.dataset.nav === page);
  });
}

document.addEventListener("DOMContentLoaded", () => {
  highlightActiveNav();
  wireTabs();
});
