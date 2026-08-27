/**
 * Reusable UI Components Engine
 * Navbar, Sidebar, Modals, Threat Detail Viewers, and Toast Alerts
 */

// Toast Notification System
const Toast = {
  container: null,

  init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.id = 'toast-container';
      this.container.className = 'fixed bottom-5 right-5 z-50 flex flex-col space-y-3 max-w-sm w-full pointer-events-none';
      document.body.appendChild(this.container);
    }
  },

  show(message, type = 'info', duration = 4000) {
    this.init();
    const toast = document.createElement('div');
    toast.className = 'pointer-events-auto transform transition-all duration-300 translate-y-4 opacity-0 flex items-start p-4 rounded-xl shadow-2xl glass-card border';
    
    let icon = 'ℹ️';
    let borderColor = 'border-cyan-500/40';
    let iconBg = 'bg-cyan-500/10 text-cyan-400';

    if (type === 'success') {
      icon = '✓';
      borderColor = 'border-emerald-500/40';
      iconBg = 'bg-emerald-500/10 text-emerald-400';
    } else if (type === 'danger') {
      icon = '⚠️';
      borderColor = 'border-rose-500/40';
      iconBg = 'bg-rose-500/10 text-rose-400';
    } else if (type === 'warning') {
      icon = '⚡';
      borderColor = 'border-amber-500/40';
      iconBg = 'bg-amber-500/10 text-amber-400';
    }

    toast.classList.add(borderColor);
    toast.innerHTML = `
      <div class="flex-shrink-0 w-8 h-8 rounded-lg ${iconBg} flex items-center justify-center font-bold mr-3">
        ${icon}
      </div>
      <div class="flex-1 text-sm font-medium text-slate-200">
        ${message}
      </div>
      <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-slate-200 ml-2 text-xs">✕</button>
    `;

    this.container.appendChild(toast);

    // Animate in
    setTimeout(() => {
      toast.classList.remove('translate-y-4', 'opacity-0');
    }, 20);

    // Auto dismiss
    setTimeout(() => {
      toast.classList.add('opacity-0', 'translate-y-2');
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }
};

window.Toast = Toast;

// Threat Detail Modal Controller
const ThreatModal = {
  modalEl: null,

  init() {
    if (!this.modalEl) {
      this.modalEl = document.createElement('div');
      this.modalEl.id = 'threat-detail-modal';
      this.modalEl.className = 'fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md hidden opacity-0 transition-opacity duration-300';
      document.body.appendChild(this.modalEl);

      // Close on backdrop click
      this.modalEl.addEventListener('click', (e) => {
        if (e.target === this.modalEl) this.close();
      });
    }
  },

  open(threatId) {
    this.init();
    const threats = window.MOCK_DATA.recentThreats;
    const threat = threats.find(t => t.id === threatId) || threats[0];
    if (!threat) return;

    const isHigh = threat.riskScore >= 80;
    const isMed = threat.riskScore >= 50 && threat.riskScore < 80;
    const riskBadgeClass = isHigh ? 'badge-threat-high' : isMed ? 'badge-threat-medium' : 'badge-threat-clean';
    const verdictColor = threat.verdict === 'Phishing' || threat.verdict === 'Malware' ? 'text-rose-400' : threat.verdict === 'Spam' ? 'text-amber-400' : 'text-emerald-400';

    const explainableAi = threat.explainableAi || { reasons: [], extractedUrls: [], attachments: [] };

    this.modalEl.innerHTML = `
      <div class="relative w-full max-w-3xl glass-card rounded-2xl border border-slate-700/60 p-6 md:p-8 max-h-[90vh] overflow-y-auto shadow-2xl">
        <!-- Header -->
        <div class="flex items-start justify-between pb-5 border-b border-slate-800">
          <div>
            <div class="flex items-center space-x-3 mb-2">
              <span class="px-3 py-1 rounded-md text-xs font-bold font-mono ${riskBadgeClass}">
                RISK SCORE: ${threat.riskScore}/100
              </span>
              <span class="text-xs font-mono text-cyan-400 uppercase tracking-wider">${threat.id}</span>
              <span class="text-xs text-slate-500 font-mono">${threat.date}</span>
            </div>
            <h3 class="text-xl font-bold text-white tracking-tight">${threat.subject}</h3>
          </div>
          <button onclick="ThreatModal.close()" class="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/60 hover:bg-slate-800 transition">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
          </button>
        </div>

        <!-- Body Metadata Grid -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 my-6">
          <div class="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
            <div class="text-xs font-mono text-slate-400 mb-1">SENDER ADDRESS</div>
            <div class="text-sm font-semibold text-rose-300 truncate font-mono">${threat.sender}</div>
            <div class="mt-2 text-xs text-slate-400 flex items-center space-x-2">
              <span>Domain Age: <strong class="text-slate-200">${explainableAi.domainAge || 'Unknown'}</strong></span>
            </div>
          </div>
          <div class="bg-slate-900/60 p-4 rounded-xl border border-slate-800/80">
            <div class="text-xs font-mono text-slate-400 mb-1">AI CLASSIFICATION & CONFIDENCE</div>
            <div class="text-sm font-bold ${verdictColor} flex items-center space-x-2">
              <span>${threat.verdict} (${threat.category || 'Threat'})</span>
              <span class="text-xs bg-slate-800 px-2 py-0.5 rounded text-cyan-300 font-mono">${threat.confidence}% Confidence</span>
            </div>
            <div class="mt-2 text-xs text-slate-400">Target: <span class="text-slate-200 font-mono">${threat.receiver || 'Enterprise User'}</span></div>
          </div>
        </div>

        <!-- Email Authentication Protocols -->
        <div class="mb-6">
          <h4 class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">Email Authentication Protocol Checks</h4>
          <div class="grid grid-cols-3 gap-3">
            <div class="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center justify-between">
              <span class="text-xs font-mono text-slate-300">SPF</span>
              <span class="px-2 py-0.5 rounded text-xs font-bold font-mono ${explainableAi.spfStatus === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}">${explainableAi.spfStatus || 'FAIL'}</span>
            </div>
            <div class="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center justify-between">
              <span class="text-xs font-mono text-slate-300">DKIM</span>
              <span class="px-2 py-0.5 rounded text-xs font-bold font-mono ${explainableAi.dkimStatus === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}">${explainableAi.dkimStatus || 'FAIL'}</span>
            </div>
            <div class="p-3 rounded-lg bg-slate-900/40 border border-slate-800 flex items-center justify-between">
              <span class="text-xs font-mono text-slate-300">DMARC</span>
              <span class="px-2 py-0.5 rounded text-xs font-bold font-mono ${explainableAi.dmarcStatus === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}">${explainableAi.dmarcStatus || 'FAIL'}</span>
            </div>
          </div>
        </div>

        <!-- Explainable AI Reasons -->
        <div class="mb-6">
          <h4 class="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider mb-3">AI Explainability & Threat Vectors</h4>
          <div class="space-y-2 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
            ${(explainableAi.reasons || []).map(reason => `
              <div class="flex items-start text-xs text-slate-300">
                <span class="text-rose-400 mr-2 font-mono">▸</span>
                <span>${reason}</span>
              </div>
            `).join('')}
          </div>
        </div>

        <!-- Extracted URLs & Attachments -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
          <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
            <h5 class="text-xs font-mono font-bold text-slate-400 mb-2">EXTRACTED SUSPICIOUS URLS</h5>
            ${explainableAi.extractedUrls && explainableAi.extractedUrls.length > 0 ? `
              <div class="space-y-2">
                ${explainableAi.extractedUrls.map(u => `
                  <div class="text-xs font-mono p-2 bg-slate-950 rounded border border-rose-900/40 text-rose-300 truncate">
                    ${u.url}
                  </div>
                `).join('')}
              </div>
            ` : '<p class="text-xs text-slate-500 italic">No external hyperlinked payloads detected.</p>'}
          </div>

          <div class="p-4 rounded-xl bg-slate-900/50 border border-slate-800">
            <h5 class="text-xs font-mono font-bold text-slate-400 mb-2">ATTACHMENT SCAN RESULTS</h5>
            ${explainableAi.attachments && explainableAi.attachments.length > 0 ? `
              <div class="space-y-2">
                ${explainableAi.attachments.map(att => `
                  <div class="text-xs font-mono p-2 bg-slate-950 rounded border border-rose-900/40 flex items-center justify-between">
                    <span class="text-rose-300 truncate">${att.filename} (${att.size})</span>
                    <span class="px-2 py-0.5 text-[10px] rounded bg-rose-500/20 text-rose-400 uppercase font-bold">${att.threatLevel}</span>
                  </div>
                `).join('')}
              </div>
            ` : '<p class="text-xs text-slate-500 italic">No file attachments included in this message.</p>'}
          </div>
        </div>

        <!-- Modal Actions -->
        <div class="flex items-center justify-between pt-4 border-t border-slate-800">
          <button onclick="Toast.show('Threat report generated in PDF preview format.', 'info')" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center space-x-2 transition">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
            <span>Export Incident Report</span>
          </button>
          <div class="flex space-x-3">
            <button onclick="Toast.show('Sender domain added to global blocklist.', 'success'); ThreatModal.close();" class="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold transition shadow-lg shadow-rose-600/30">
              Quarantine & Block Sender
            </button>
          </div>
        </div>
      </div>
    `;

    this.modalEl.classList.remove('hidden');
    setTimeout(() => {
      this.modalEl.classList.remove('opacity-0');
    }, 10);
  },

  close() {
    if (!this.modalEl) return;
    this.modalEl.classList.add('opacity-0');
    setTimeout(() => {
      this.modalEl.classList.add('hidden');
    }, 250);
  }
};

window.ThreatModal = ThreatModal;

// Component Renderers for Navigation and Layout
const Layout = {
  // Render Shared Header Navbar
  renderNavbar(activePage = 'dashboard') {
    const user = window.AuthManager ? window.AuthManager.getUser() : { name: "Analyst", role: "SOC Lead", email: "admin@acme.com" };
    const notifications = (window.MOCK_DATA && window.MOCK_DATA.notifications) || [];
    const unreadCount = notifications.filter(n => !n.read).length;

    return `
      <header class="sticky top-0 z-40 w-full glass-card border-b border-slate-800/80 px-4 md:px-6 py-3 flex items-center justify-between">
        <!-- Left: Mobile Toggle & SOC Breadcrumbs -->
        <div class="flex items-center space-x-4">
          <button id="mobile-sidebar-toggle" class="lg:hidden text-slate-400 hover:text-white p-1.5 rounded-lg bg-slate-800/80">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
          </button>
          <div class="flex items-center space-x-2">
            <div class="w-2.5 h-2.5 rounded-full bg-cyan-400 pulse-dot"></div>
            <span class="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest hidden sm:inline-block">AI Threat Engine</span>
            <span class="text-xs font-mono text-slate-500 hidden sm:inline-block">|</span>
            <span class="text-xs font-medium text-slate-300 font-mono capitalize">SOC // ${activePage}</span>
          </div>
        </div>

        <!-- Center: Search Threat Intelligence Bar -->
        <div class="hidden md:flex items-center flex-1 max-w-md mx-6">
          <div class="relative w-full">
            <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
            </div>
            <input 
              type="text" 
              placeholder="Search sender, hash, suspicious domain, or Threat ID... (Ctrl+/)" 
              class="w-full pl-9 pr-12 py-1.5 bg-slate-900/90 text-xs text-slate-200 rounded-lg border border-slate-700/60 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 placeholder-slate-500 transition font-mono"
              onkeydown="if(event.key === 'Enter'){ Toast.show('Searching threat intel for: ' + this.value, 'info'); }"
            />
            <div class="absolute inset-y-0 right-0 pr-2.5 flex items-center pointer-events-none">
              <kbd class="px-1.5 py-0.5 text-[10px] font-mono text-slate-400 bg-slate-800 rounded border border-slate-700">⌘K</kbd>
            </div>
          </div>
        </div>

        <!-- Right: Status Pill, Notifications & Profile Dropdown -->
        <div class="flex items-center space-x-3 md:space-x-4">
          <!-- Live AI Engine Health -->
          <div class="hidden xl:flex items-center space-x-2 px-3 py-1 rounded-full bg-slate-900/80 border border-slate-800 text-xs font-mono">
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
            <span class="text-emerald-400 font-bold">FastAPI AI</span>
            <span class="text-slate-500">|</span>
            <span class="text-slate-300">Accuracy 98.6%</span>
          </div>

          <!-- Notification Dropdown -->
          <div class="relative">
            <button id="notif-btn" class="relative p-2 rounded-lg bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-white transition">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"></path></svg>
              ${unreadCount > 0 ? `
                <span class="absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center rounded-full bg-rose-500 text-[10px] font-bold text-white">
                  ${unreadCount}
                </span>
              ` : ''}
            </button>
            <div id="notif-dropdown" class="hidden absolute right-0 mt-2 w-80 glass-card rounded-xl border border-slate-700/80 shadow-2xl p-4 z-50">
              <div class="flex items-center justify-between pb-3 border-b border-slate-800">
                <span class="text-xs font-mono font-bold text-white uppercase">Security Alerts</span>
                <span class="text-[11px] font-mono text-cyan-400">${unreadCount} Unread</span>
              </div>
              <div class="divide-y divide-slate-800/60 max-h-64 overflow-y-auto mt-2">
                ${notifications.map(n => `
                  <div class="py-2.5 hover:bg-slate-800/40 px-1 rounded transition cursor-pointer" onclick="Toast.show('${n.title}', '${n.type}')">
                    <div class="flex items-center justify-between text-xs font-semibold ${n.type === 'danger' ? 'text-rose-400' : n.type === 'warning' ? 'text-amber-400' : 'text-emerald-400'}">
                      <span>${n.title}</span>
                      <span class="text-[10px] font-mono text-slate-500">${n.time}</span>
                    </div>
                    <p class="text-[11px] text-slate-400 mt-1 line-clamp-2">${n.desc}</p>
                  </div>
                `).join('')}
              </div>
            </div>
          </div>

          <!-- User Profile Dropdown -->
          <div class="relative">
            <button id="profile-btn" class="flex items-center space-x-2.5 p-1 rounded-lg hover:bg-slate-800/80 transition">
              <img src="${user.avatar || 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80'}" class="w-8 h-8 rounded-full border border-cyan-500/50 object-cover" alt="User" />
              <div class="hidden md:block text-left">
                <div class="text-xs font-bold text-white leading-tight">${user.name}</div>
                <div class="text-[10px] font-mono text-cyan-400">${user.role}</div>
              </div>
              <svg class="w-4 h-4 text-slate-400 hidden md:block" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
            </button>
            <div id="profile-dropdown" class="hidden absolute right-0 mt-2 w-56 glass-card rounded-xl border border-slate-700/80 shadow-2xl p-3 z-50">
              <div class="pb-2 mb-2 border-b border-slate-800">
                <div class="text-xs font-bold text-white">${user.name}</div>
                <div class="text-[11px] font-mono text-slate-400 truncate">${user.email}</div>
              </div>
              <div class="space-y-1">
                <a href="index.html" class="flex items-center px-3 py-2 rounded-lg text-xs text-slate-300 hover:bg-slate-800 hover:text-white transition">
                  <span class="mr-2">📊</span> Dashboard Overview
                </a>
                <a href="analytics.html" class="flex items-center px-3 py-2 rounded-lg text-xs text-slate-300 hover:bg-slate-800 hover:text-white transition">
                  <span class="mr-2">📈</span> Threat Analytics
                </a>
                <button onclick="AuthManager.logout()" class="w-full flex items-center px-3 py-2 rounded-lg text-xs text-rose-400 hover:bg-rose-500/10 hover:text-rose-300 transition text-left">
                  <span class="mr-2">🚪</span> Terminate Session
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>
    `;
  },

  // Render Sidebar Navigation
  renderSidebar(activePage = 'dashboard') {
    const navItems = [
      { id: 'dashboard', label: 'SOC Dashboard', href: 'index.html', icon: 'M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z' },
      { id: 'analytics', label: 'Threat Analytics', href: 'analytics.html', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
      { id: 'scan', label: 'Analyze Email', href: 'javascript:void(0)', badge: 'Member B', onClick: "Toast.show('Analyze Email module will be integrated with Frontend Developer B branch.', 'info')", icon: 'M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12' },
      { id: 'feed', label: 'Live Threat Feed', href: 'javascript:void(0)', onClick: "Toast.show('Live Feed streaming active on SOC Overview.', 'info')", icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
      { id: 'history', label: 'Threat History', href: 'javascript:void(0)', badge: 'Member B', onClick: "Toast.show('Incident History managed under Frontend Developer B.', 'info')", icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z' },
      { id: 'settings', label: 'Platform Settings', href: 'javascript:void(0)', onClick: "Toast.show('Platform configuration & API keys panel.', 'info')", icon: 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z' }
    ];

    return `
      <aside id="sidebar-menu" class="fixed inset-y-0 left-0 z-50 w-64 bg-slate-950/95 lg:bg-slate-950/80 backdrop-blur-xl border-r border-slate-800/80 flex flex-col justify-between transform -translate-x-full lg:translate-x-0 transition-transform duration-300 ease-in-out">
        <!-- Logo & Branding -->
        <div>
          <div class="p-6 border-b border-slate-800/80 flex items-center justify-between">
            <a href="index.html" class="flex items-center space-x-3">
              <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 via-blue-600 to-indigo-600 p-0.5 flex items-center justify-center glow-cyan shadow-lg shadow-cyan-500/20">
                <div class="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                  <svg class="w-5 h-5 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
                </div>
              </div>
              <div>
                <h1 class="text-sm font-extrabold text-white tracking-wider font-mono">SENTINEL<span class="text-cyan-400">.AI</span></h1>
                <p class="text-[10px] text-slate-400 font-mono tracking-tight">SIH26106 THREAT SOC</p>
              </div>
            </a>
            <button id="close-sidebar-btn" class="lg:hidden text-slate-400 hover:text-white">✕</button>
          </div>

          <!-- Navigation Links -->
          <nav class="p-4 space-y-1.5">
            <div class="px-3 py-1.5 text-[10px] font-mono font-bold text-slate-400 uppercase tracking-wider">
              Navigation & Telemetry
            </div>
            ${navItems.map(item => {
              const isActive = activePage === item.id;
              const activeClass = isActive 
                ? 'bg-gradient-to-r from-cyan-500/20 to-transparent border-l-2 border-cyan-400 text-cyan-300 font-semibold' 
                : 'text-slate-400 hover:bg-slate-900/80 hover:text-slate-200';

              return `
                <a 
                  href="${item.href}" 
                  ${item.onClick ? `onclick="${item.onClick}"` : ''} 
                  class="flex items-center justify-between px-3 py-2.5 rounded-lg text-xs transition duration-200 ${activeClass}"
                >
                  <div class="flex items-center space-x-3">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${item.icon}"></path>
                    </svg>
                    <span>${item.label}</span>
                  </div>
                  ${item.badge ? `
                    <span class="px-1.5 py-0.5 text-[9px] font-mono rounded bg-slate-800 text-cyan-400 border border-slate-700">
                      ${item.badge}
                    </span>
                  ` : ''}
                </a>
              `;
            }).join('')}
          </nav>
        </div>

        <!-- System & API Switcher Card -->
        <div class="p-4 m-4 rounded-xl bg-slate-900/70 border border-slate-800">
          <div class="flex items-center justify-between mb-2">
            <span class="text-[11px] font-mono font-bold text-slate-300 uppercase">Engine Status</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 font-semibold">ONLINE</span>
          </div>
          <div class="text-[11px] text-slate-400 space-y-1 font-mono">
            <div class="flex justify-between"><span>Latencies:</span> <span class="text-cyan-300">142 ms</span></div>
            <div class="flex justify-between"><span>Model:</span> <span class="text-slate-200">FastAPI-v4</span></div>
            <div class="flex justify-between"><span>DB Sync:</span> <span class="text-emerald-400">MongoDB OK</span></div>
          </div>
          <button onclick="Toast.show('API Mode: Mock data active for offline evaluation. Toggle in js/api.js', 'info')" class="mt-3 w-full py-1.5 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] font-mono text-cyan-400 border border-slate-700/60 transition">
            API Endpoints Info
          </button>
        </div>
      </aside>
    `;
  },

  // Setup Global Interactive Listeners (Dropdowns, Sidebar Toggle)
  initInteractions() {
    // Dropdown toggles
    const notifBtn = document.getElementById('notif-btn');
    const notifDropdown = document.getElementById('notif-dropdown');
    const profileBtn = document.getElementById('profile-btn');
    const profileDropdown = document.getElementById('profile-dropdown');

    if (notifBtn && notifDropdown) {
      notifBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        notifDropdown.classList.toggle('hidden');
        if (profileDropdown) profileDropdown.classList.add('hidden');
      });
    }

    if (profileBtn && profileDropdown) {
      profileBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        profileDropdown.classList.toggle('hidden');
        if (notifDropdown) notifDropdown.classList.add('hidden');
      });
    }

    // Close dropdowns on document click
    document.addEventListener('click', () => {
      if (notifDropdown) notifDropdown.classList.add('hidden');
      if (profileDropdown) profileDropdown.classList.add('hidden');
    });

    // Mobile sidebar toggle
    const toggleBtn = document.getElementById('mobile-sidebar-toggle');
    const closeSidebarBtn = document.getElementById('close-sidebar-btn');
    const sidebar = document.getElementById('sidebar-menu');

    if (toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.remove('-translate-x-full');
      });
    }

    if (closeSidebarBtn && sidebar) {
      closeSidebarBtn.addEventListener('click', () => {
        sidebar.classList.add('-translate-x-full');
      });
    }
  }
};

window.Layout = Layout;
