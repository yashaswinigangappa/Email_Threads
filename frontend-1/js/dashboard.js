/**
 * Dashboard Logic & Chart Controllers
 * Manages Stats Cards, Threat Trend Line Charts, Distribution Donut, and Recent Threats Table
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Ensure authentication state
  if (window.AuthManager) window.AuthManager.requireAuth();

  // Initialize Layout Elements
  const navbarContainer = document.getElementById('navbar-container');
  const sidebarContainer = document.getElementById('sidebar-container');

  if (navbarContainer) navbarContainer.innerHTML = window.Layout.renderNavbar('dashboard');
  if (sidebarContainer) sidebarContainer.innerHTML = window.Layout.renderSidebar('dashboard');

  window.Layout.initInteractions();

  // Load Dashboard Data
  await initDashboard();
});

let trendChartInstance = null;
let distributionChartInstance = null;

async function initDashboard() {
  try {
    // 1. Fetch Stats from API Service
    const statsRes = await window.api.getDashboardStats();
    if (statsRes && statsRes.data) {
      renderStatsCards(statsRes.data);
    }

    // 2. Fetch Recent Threats Table Data
    const threatsRes = await window.api.getRecentThreats();
    if (threatsRes && threatsRes.data) {
      renderRecentThreatsTable(threatsRes.data);
    }

    // 3. Render Threat Trends Chart (Default 7 Days)
    await updateTrendsChart('7d');

    // 4. Render Threat Distribution Donut Chart
    renderDistributionChart();

    // 5. Render Threat Feed Widget
    renderThreatFeed();

  } catch (error) {
    console.error("Dashboard initialization error:", error);
    if (window.Toast) window.Toast.show("Failed to load live telemetry: " + error.message, "danger");
  }
}

// Render Statistics Cards
function renderStatsCards(stats) {
  const container = document.getElementById('stats-grid');
  if (!container) return;

  const cards = [
    {
      title: "Total Emails Scanned",
      value: stats.totalScanned.toLocaleString(),
      change: stats.totalScannedGrowth,
      changeType: "up",
      subtext: "vs prior 7 days",
      icon: `<svg class="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>`,
      glow: "border-cyan-500/20 hover:border-cyan-500/50"
    },
    {
      title: "Safe & Verified",
      value: stats.safeEmails.toLocaleString(),
      change: `${stats.safePercentage}%`,
      changeType: "neutral",
      subtext: "Clean email traffic",
      icon: `<svg class="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>`,
      glow: "border-emerald-500/20 hover:border-emerald-500/50"
    },
    {
      title: "Spam Quarantined",
      value: stats.spamEmails.toLocaleString(),
      change: `${stats.spamPercentage}%`,
      changeType: "warning",
      subtext: "Unsolicited bulk mail",
      icon: `<svg class="w-6 h-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`,
      glow: "border-amber-500/20 hover:border-amber-500/50"
    },
    {
      title: "Phishing Attacks",
      value: stats.phishingEmails.toLocaleString(),
      change: `${stats.phishingPercentage}%`,
      changeType: "danger",
      subtext: "Credential harvest attempts",
      icon: `<svg class="w-6 h-6 text-rose-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>`,
      glow: "border-rose-500/20 hover:border-rose-500/50"
    },
    {
      title: "Malware Payloads",
      value: stats.malwareEmails.toLocaleString(),
      change: `${stats.malwarePercentage}%`,
      changeType: "danger",
      subtext: "Trojans, Macros & Scripts",
      icon: `<svg class="w-6 h-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>`,
      glow: "border-purple-500/20 hover:border-purple-500/50"
    }
  ];

  container.innerHTML = cards.map(card => `
    <div class="glass-card rounded-2xl p-5 border transition-all duration-300 ${card.glow} relative overflow-hidden group">
      <div class="flex items-center justify-between mb-3">
        <span class="text-xs font-mono text-slate-400 font-semibold">${card.title}</span>
        <div class="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 shadow-inner group-hover:scale-110 transition-transform">
          ${card.icon}
        </div>
      </div>
      <div class="text-2xl lg:text-3xl font-extrabold text-white tracking-tight font-mono mb-2">
        ${card.value}
      </div>
      <div class="flex items-center justify-between text-xs font-mono">
        <span class="px-2 py-0.5 rounded ${
          card.changeType === 'danger' ? 'bg-rose-500/10 text-rose-400' :
          card.changeType === 'warning' ? 'bg-amber-500/10 text-amber-400' :
          card.changeType === 'neutral' ? 'bg-emerald-500/10 text-emerald-400' :
          'bg-cyan-500/10 text-cyan-400'
        } font-bold">
          ${card.change}
        </span>
        <span class="text-slate-500 text-[11px] truncate ml-2">${card.subtext}</span>
      </div>
    </div>
  `).join('');
}

// Render Recent Threats Table
function renderRecentThreatsTable(threats) {
  const tbody = document.getElementById('recent-threats-body');
  if (!tbody) return;

  tbody.innerHTML = threats.map(threat => {
    const isPhish = threat.verdict === 'Phishing';
    const isMalware = threat.verdict === 'Malware';
    const isSpam = threat.verdict === 'Spam';
    const isSafe = threat.verdict === 'Safe';

    const badgeClass = (isPhish || isMalware) ? 'badge-threat-high' : isSpam ? 'badge-threat-medium' : 'badge-threat-clean';
    const verdictBg = isPhish ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' :
                      isMalware ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30' :
                      isSpam ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30' :
                      'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30';

    return `
      <tr class="border-b border-slate-800/80 hover:bg-slate-900/60 transition group cursor-pointer" onclick="ThreatModal.open('${threat.id}')">
        <td class="py-4 px-4">
          <div class="font-medium text-slate-200 text-sm group-hover:text-cyan-300 transition line-clamp-1">
            ${threat.subject}
          </div>
          <div class="text-[11px] font-mono text-cyan-500/80 flex items-center space-x-2 mt-0.5">
            <span>${threat.id}</span>
            <span>•</span>
            <span class="text-slate-400">${threat.category || 'Threat Vector'}</span>
          </div>
        </td>
        <td class="py-4 px-4 font-mono text-xs text-slate-300">
          <div class="truncate max-w-[200px]" title="${threat.sender}">
            ${threat.sender}
          </div>
        </td>
        <td class="py-4 px-4 font-mono">
          <span class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold ${badgeClass}">
            <span class="w-1.5 h-1.5 rounded-full ${threat.riskScore > 75 ? 'bg-rose-500' : threat.riskScore > 40 ? 'bg-amber-500' : 'bg-emerald-500'} mr-1.5"></span>
            ${threat.riskScore}/100
          </span>
        </td>
        <td class="py-4 px-4">
          <span class="inline-block px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider font-mono ${verdictBg}">
            ${threat.verdict}
          </span>
        </td>
        <td class="py-4 px-4 font-mono text-xs text-slate-400">
          ${threat.date.split(' ')[0]} <span class="text-slate-600">${threat.date.split(' ')[1]}</span>
        </td>
        <td class="py-4 px-4 text-right">
          <button 
            onclick="event.stopPropagation(); ThreatModal.open('${threat.id}')"
            class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-cyan-500 hover:text-slate-950 text-xs font-semibold text-cyan-400 transition font-mono border border-slate-700/60"
          >
            Investigate
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// Update Threat Trends Multi-Line Chart
async function updateTrendsChart(timeframe) {
  const trendRes = await window.api.getDashboardTrends(timeframe);
  const data = trendRes.data;

  // Update active state of button
  document.querySelectorAll('.timeframe-btn').forEach(btn => {
    if (btn.getAttribute('data-timeframe') === timeframe) {
      btn.className = "timeframe-btn px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40";
    } else {
      btn.className = "timeframe-btn px-3 py-1 rounded-lg text-xs font-mono text-slate-400 hover:text-white bg-slate-900 border border-slate-800";
    }
  });

  const ctx = document.getElementById('threatTrendsChart');
  if (!ctx) return;

  if (trendChartInstance) {
    trendChartInstance.destroy();
  }

  trendChartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.labels,
      datasets: [
        {
          label: 'Phishing Attacks',
          data: data.phishing,
          borderColor: '#EF4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#EF4444',
          pointRadius: 4
        },
        {
          label: 'Malware Incidents',
          data: data.malware,
          borderColor: '#8B5CF6',
          backgroundColor: 'rgba(139, 92, 246, 0.08)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#8B5CF6',
          pointRadius: 4
        },
        {
          label: 'Spam Quarantined',
          data: data.spam,
          borderColor: '#F59E0B',
          backgroundColor: 'transparent',
          borderDash: [4, 4],
          tension: 0.35,
          borderWidth: 2,
          pointBackgroundColor: '#F59E0B',
          pointRadius: 3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: '#94A3B8',
            font: { family: 'Plus Jakarta Sans', size: 12 },
            usePointStyle: true,
            boxWidth: 8
          }
        },
        tooltip: {
          backgroundColor: '#0F172A',
          titleColor: '#F8FAFC',
          bodyColor: '#CBD5E1',
          borderColor: '#334155',
          borderWidth: 1,
          padding: 12,
          boxPadding: 6,
          usePointStyle: true
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 11 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 11 } }
        }
      }
    }
  });
}

// Render Threat Distribution Donut Chart
function renderDistributionChart() {
  const ctx = document.getElementById('threatDistributionChart');
  if (!ctx) return;

  const dist = window.MOCK_DATA.distribution;

  if (distributionChartInstance) {
    distributionChartInstance.destroy();
  }

  distributionChartInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: dist.labels,
      datasets: [{
        data: dist.data,
        backgroundColor: dist.colors,
        borderColor: '#111827',
        borderWidth: 3,
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: '#94A3B8',
            font: { family: 'Plus Jakarta Sans', size: 11 },
            usePointStyle: true,
            padding: 16
          }
        },
        tooltip: {
          backgroundColor: '#0F172A',
          titleColor: '#F8FAFC',
          bodyColor: '#CBD5E1',
          borderColor: '#334155',
          borderWidth: 1,
          padding: 10
        }
      },
      cutout: '72%'
    }
  });
}

// Render Live Threat Stream Widget
function renderThreatFeed() {
  const container = document.getElementById('threat-feed-container');
  if (!container) return;

  const feed = window.MOCK_DATA.threatFeed;
  container.innerHTML = feed.map(item => `
    <div class="flex items-center justify-between p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 hover:border-cyan-500/40 transition">
      <div class="flex items-center space-x-3 overflow-hidden">
        <span class="w-2 h-2 rounded-full ${item.type === 'Phishing' || item.type === 'Malware' ? 'bg-rose-400' : 'bg-amber-400'}"></span>
        <div class="truncate">
          <div class="text-xs font-mono font-bold text-slate-200 truncate">${item.domain}</div>
          <div class="text-[10px] text-slate-400 font-mono">${item.type} • Target: ${item.target}</div>
        </div>
      </div>
      <div class="text-right flex-shrink-0 ml-3">
        <span class="text-xs font-mono font-bold ${item.risk >= 90 ? 'text-rose-400' : 'text-amber-400'}">${item.risk}/100</span>
        <div class="text-[10px] font-mono text-slate-500">${item.time}</div>
      </div>
    </div>
  `).join('');
}

window.updateTrendsChart = updateTrendsChart;
