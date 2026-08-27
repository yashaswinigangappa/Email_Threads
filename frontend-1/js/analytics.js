/**
 * Analytics Page Controller & In-depth Telemetry Charts
 * Targeted Departments, Attack Vectors Radar, Protocol Failure Rates, and Top Malicious Domains
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Ensure authentication
  if (window.AuthManager) window.AuthManager.requireAuth();

  // Render components
  const navbarContainer = document.getElementById('navbar-container');
  const sidebarContainer = document.getElementById('sidebar-container');

  if (navbarContainer) navbarContainer.innerHTML = window.Layout.renderNavbar('analytics');
  if (sidebarContainer) sidebarContainer.innerHTML = window.Layout.renderSidebar('analytics');

  window.Layout.initInteractions();

  // Load Analytics Data
  await initAnalytics();
});

let deptChartInstance = null;
let radarChartInstance = null;
let velocityChartInstance = null;

async function initAnalytics() {
  try {
    const analyticsRes = await window.api.getAnalyticsData();
    const data = analyticsRes.data;

    // Render Department Targeting Bar Chart
    renderDepartmentChart(data.targetedDepartments);

    // Render Threat Vector Radar Chart
    renderVectorRadarChart(data.threatVectors);

    // Render Velocity Chart
    renderVelocityChart();

    // Render Top Malicious Domains Table
    renderTopDomainsTable(data.topAttackingDomains);

  } catch (err) {
    console.error("Analytics load failed:", err);
    if (window.Toast) window.Toast.show("Failed to load analytics: " + err.message, "danger");
  }
}

// 1. Horizontal Bar Chart for Targeted Departments
function renderDepartmentChart(deptData) {
  const ctx = document.getElementById('departmentTargetChart');
  if (!ctx) return;

  if (deptChartInstance) deptChartInstance.destroy();

  deptChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: deptData.labels,
      datasets: [
        {
          label: 'Phishing Attempts',
          data: deptData.phishingAttempts,
          backgroundColor: 'rgba(239, 68, 68, 0.85)',
          borderRadius: 6,
          barThickness: 16
        },
        {
          label: 'Malware Droppers',
          data: deptData.malwareAttempts,
          backgroundColor: 'rgba(139, 92, 246, 0.85)',
          borderRadius: 6,
          barThickness: 16
        }
      ]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#94A3B8', font: { family: 'Plus Jakarta Sans', size: 11 }, usePointStyle: true }
        },
        tooltip: {
          backgroundColor: '#0F172A',
          borderColor: '#334155',
          borderWidth: 1,
          padding: 10
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#CBD5E1', font: { family: 'Plus Jakarta Sans', size: 11 } }
        }
      }
    }
  });
}

// 2. Threat Vector Radar Chart
function renderVectorRadarChart(vectors) {
  const ctx = document.getElementById('threatVectorRadar');
  if (!ctx) return;

  if (radarChartInstance) radarChartInstance.destroy();

  radarChartInstance = new Chart(ctx, {
    type: 'radar',
    data: {
      labels: vectors.labels,
      datasets: [{
        label: 'Threat Vector Frequency (%)',
        data: vectors.data,
        backgroundColor: 'rgba(6, 182, 212, 0.25)',
        borderColor: '#06B6D4',
        borderWidth: 2,
        pointBackgroundColor: '#06B6D4',
        pointBorderColor: '#fff',
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: '#06B6D4'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          backgroundColor: '#0F172A',
          borderColor: '#334155',
          borderWidth: 1
        }
      },
      scales: {
        r: {
          grid: { color: 'rgba(255, 255, 255, 0.08)' },
          angleLines: { color: 'rgba(255, 255, 255, 0.08)' },
          pointLabels: {
            color: '#94A3B8',
            font: { family: 'JetBrains Mono', size: 10 }
          },
          ticks: {
            backdropColor: 'transparent',
            color: '#64748B',
            font: { size: 9 }
          }
        }
      }
    }
  });
}

// 3. Hourly Velocity / Daily Threat Trend
function renderVelocityChart() {
  const ctx = document.getElementById('velocityTrendChart');
  if (!ctx) return;

  if (velocityChartInstance) velocityChartInstance.destroy();

  const hours = ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'];
  const inboundScan = [120, 95, 340, 1840, 2450, 1920, 890, 420];
  const threatsDetected = [14, 8, 42, 280, 410, 310, 95, 35];

  velocityChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hours,
      datasets: [
        {
          type: 'line',
          label: 'Threats Intercepted',
          data: threatsDetected,
          borderColor: '#F43F5E',
          backgroundColor: 'rgba(244, 63, 94, 0.1)',
          fill: true,
          tension: 0.4,
          yAxisID: 'y1'
        },
        {
          type: 'bar',
          label: 'Total Inbound Emails',
          data: inboundScan,
          backgroundColor: 'rgba(59, 130, 246, 0.35)',
          borderColor: '#3B82F6',
          borderWidth: 1,
          borderRadius: 4,
          yAxisID: 'y'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#94A3B8', font: { family: 'Plus Jakarta Sans', size: 11 }, usePointStyle: true }
        },
        tooltip: {
          backgroundColor: '#0F172A',
          borderColor: '#334155',
          borderWidth: 1,
          padding: 10
        }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y: {
          type: 'linear',
          position: 'left',
          grid: { color: 'rgba(255, 255, 255, 0.05)' },
          ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 } }
        },
        y1: {
          type: 'linear',
          position: 'right',
          grid: { drawOnChartArea: false },
          ticks: { color: '#F43F5E', font: { family: 'JetBrains Mono', size: 10 } }
        }
      }
    }
  });
}

// 4. Top Malicious Inbound Domains
function renderTopDomainsTable(domains) {
  const container = document.getElementById('top-domains-list');
  if (!container) return;

  container.innerHTML = domains.map((d, index) => `
    <div class="flex items-center justify-between p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition">
      <div class="flex items-center space-x-3">
        <span class="w-6 h-6 rounded-lg bg-slate-800 text-cyan-400 font-mono text-xs font-bold flex items-center justify-center border border-slate-700">
          #${index + 1}
        </span>
        <div>
          <div class="text-xs font-mono font-bold text-slate-200">${d.domain}</div>
          <div class="text-[11px] text-slate-400 font-mono">${d.category} • ${d.attacks} Blocked Events</div>
        </div>
      </div>
      <div class="text-right">
        <span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
          Risk: ${d.risk}/100
        </span>
      </div>
    </div>
  `).join('');
}

// Export Analytics Report
function exportAnalyticsData(format) {
  if (format === 'csv') {
    const csvContent = "data:text/csv;charset=utf-8," 
      + "Domain,Attacks,Category,RiskScore\n"
      + window.MOCK_DATA.analytics.topAttackingDomains.map(e => `"${e.domain}",${e.attacks},"${e.category}",${e.risk}`).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `threat_analytics_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    if (window.Toast) window.Toast.show("Telemetry CSV Export generated!", "success");
  } else if (format === 'json') {
    const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(window.MOCK_DATA.analytics, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonStr);
    link.setAttribute("download", `threat_intel_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    if (window.Toast) window.Toast.show("Threat Intelligence JSON exported successfully!", "success");
  }
}

window.exportAnalyticsData = exportAnalyticsData;
