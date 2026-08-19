/**
 * Dashboard Module: summary statistics, charts, host status and recent alerts.
 */
import {
    createEl, clearContainer, emptyRow, notify,
    severityClass, severityRowClass, formatTime,
} from './dom.js';
import {
    fetchHosts, checkHostStatus, triggerLogFetch, fetchAlerts,
    fetchSummary, fetchSeverityStats, fetchRuleStats, fetchTimeline, fetchTopSources,
    fetchHostStats, fetchEvents,
} from './api.js';

const hostsContainer = document.getElementById('hostsContainer');
const alertsBody = document.getElementById('alertsBody');
const topSources = document.getElementById('topSources');
const hostOverviewBody = document.getElementById('hostOverviewBody');
const usbBody = document.getElementById('usbBody');

// Chart instances are kept so a refresh updates them instead of stacking
// a new canvas overlay on top of the old one.
const charts = {};

// Severity palette, reused by both the doughnut and the rule chart.
const COLORS = {
    low: '#0dcaf0',
    medium: '#ffc107',
    high: '#dc3545',
    accent: '#0d6efd',
};

export async function initDashboard() {
    if (!hostsContainer) return;

    const refreshBtn = document.getElementById('refreshDashboard');
    if (refreshBtn) refreshBtn.addEventListener('click', () => loadAll());

    await loadAll();
}

async function loadAll() {
    // Run the panels concurrently — one slow panel shouldn't hold up the rest.
    await Promise.allSettled([
        refreshStats(),
        refreshCharts(),
        refreshTopSources(),
        refreshHostOverview(),
        refreshHostsList(),
        refreshAlertsTable(),
        refreshUsbDevices(),
    ]);
}

// ======================= HOST OVERVIEW =======================

/** Per-host status, so it is obvious which machines are actually reporting. */
async function refreshHostOverview() {
    if (!hostOverviewBody) return;
    clearContainer(hostOverviewBody);

    const statusStyles = {
        ONLINE: ['bg-success', '🟢 online'],
        DEGRADED: ['bg-warning text-dark', '🟡 degraded'],
        OFFLINE: ['bg-danger', '🔴 offline'],
        UNKNOWN: ['bg-secondary', '⚪ unknown'],
    };

    try {
        const hosts = await fetchHostStats();

        if (hosts.length === 0) {
            emptyRow(hostOverviewBody, 7, 'No hosts configured yet.');
            return;
        }

        hosts.forEach((host) => {
            const row = createEl('tr', [], '', hostOverviewBody);
            const [cls, label] = statusStyles[host.status] || statusStyles.UNKNOWN;

            const statusCell = createEl('td', [], '', row);
            createEl('span', ['badge', ...cls.split(' ')], label, statusCell);

            createEl('td', ['fw-semibold'], host.hostname, row);
            createEl('td', ['small'], host.os_type || '-', row);
            createEl('td', ['small', 'text-muted'], host.collection_method, row);
            createEl('td', ['text-end'], String(host.events), row);
            createEl('td', ['text-end'], String(host.alerts), row);
            createEl('td', ['small', 'text-muted'],
                host.last_success ? formatTime(host.last_success) : 'never', row);
        });
    } catch (err) {
        emptyRow(hostOverviewBody, 7, 'Could not load host status.');
    }
}

// ======================= SUMMARY STAT CARDS =======================

async function refreshStats() {
    try {
        const stats = await fetchSummary();
        Object.entries(stats).forEach(([key, value]) => {
            document.querySelectorAll(`[data-stat="${key}"]`).forEach((el) => {
                el.textContent = value;
            });
        });
    } catch (err) {
        console.error('Error loading summary statistics:', err);
    }
}

// ======================= CHARTS =======================

async function refreshCharts() {
    if (typeof Chart === 'undefined') return;

    try {
        const [timeline, severity, rules] = await Promise.all([
            fetchTimeline(7),
            fetchSeverityStats(),
            fetchRuleStats(),
        ]);

        renderChart('timelineChart', {
            type: 'line',
            data: {
                labels: timeline.labels,
                datasets: [{
                    label: 'Authentication failures',
                    data: timeline.counts,
                    borderColor: COLORS.accent,
                    backgroundColor: 'rgba(13, 110, 253, 0.15)',
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3,
                }],
            },
            options: baseOptions({ legend: false }),
        });

        renderChart('severityChart', {
            type: 'doughnut',
            data: {
                labels: severity.labels,
                datasets: [{
                    data: severity.counts,
                    backgroundColor: [COLORS.low, COLORS.medium, COLORS.high],
                    borderWidth: 0,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } },
            },
        });

        renderChart('ruleChart', {
            type: 'bar',
            data: {
                labels: rules.labels,
                datasets: [{
                    label: 'Alerts',
                    data: rules.counts,
                    backgroundColor: COLORS.accent,
                    borderRadius: 4,
                }],
            },
            options: baseOptions({ legend: false, indexAxis: 'y' }),
        });
    } catch (err) {
        console.error('Error loading chart data:', err);
    }
}

function baseOptions({ legend = true, indexAxis = 'x' } = {}) {
    return {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis,
        plugins: { legend: { display: legend } },
        scales: {
            x: { grid: { display: false } },
            // Alert counts are whole numbers; fractional ticks would be noise.
            y: { beginAtZero: true, ticks: { precision: 0 } },
        },
    };
}

function renderChart(canvasId, config) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    if (charts[canvasId]) {
        charts[canvasId].destroy();
    }
    charts[canvasId] = new Chart(canvas, config);
}

// ======================= TOP SOURCE IPs =======================

async function refreshTopSources() {
    if (!topSources) return;
    clearContainer(topSources);

    try {
        const sources = await fetchTopSources(5);
        if (sources.length === 0) {
            createEl('li', ['list-group-item', 'text-muted', 'small'],
                'No attacking source IPs recorded yet.', topSources);
            return;
        }

        sources.forEach((source) => {
            const item = createEl('li',
                ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'],
                '', topSources);

            const left = createEl('span', [], '', item);
            createEl('span', ['font-monospace', 'me-2'], source.source_ip, left);

            let badgeClass = 'bg-secondary';
            if (source.status === 'BANNED') badgeClass = 'bg-danger';
            else if (source.status === 'TRUSTED') badgeClass = 'bg-success';
            createEl('span', ['badge', badgeClass], source.status, left);

            createEl('span', ['badge', 'bg-light', 'text-dark'],
                `${source.hits} failures`, item);
        });
    } catch (err) {
        console.error('Error loading top sources:', err);
    }
}

// ======================= REMOVABLE MEDIA =======================

/**
 * Recent USB connections, read from the ordinary events endpoint with an
 * event_type filter. A dedicated API route would duplicate logic that
 * /api/events already performs, so none is added.
 */
async function refreshUsbDevices() {
    if (!usbBody) return;
    clearContainer(usbBody);

    try {
        const data = await fetchEvents({ event_type: 'USB_DEVICE_CONNECTED', limit: 10 });

        if (data.events.length === 0) {
            // Absence of USB events is the normal state, and also what a host
            // without Plug and Play auditing looks like — so the empty message
            // points at the setting rather than implying something is broken.
            emptyRow(usbBody, 4,
                'No USB devices recorded. Enable Plug and Play auditing on a monitored host to collect these.');
            return;
        }

        data.events.forEach((event) => {
            const row = createEl('tr', [], '', usbBody);

            createEl('td', ['text-nowrap', 'small'], formatTime(event.timestamp), row);
            createEl('td', ['small'], event.host_name, row);
            createEl('td', ['small'], event.username || '-', row);
            createEl('td', ['small', 'fw-semibold'], event.device_name || 'Unknown device', row);
        });
    } catch (err) {
        emptyRow(usbBody, 4, `Could not load USB devices: ${err.message}`);
    }
}

// ======================= HOST STATUS =======================

async function refreshHostsList() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        if (hosts.length === 0) {
            createEl('div', ['p-4', 'text-center', 'text-muted'],
                'No hosts yet. Add one in the Configuration panel.', hostsContainer);
            return;
        }
        hosts.forEach(renderDashboardRow);
    } catch (err) {
        console.error(err);
        createEl('div', ['alert', 'alert-danger', 'mb-0'],
            `Error loading hosts: ${err.message}`, hostsContainer);
    }
}

function renderDashboardRow(host) {
    const item = createEl('div', ['list-group-item', 'py-3'], '', hostsContainer);
    const row = createEl('div', ['row', 'align-items-center', 'g-2'], '', item);

    // COLUMN 1: identity
    const colInfo = createEl('div', ['col-12', 'col-md-4', 'd-flex', 'align-items-center'], '', row);
    createEl('span', ['fs-2', 'me-2'], host.os_type === 'LINUX' ? '🐧' : '🪟', colInfo);

    const details = createEl('div', ['d-flex', 'flex-column', 'overflow-hidden'], '', colInfo);
    createEl('div', ['fw-bold', 'text-truncate'], host.hostname, details);
    createEl('small', ['text-muted', 'font-monospace'], host.ip_address, details);
    if (host.description) {
        createEl('small', ['text-muted', 'text-truncate'], host.description, details);
    }
    createEl('small', ['text-muted'],
        `${host.event_count} events · ${host.alert_count} alerts`, details);

    // COLUMN 2: telemetry, filled in when Status is clicked
    const colStatus = createEl('div', ['col-8', 'col-md-5'], '', row);
    createEl('div', ['text-muted', 'small', 'fst-italic'], 'Click Status to poll this host.', colStatus);

    // COLUMN 3: actions
    const colActions = createEl('div', ['col-4', 'col-md-3', 'text-end'], '', row);
    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', colActions);

    const checkBtn = createEl('button', ['btn', 'btn-outline-primary'], 'Status', btnGroup);
    checkBtn.addEventListener('click', () => handleCheckStatus(host, colStatus, checkBtn));

    const logsBtn = createEl('button', ['btn', 'btn-outline-dark'], 'Collect', btnGroup);
    logsBtn.title = 'Collect logs from this host and run the detection rules';
    logsBtn.addEventListener('click', () => handleFetchLogs(host, logsBtn));
}

async function handleCheckStatus(host, container, btn) {
    if (btn.disabled) return;
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = '…';

    clearContainer(container);
    createEl('div', ['text-muted', 'small'], 'Connecting…', container);

    try {
        const data = await checkHostStatus(host.id, host.os_type);
        clearContainer(container);
        const badges = createEl('div', ['d-flex', 'gap-1', 'flex-wrap'], '', container);
        addBadge(badges, 'RAM', `${data.free_ram_mb} MB`, 'text-success');
        addBadge(badges, 'Disk', data.disk_info, 'text-warning');
        addBadge(badges, 'CPU', data.cpu_load, 'text-info');
        addBadge(badges, 'Uptime', data.uptime_hours, 'text-secondary');
        btn.textContent = 'Refresh';
    } catch (err) {
        clearContainer(container);
        createEl('div', ['text-danger', 'small'], err.message, container);
        btn.textContent = 'Retry';
    } finally {
        btn.disabled = false;
        if (!btn.textContent) btn.textContent = original;
    }
}

function addBadge(parent, label, value, colorClass) {
    const box = createEl('div', ['text-center', 'border', 'rounded', 'px-2', 'py-1'], '', parent);
    const lbl = createEl('div', ['text-muted', 'text-uppercase'], label, box);
    lbl.style.fontSize = '0.65rem';
    const val = createEl('div', ['fw-bold', 'text-nowrap', colorClass], value || '?', box);
    val.style.fontSize = '0.8rem';
}

async function handleFetchLogs(host, btn) {
    if (btn.disabled) return;
    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = '…';

    try {
        const result = await triggerLogFetch(host.id);
        const alertCount = (result.alerts && result.alerts.total) || 0;

        notify(
            `${host.hostname}: ${result.message}. ${alertCount} new alert(s).`,
            alertCount > 0 ? 'warning' : 'success',
        );

        await Promise.allSettled([
            refreshStats(), refreshCharts(), refreshAlertsTable(),
            refreshTopSources(), refreshUsbDevices(),
        ]);
    } catch (err) {
        notify(`Log collection failed for ${host.hostname}: ${err.message}`, 'danger');
    } finally {
        btn.disabled = false;
        btn.textContent = original;
    }
}

// ======================= RECENT ALERTS =======================

async function refreshAlertsTable() {
    if (!alertsBody) return;
    clearContainer(alertsBody);

    try {
        const alerts = await fetchAlerts({ limit: 10 });

        if (alerts.length === 0) {
            emptyRow(alertsBody, 7, 'No alerts yet. Import sample logs from the Events page to see detection in action.');
            return;
        }

        alerts.forEach((alert) => {
            const row = createEl('tr', [], '', alertsBody);
            const highlight = severityRowClass(alert.severity);
            if (highlight) row.classList.add(highlight);

            createEl('td', ['text-nowrap', 'small'], formatTime(alert.timestamp), row);
            createEl('td', ['small', 'font-monospace'], alert.rule_id || '-', row);
            createEl('td', ['fw-bold'], alert.host_name, row);
            createEl('td', ['small'], alert.alert_type, row);
            createEl('td', ['font-monospace', 'small'], alert.source_ip || '-', row);
            createEl('td', ['small'], alert.message, row);

            const badgeCell = createEl('td', [], '', row);
            createEl('span', ['badge', ...severityClass(alert.severity).split(' ')],
                alert.severity, badgeCell);
        });
    } catch (err) {
        clearContainer(alertsBody);
        emptyRow(alertsBody, 7, `Error loading alerts: ${err.message}`);
    }
}
