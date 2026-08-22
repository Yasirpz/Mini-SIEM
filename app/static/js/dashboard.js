/**
 * Dashboard Module: summary statistics, charts, host status and recent alerts.
 */
import {
    createEl, clearContainer, emptyRow, notify,
    severityRowClass, severityBadge, formatTime,
    displayTimeZoneLabel, displayTimeZoneName,
    markLoaded, panelFailed, renderLivePill,
} from './dom.js';
import { createLiveRefresh, REFRESH_CHOICES, savedInterval } from './live.js';
import {
    fetchHosts, checkHostStatus, triggerLogFetch, fetchAlerts,
    fetchSummary, fetchSeverityStats, fetchRuleStats, fetchTimeline, fetchTopSources,
    fetchHostStats, fetchEvents, fetchSchedulerStatus, fetchAttackCoverage,
    fetchIntegrityChanges,
} from './api.js';

const hostsContainer = document.getElementById('hostsContainer');
const alertsBody = document.getElementById('alertsBody');
const topSources = document.getElementById('topSources');
const hostOverviewBody = document.getElementById('hostOverviewBody');
const usbBody = document.getElementById('usbBody');
const integrityBody = document.getElementById('integrityBody');
const liveStatus = document.getElementById('liveStatus');
const liveIndicator = document.getElementById('liveIndicator');
const lastUpdated = document.getElementById('lastUpdated');
const intervalSelect = document.getElementById('refreshInterval');
const attackBody = document.getElementById('attackBody');
const tacticStrip = document.getElementById('tacticStrip');
const attackSummary = document.getElementById('attackSummary');

// The refresh cadence itself lives in live.js, because the Alerts and Events
// pages have to agree with this one — a dashboard that updated every five
// seconds while the Events page needed a manual reload would just move the
// confusion somewhere else.
let live = null;

// Chart instances are kept so a refresh updates them instead of stacking
// a new canvas overlay on top of the old one.
const charts = {};

// Severity palette, reused by both the doughnut and the rule chart. Read from
// the stylesheet rather than repeated here, so the amber in a chart is the
// same amber as the badge beside it — two palettes drifting apart is how a
// dashboard stops being readable at a glance.
const COLORS = readPalette();

function readPalette() {
    const style = getComputedStyle(document.documentElement);
    const token = (name, fallback) =>
        (style.getPropertyValue(name) || '').trim() || fallback;

    return {
        low: token('--siem-low', '#38bdf8'),
        medium: token('--siem-medium', '#f59e0b'),
        high: token('--siem-high', '#ef4444'),
        accent: token('--siem-accent', '#22d3ee'),
        grid: token('--siem-grid', 'rgba(148, 163, 184, 0.18)'),
        muted: token('--siem-text-muted', '#94a3b8'),
    };
}

export async function initDashboard() {
    if (!hostsContainer) return;

    const refreshBtn = document.getElementById('refreshDashboard');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => live && live.refreshNow());
    }

    buildIntervalPicker();
    startLiveRefresh();
}

/**
 * Keep the page in step with the background collector.
 *
 * The dashboard re-reads the database the scheduler is writing to, so a USB
 * drive plugged into a monitored machine appears without anybody touching the
 * page. The timer only ever reads — collection itself is the server's job —
 * which is why running it every few seconds is affordable.
 *
 * The controller owns the first load as well as the repeats, so the indicator
 * moves through the same states on page open as on any later tick and there
 * is no separate startup path to get wrong.
 */
function startLiveRefresh() {
    live = createLiveRefresh({ refresh: loadAll, onStatus: renderLiveState });
    live.refreshNow();
}

/** Fill the interval picker and remember what the reader chooses. */
function buildIntervalPicker() {
    if (!intervalSelect) return;

    const current = savedInterval();
    REFRESH_CHOICES.forEach((choice) => {
        const option = createEl('option', [], choice.label, intervalSelect);
        option.value = String(choice.ms);
        if (choice.ms === current) option.selected = true;
    });

    intervalSelect.addEventListener('change', () => {
        if (live) live.setInterval(Number(intervalSelect.value));
    });
}

/**
 * Show whether the page is actually being kept up to date.
 *
 * A dashboard that has quietly stopped talking to the server looks exactly
 * like a dashboard where nothing is happening, and on a security console
 * those are opposite conclusions. A failed refresh therefore says so, keeps
 * the last good data on screen rather than blanking it, and keeps retrying —
 * the usual cause is a laptop's wifi, not the SIEM.
 */
function renderLiveState(status) {
    if (!liveIndicator) return;

    // A refresh in flight after a failure must not flicker back to a
    // reassuring "Updating"; it stays reported as lost until one succeeds.
    if (status.state === 'working' && live && !live.connected) return;

    // The pill itself is drawn by the shared helper, so this page and the
    // Alerts and Events pages cannot describe a lost connection differently.
    renderLivePill(liveIndicator, status);

    if (status.state === 'live') {
        if (lastUpdated) lastUpdated.textContent = formatTime(toApiTime(status.at));
        liveIndicator.title = 'This page is refreshing itself automatically.';
    } else if (status.state === 'lost') {
        liveIndicator.title = 'The last refresh failed: ' + status.error.message
            + '. The figures below are the last ones successfully read.';
    } else if (status.state === 'off') {
        liveIndicator.title =
            'Automatic refreshing is off. Use Refresh to update the page.';
    }
}

/**
 * A Date rendered the way the API renders one, so the "last updated" clock
 * goes through exactly the same timezone conversion as every other time on
 * the page. Formatting it separately is how that clock ends up disagreeing
 * with the rows underneath it.
 */
function toApiTime(date) {
    return date.toISOString().slice(0, 19).replace('T', ' ');
}

/**
 * Report whether collection is happening on its own, next to the title.
 *
 * Without this the dashboard is ambiguous in exactly the way the rest of this
 * project tries not to be: a quiet screen could mean nothing has happened, or
 * that nothing is watching.
 */
async function refreshLiveStatus() {
    if (!liveStatus) return;
    clearContainer(liveStatus);

    try {
        const status = await fetchSchedulerStatus();
        const polled = status.hosts_polled || 0;

        if (status.running && polled > 0) {
            const chip = statusChip('ok', 'Collector', `auto · ${polled} host(s)`);
            chip.title = `Collecting automatically from ${polled} host(s), `
                + `checked every ${status.tick_seconds}s.`
                + (status.next_poll
                    ? ` Next collection ${formatTime(status.next_poll)}.`
                    : '');
        } else {
            const chip = statusChip('idle', 'Collector', 'manual');
            chip.title = status.detail
                || 'No host is being collected from automatically. Switch it on '
                   + 'per host on the Configuration page.';
        }

        setPipelineStage('collect', polled);
        addTimeZoneNote();
    } catch (err) {
        // A failure here says nothing about the data already on the page, so
        // it is reported in its own chip rather than as a page-level error.
        statusChip('idle', 'Collector', 'unknown').title = err.message;
        addTimeZoneNote();
    }
}

/** One labelled chip on the status line under the page title. */
function statusChip(tone, label, value) {
    const chip = createEl('span', ['chip', `chip--${tone}`], '', liveStatus);
    createEl('span', ['chip-label'], label, chip);
    createEl('span', ['chip-value'], value, chip);
    return chip;
}

/**
 * Name the clock every time on this page is being read against.
 *
 * Stored times are UTC, so what appears on screen depends entirely on the
 * timezone of the machine looking at it. Saying which one turns "why is that
 * event five hours in the future?" into something the reader can diagnose
 * themselves rather than a mystery.
 */
function addTimeZoneNote() {
    const label = displayTimeZoneLabel();
    if (!label) return;

    const chip = statusChip('neutral', 'Times', label);
    chip.title = `Every time on this page is shown in ${displayTimeZoneName()}. `
        + 'Times are stored in UTC and converted for display, so they read the '
        + 'same on any machine.';
}

async function loadAll() {
    // Run the panels concurrently — one slow panel shouldn't hold up the rest.
    // Each panel reports its own failure in its own corner of the page, so one
    // rejection here is not fatal to the others.
    const results = await Promise.allSettled([
        refreshStats(),
        refreshCharts(),
        refreshTopSources(),
        refreshHostOverview(),
        refreshHostsList(),
        refreshAlertsTable(),
        refreshUsbDevices(),
        refreshIntegrityChanges(),
        refreshAttackCoverage(),
        refreshLiveStatus(),
    ]);

    // The summary is the cheapest call on the page and the first one issued.
    // If even that failed, the server is unreachable or the session has
    // expired, and the live indicator has to say so rather than let the page
    // sit there looking current. Anything else failing is a panel problem,
    // which that panel has already reported in its own place.
    if (results[0].status === 'rejected') throw results[0].reason;
}

// ======================= HOST OVERVIEW =======================

/** Per-host status, so it is obvious which machines are actually reporting. */
async function refreshHostOverview() {
    if (!hostOverviewBody) return;

    const statusStyles = {
        ONLINE: ['bg-success', '🟢 online'],
        DEGRADED: ['bg-warning text-dark', '🟡 degraded'],
        OFFLINE: ['bg-danger', '🔴 offline'],
        UNKNOWN: ['bg-secondary', '⚪ unknown'],
    };

    // Whether the host can report USB devices at all. DISABLED and UNKNOWN
    // are shown differently on purpose: the first is one command away from
    // being fixed, the second usually means the probe could not run.
    const usbAuditStyles = {
        ENABLED: ['bg-success', 'on', 'Plug and Play auditing is enabled — USB devices will be recorded.'],
        DISABLED: ['bg-secondary', 'off', 'Plug and Play auditing is off. Run: auditpol /set /subcategory:"Plug and Play Events" /success:enable'],
        UNKNOWN: ['bg-light text-dark border', '?', 'Not probed yet, or the audit policy could not be read. Use Status or Collect on this host.'],
    };

    try {
        // Fetched before anything is cleared, so a refresh that fails leaves
        // the previous rows on screen instead of emptying the table.
        const hosts = await fetchHostStats();
        clearContainer(hostOverviewBody);

        if (hosts.length === 0) {
            emptyRow(hostOverviewBody, 8, 'No hosts configured yet.');
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

            const usbCell = createEl('td', [], '', row);
            const [usbCls, usbLabel, usbTitle] =
                usbAuditStyles[host.usb_audit_status] || usbAuditStyles.UNKNOWN;
            const usbBadge = createEl('span', ['badge', ...usbCls.split(' ')], usbLabel, usbCell);
            usbBadge.title = usbTitle;

            createEl('td', ['text-end'], String(host.events), row);
            createEl('td', ['text-end'], String(host.alerts), row);
            createEl('td', ['small', 'text-muted'],
                host.last_success ? formatTime(host.last_success) : 'never', row);
        });
        markLoaded(hostOverviewBody);
    } catch (err) {
        if (panelFailed(hostOverviewBody)) {
            clearContainer(hostOverviewBody);
            emptyRow(hostOverviewBody, 8, `Could not load host status: ${err.message}`);
        }
    }
}

// ======================= SUMMARY STAT CARDS =======================

async function refreshStats() {
    // Deliberately not caught here. This is the call the live indicator uses
    // to decide whether the server is answering at all, so swallowing its
    // failure would leave a disconnected dashboard claiming to be live.
    const stats = await fetchSummary();

    Object.entries(stats).forEach(([key, value]) => {
        document.querySelectorAll(`[data-stat="${key}"]`).forEach((el) => {
            el.textContent = value;
        });
    });

    updatePipeline(stats);
}

/**
 * The four pipeline stages, each showing what it actually produced.
 *
 * Every figure is read back out of the database, so a stage that is not
 * running shows a zero. An animation implying work was happening would be
 * exactly the kind of decoration a security console should not have.
 */
function updatePipeline(stats) {
    setPipelineStage('process', stats.events_24h);
    setPipelineStage('alert', stats.alerts_24h);
}

function setPipelineStage(stage, value, note) {
    const el = document.querySelector('[data-pipeline="' + stage + '"]');
    if (el) {
        el.textContent = value;
        const step = el.closest('.pipeline-step');
        if (step) step.classList.toggle('is-active', Number(value) > 0);
    }
    if (note !== undefined) {
        const noteEl = document.querySelector('[data-pipeline-note="' + stage + '"]');
        if (noteEl) noteEl.textContent = note;
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
                    backgroundColor: 'rgba(34, 211, 238, 0.14)',
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
                plugins: {
                    legend: { position: 'bottom', labels: { color: COLORS.muted } },
                },
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
    // Grid lines and tick labels are drawn on a canvas, so they do not
    // inherit the page's colours the way the rest of the dashboard does. On a
    // dark console the Chart.js defaults come out as near-black on near-black
    // — legible in a screenshot of the light theme and invisible in use.
    return {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis,
        plugins: {
            legend: { display: legend, labels: { color: COLORS.muted } },
        },
        scales: {
            x: {
                grid: { display: false },
                ticks: { color: COLORS.muted },
            },
            // Alert counts are whole numbers; fractional ticks would be noise.
            y: {
                beginAtZero: true,
                ticks: { precision: 0, color: COLORS.muted },
                grid: { color: COLORS.grid },
            },
        },
    };
}

/**
 * Draw a chart, or update the one already there.
 *
 * Destroying and rebuilding every chart was acceptable when the dashboard
 * redrew itself every twenty seconds. At five it is not: the charts would
 * visibly blink, and any tooltip the reader was hovering over would be torn
 * out from under the cursor. Feeding new numbers into the existing chart
 * animates from the old values instead, which is both smoother and cheaper.
 */
function renderChart(canvasId, config) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;

    const existing = charts[canvasId];

    // Only a chart of the same kind can be updated in place; anything else
    // has to be rebuilt, or Chart.js is left holding scales it cannot use.
    if (existing && existing.config.type === config.type) {
        existing.data.labels = config.data.labels;
        config.data.datasets.forEach((dataset, index) => {
            if (existing.data.datasets[index]) {
                Object.assign(existing.data.datasets[index], dataset);
            } else {
                existing.data.datasets[index] = dataset;
            }
        });
        existing.data.datasets.length = config.data.datasets.length;
        existing.update();
        return;
    }

    if (existing) existing.destroy();
    charts[canvasId] = new Chart(canvas, config);
}

// ======================= ATT&CK COVERAGE =======================

/**
 * Which adversary behaviours this deployment can see, and which it has seen.
 *
 * Rules that have never fired are listed too, greyed rather than omitted. A
 * panel showing only what had triggered would say nothing about coverage,
 * which is the question this panel exists to answer: an empty Persistence row
 * means "watched, nothing seen", and that is a finding.
 */
async function refreshAttackCoverage() {
    if (!attackBody) return;

    try {
        const data = await fetchAttackCoverage();

        renderTacticStrip(data.tactics);
        renderTechniqueTable(data.techniques);

        if (attackSummary) {
            attackSummary.textContent =
                `${data.techniques_observed} of ${data.techniques_total} techniques `
                + `observed · ${data.rules_triggered} of ${data.rules_total} rules `
                + 'have fired';
        }
        setPipelineStage('detect', data.rules_triggered);
        markLoaded(attackBody);
    } catch (err) {
        if (panelFailed(attackBody)) {
            clearContainer(attackBody);
            emptyRow(attackBody, 6, `Could not load ATT&CK coverage: ${err.message}`);
            if (attackSummary) attackSummary.textContent = 'Unavailable';
        }
    }
}

function renderTacticStrip(tactics) {
    if (!tacticStrip) return;
    clearContainer(tacticStrip);

    tactics.forEach((tactic) => {
        const card = createEl('div', ['tactic'], '', tacticStrip);
        if (tactic.alerts > 0) card.classList.add('is-hit');

        createEl('div', ['tactic-name'], tactic.tactic, card);
        createEl('div', ['tactic-count'], String(tactic.alerts), card);
        createEl('div', ['tactic-rules'], tactic.rules.join(' · '), card);
        card.title = tactic.alerts > 0
            ? `${tactic.alerts} alert(s) from ${tactic.rules.join(', ')}.`
            : `Covered by ${tactic.rules.join(', ')}, but nothing has been `
              + 'seen at this stage.';
    });
}

function renderTechniqueTable(techniques) {
    clearContainer(attackBody);

    techniques.forEach((entry) => {
        const row = createEl('tr', [], '', attackBody);
        if (entry.alerts === 0) row.classList.add('is-quiet');

        createEl('td', ['mono', 'fw-semibold'], entry.rule_id, row);

        const detects = createEl('td', ['small'], entry.summary, row);
        detects.title = entry.rationale;

        // The technique identifier links out to MITRE, which is the point of
        // using their vocabulary: the reader can check the claim rather than
        // taking this project's word for it.
        const techCell = createEl('td', ['small'], '', row);
        const link = createEl('a', ['mono', 'tech-link'], entry.technique_id, techCell);
        link.href = entry.technique_url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.title = entry.rationale;
        createEl('div', ['tech-name'], entry.technique_name, techCell);

        createEl('td', ['small'], entry.tactic, row);

        const count = createEl('td', ['text-end', 'fw-semibold'],
            String(entry.alerts), row);
        if (entry.alerts > 0) count.classList.add('text-bad');

        createEl('td', ['small', 'text-muted', 'text-nowrap'],
            entry.last_seen ? formatTime(entry.last_seen) : 'never', row);
    });
}

// ======================= TOP SOURCE IPs =======================

async function refreshTopSources() {
    if (!topSources) return;

    try {
        const sources = await fetchTopSources(5);
        clearContainer(topSources);

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
        markLoaded(topSources);
    } catch (err) {
        if (panelFailed(topSources)) {
            clearContainer(topSources);
            createEl('li', ['list-group-item', 'text-muted', 'small'],
                `Could not load top sources: ${err.message}`, topSources);
        }
    }
}

// ======================= REMOVABLE MEDIA =======================

/**
 * Recent file integrity findings, with the hashes behind them.
 *
 * "Watched file was modified" is an assertion; a pair of hashes is evidence.
 * Both are shown, because an analyst writing this up has to be able to quote
 * the thing that actually changed, and a truncated digest is enough to
 * compare by eye while the full value stays available on hover.
 */
async function refreshIntegrityChanges() {
    if (!integrityBody) return;

    const labels = {
        FILE_MODIFIED: ['modified', 'fim--modified'],
        FILE_DELETED: ['deleted', 'fim--deleted'],
        FILE_ADDED: ['appeared', 'fim--added'],
    };

    try {
        const data = await fetchIntegrityChanges(10);
        clearContainer(integrityBody);

        if (data.changes.length === 0) {
            // An empty panel is the healthy state here, but it is also what a
            // host with nothing watched looks like — so say which of the two
            // this is rather than leaving the reader to guess.
            emptyRow(integrityBody, 6, data.watched_paths > 0
                ? `No integrity changes recorded. ${data.watched_paths} path(s) `
                  + 'are being watched and all files still match their baseline.'
                : 'Nothing is being watched yet. Add a watched path on the '
                  + 'Configuration page to start checking files.');
            return;
        }

        data.changes.forEach((change) => {
            const row = createEl('tr', [], '', integrityBody);
            createEl('td', ['text-nowrap', 'small'], formatTime(change.timestamp), row);
            createEl('td', ['small'], change.host_name, row);

            const [label, cls] = labels[change.event_type] || ['changed', ''];
            const cell = createEl('td', [], '', row);
            createEl('span', ['fim-tag', cls].filter(Boolean), label, cell);

            const fileCell = createEl('td', ['small', 'mono', 'text-truncate'],
                change.file_path || '-', row);
            fileCell.style.maxWidth = '260px';
            fileCell.title = change.message || change.file_path || '';

            hashCell(row, change.previous_sha256);
            hashCell(row, change.sha256);
        });
        markLoaded(integrityBody);
    } catch (err) {
        if (panelFailed(integrityBody)) {
            clearContainer(integrityBody);
            emptyRow(integrityBody, 6,
                `Could not load integrity changes: ${err.message}`);
        }
    }
}

/**
 * One SHA-256, shortened to something a person can compare.
 *
 * Twelve characters is roughly what the eye can check in one go, and the full
 * digest stays on the element's title so nothing is actually lost. A file
 * that has just appeared has no previous hash, and that is shown as a dash
 * rather than as an empty cell that could be read as a rendering failure.
 */
function hashCell(row, digest) {
    const cell = createEl('td', ['small', 'mono', 'hash'], digest ? digest.slice(0, 12) : '—', row);
    cell.title = digest || 'Not applicable for this kind of change.';
    return cell;
}

/**
 * Recent USB connections, read from the ordinary events endpoint with an
 * event_type filter. A dedicated API route would duplicate logic that
 * /api/events already performs, so none is added.
 */
async function refreshUsbDevices() {
    if (!usbBody) return;

    try {
        const data = await fetchEvents({ event_type: 'USB_DEVICE_CONNECTED', limit: 10 });
        clearContainer(usbBody);

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
        markLoaded(usbBody);
    } catch (err) {
        if (panelFailed(usbBody)) {
            clearContainer(usbBody);
            emptyRow(usbBody, 4, `Could not load USB devices: ${err.message}`);
        }
    }
}

// ======================= HOST STATUS =======================

async function refreshHostsList() {
    try {
        const hosts = await fetchHosts();
        clearContainer(hostsContainer);

        if (hosts.length === 0) {
            createEl('div', ['p-4', 'text-center', 'text-muted'],
                'No hosts yet. Add one in the Configuration panel.', hostsContainer);
            return;
        }
        hosts.forEach(renderDashboardRow);
        markLoaded(hostsContainer);
    } catch (err) {
        if (panelFailed(hostsContainer)) {
            clearContainer(hostsContainer);
            createEl('div', ['alert', 'alert-danger', 'mb-0'],
                `Error loading hosts: ${err.message}`, hostsContainer);
        }
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

        // The host overview is included because a collection updates the
        // host's own row — its event and alert counts, when it was last
        // collected, and the USB auditing state the collection just probed.
        // Leaving it out meant pressing Collect refreshed everything except
        // the table describing the host you had just collected from.
        await Promise.allSettled([
            refreshStats(), refreshCharts(), refreshAlertsTable(),
            refreshTopSources(), refreshUsbDevices(), refreshHostOverview(),
            refreshIntegrityChanges(),
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

    try {
        const alerts = await fetchAlerts({ limit: 10 });
        clearContainer(alertsBody);

        if (alerts.length === 0) {
            emptyRow(alertsBody, 7, 'No alerts yet. Import sample logs from the '
                + 'Events page to see detection in action.');
            return;
        }

        alerts.forEach((alert) => {
            const row = createEl('tr', [], '', alertsBody);
            const highlight = severityRowClass(alert.severity);
            if (highlight) row.classList.add(highlight);

            // Severity leads the row. It is the first thing that decides
            // whether the rest of the row is worth reading, and putting it
            // last meant scanning past six columns to find out.
            severityBadge(alert.severity, createEl('td', [], '', row));

            createEl('td', ['text-nowrap', 'small'], formatTime(alert.timestamp), row);

            const ruleCell = createEl('td', ['small'], '', row);
            createEl('div', ['mono', 'fw-semibold'], alert.rule_id || '-', ruleCell);
            if (alert.rule_name) {
                createEl('div', ['text-muted', 'tech-name'], alert.rule_name, ruleCell);
            }

            // The ATT&CK technique, so the alert can be understood and
            // checked by somebody who has never seen this project's rule
            // numbering.
            const techCell = createEl('td', ['small'], '', row);
            if (alert.technique_id) {
                const link = createEl('a', ['mono', 'tech-link'],
                    alert.technique_id, techCell);
                link.href = alert.technique_url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.title = `${alert.technique_name} (${alert.tactic})`;
                createEl('div', ['tech-name'], alert.tactic, techCell);
            } else {
                createEl('span', ['text-muted'], '-', techCell);
            }

            createEl('td', ['fw-semibold', 'small'], alert.host_name, row);
            createEl('td', ['mono', 'small'], alert.source_ip || '-', row);
            createEl('td', ['small'], alert.message, row);
        });
        markLoaded(alertsBody);
    } catch (err) {
        if (panelFailed(alertsBody)) {
            clearContainer(alertsBody);
            emptyRow(alertsBody, 7, `Error loading alerts: ${err.message}`);
        }
    }
}
