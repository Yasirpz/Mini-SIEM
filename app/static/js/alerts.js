/**
 * Alert Module page: filtering, pagination and acknowledgement.
 */
import {
    createEl, clearContainer, emptyRow, notify,
    severityRowClass, severityBadge, formatTime,
    markLoaded, panelFailed, renderLivePill,
} from './dom.js';
import {
    fetchAlerts, acknowledgeAlert, fetchHosts, runDetection, fetchAttackCoverage,
} from './api.js';
import { createLiveRefresh } from './live.js';

const PAGE_SIZE = 25;

const livePill = document.getElementById('liveIndicator');

const alertsBody = document.getElementById('alertsBody');
const countLabel = document.getElementById('alertsCount');
const pageLabel = document.getElementById('pageLabel');
const prevBtn = document.getElementById('prevPage');
const nextBtn = document.getElementById('nextPage');

let offset = 0;
let total = 0;

export async function initAlerts() {
    if (!alertsBody) return;

    document.getElementById('applyFilters').addEventListener('click', () => {
        offset = 0;
        load();
    });
    prevBtn.addEventListener('click', () => {
        offset = Math.max(0, offset - PAGE_SIZE);
        load();
    });
    nextBtn.addEventListener('click', () => {
        offset += PAGE_SIZE;
        load();
    });

    const rerun = document.getElementById('rerunDetection');
    if (rerun) rerun.addEventListener('click', handleRerun);

    await Promise.all([populateHostFilter(), populateRuleFilter()]);

    // Alerts are written by the detection rules that run at the end of every
    // automatic collection, so this page has to follow the collector too --
    // an alert nobody is shown until they press reload is not an alert. The
    // cadence is whatever was last chosen on the dashboard, so the two pages
    // do not disagree about how live "live" is.
    //
    // The first load goes through the controller as well, so the indicator
    // reports the truth from the moment the page opens rather than sitting on
    // "Connecting" until the first tick comes round.
    let drawn = false;
    const live = createLiveRefresh({
        refresh: async () => {
            await load({ quiet: drawn });
            drawn = true;
        },
        onStatus: (status) => renderLivePill(livePill, status),
    });
    live.refreshNow();
}

/**
 * Fill the rule filter from the catalogue rather than from a list typed into
 * the template. The hand-written list had gone stale: R-10 existed in the
 * engine and could not be filtered for here.
 */
async function populateRuleFilter() {
    const select = document.getElementById('filterRule');
    if (!select) return;

    try {
        const data = await fetchAttackCoverage();
        data.techniques.forEach((rule) => {
            const option = createEl('option', [], `${rule.rule_id} ${rule.name}`, select);
            option.value = rule.rule_id;
            option.title = `${rule.summary} (ATT&CK ${rule.technique_id})`;
        });
    } catch (err) {
        // The filter is a convenience; the table below is the point of the
        // page, so a failure here must not stop it loading.
        console.error('Could not load the rule list:', err);
    }
}

async function populateHostFilter() {
    const select = document.getElementById('filterHost');
    if (!select) return;

    try {
        const hosts = await fetchHosts();
        hosts.forEach((host) => {
            const option = createEl('option', [], `${host.hostname} (${host.ip_address})`, select);
            option.value = host.id;
        });
    } catch (err) {
        console.error('Could not load hosts for the filter:', err);
    }
}

function currentFilters() {
    return {
        severity: document.getElementById('filterSeverity').value,
        rule_id: document.getElementById('filterRule').value,
        host_id: document.getElementById('filterHost').value,
        acknowledged: document.getElementById('filterAck').value,
    };
}

/** Fetch and draw the current page. `quiet` skips the "Loading…" flash. */
async function load({ quiet = false } = {}) {
    if (!quiet) {
        clearContainer(alertsBody);
        emptyRow(alertsBody, 8, 'Loading…');
    }

    try {
        const data = await fetchAlerts({
            ...currentFilters(),
            paginated: 'true',
            limit: PAGE_SIZE,
            offset,
        });

        total = data.total;
        render(data.alerts);
        updatePager();
    } catch (err) {
        if (panelFailed(alertsBody)) {
            clearContainer(alertsBody);
            emptyRow(alertsBody, 9, `Error loading alerts: ${err.message}`);
        }
    }
}

function render(alerts) {
    clearContainer(alertsBody);

    if (alerts.length === 0) {
        emptyRow(alertsBody, 9, 'No alerts match these filters.');
        countLabel.textContent = '0 alerts';
        return;
    }

    countLabel.textContent = `${total} alert${total === 1 ? '' : 's'} matched`;

    alerts.forEach((alert) => {
        const row = createEl('tr', [], '', alertsBody);
        const highlight = severityRowClass(alert.severity);
        if (highlight) row.classList.add(highlight);
        if (alert.acknowledged) row.classList.add('opacity-50');

        // Severity leads, as on the dashboard: it is what decides whether the
        // rest of the row is worth reading.
        severityBadge(alert.severity, createEl('td', [], '', row));

        createEl('td', ['text-nowrap', 'small'], formatTime(alert.timestamp), row);

        const ruleCell = createEl('td', ['small'], '', row);
        createEl('div', ['mono', 'fw-semibold'], alert.rule_id || '-', ruleCell);
        if (alert.rule_name) {
            createEl('div', ['text-muted', 'tech-name'], alert.rule_name, ruleCell);
        }

        const techCell = createEl('td', ['small'], '', row);
        if (alert.technique_id) {
            const link = createEl('a', ['mono', 'tech-link'], alert.technique_id, techCell);
            link.href = alert.technique_url;
            link.target = '_blank';
            link.rel = 'noopener noreferrer';
            link.title = `${alert.technique_name} (${alert.tactic})`;
            createEl('div', ['tech-name'], alert.tactic, techCell);
        } else {
            createEl('span', ['text-muted'], '-', techCell);
        }

        createEl('td', ['fw-semibold', 'small'], alert.host_name, row);
        createEl('td', ['small', 'text-muted'], alert.alert_type, row);
        createEl('td', ['mono', 'small'], alert.source_ip || '-', row);
        createEl('td', ['small'], alert.message, row);

        const actionCell = createEl('td', ['text-end'], '', row);
        const ackBtn = createEl('button',
            ['btn', 'btn-sm', alert.acknowledged ? 'btn-outline-secondary' : 'btn-outline-success'],
            alert.acknowledged ? 'Reviewed' : 'Mark reviewed',
            actionCell);

        ackBtn.addEventListener('click', async () => {
            ackBtn.disabled = true;
            try {
                await acknowledgeAlert(alert.id, !alert.acknowledged);
                await load();
            } catch (err) {
                notify(err.message, 'danger');
                ackBtn.disabled = false;
            }
        });
    });

    markLoaded(alertsBody);
}

function updatePager() {
    const page = Math.floor(offset / PAGE_SIZE) + 1;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    pageLabel.textContent = `Page ${page} of ${pages}`;
    prevBtn.disabled = offset === 0;
    nextBtn.disabled = offset + PAGE_SIZE >= total;
}

async function handleRerun(event) {
    const btn = event.currentTarget;
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = 'Running…';

    try {
        const result = await runDetection(null);
        const counts = result.alerts;
        // Built from whatever rules the engine actually reported, so a new
        // rule appears here automatically instead of being left out of the
        // summary until someone remembers to update this line.
        const breakdown = Object.keys(counts)
            .filter((key) => key !== 'total')
            .sort()
            .map((rule) => `${rule}: ${counts[rule]}`)
            .join(', ');
        notify(
            `${result.message} (${breakdown})`,
            counts.total > 0 ? 'warning' : 'info',
        );
        offset = 0;
        await load();
    } catch (err) {
        notify(`Detection failed: ${err.message}`, 'danger');
    } finally {
        btn.disabled = false;
        btn.textContent = original;
    }
}
