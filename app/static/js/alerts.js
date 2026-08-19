/**
 * Alert Module page: filtering, pagination and acknowledgement.
 */
import {
    createEl, clearContainer, emptyRow, notify,
    severityClass, severityRowClass, formatTime,
} from './dom.js';
import { fetchAlerts, acknowledgeAlert, fetchHosts, runDetection } from './api.js';

const PAGE_SIZE = 25;

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

    await populateHostFilter();
    await load();
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

async function load() {
    clearContainer(alertsBody);
    emptyRow(alertsBody, 8, 'Loading…');

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
        clearContainer(alertsBody);
        emptyRow(alertsBody, 8, `Error loading alerts: ${err.message}`);
    }
}

function render(alerts) {
    clearContainer(alertsBody);

    if (alerts.length === 0) {
        emptyRow(alertsBody, 8, 'No alerts match these filters.');
        countLabel.textContent = '0 alerts';
        return;
    }

    countLabel.textContent = `${total} alert${total === 1 ? '' : 's'} matched`;

    alerts.forEach((alert) => {
        const row = createEl('tr', [], '', alertsBody);
        const highlight = severityRowClass(alert.severity);
        if (highlight) row.classList.add(highlight);
        if (alert.acknowledged) row.classList.add('opacity-50');

        createEl('td', ['text-nowrap', 'small'], formatTime(alert.timestamp), row);
        createEl('td', ['small', 'font-monospace'], alert.rule_id || '-', row);
        createEl('td', ['fw-bold', 'small'], alert.host_name, row);
        createEl('td', ['small'], alert.alert_type, row);
        createEl('td', ['font-monospace', 'small'], alert.source_ip || '-', row);
        createEl('td', ['small'], alert.message, row);

        const badgeCell = createEl('td', [], '', row);
        createEl('span', ['badge', ...severityClass(alert.severity).split(' ')],
            alert.severity, badgeCell);

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
