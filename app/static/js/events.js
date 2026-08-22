/**
 * Log Analysis Module page: sample log import and stored event browsing.
 */
import {
    createEl, clearContainer, emptyRow, notify, formatTime,
    markLoaded, panelFailed, renderLivePill,
} from './dom.js';
import { createLiveRefresh } from './live.js';
import {
    fetchEvents, fetchHosts, fetchSamples, importBundledSample,
    uploadSample, importPastedLog, generateEvents, clearEvents,
} from './api.js';

const PAGE_SIZE = 25;

const eventsBody = document.getElementById('eventsBody');
const countLabel = document.getElementById('eventsCount');
const pageLabel = document.getElementById('pageLabel');
const prevBtn = document.getElementById('prevPage');
const nextBtn = document.getElementById('nextPage');
const importResult = document.getElementById('importResult');
const livePill = document.getElementById('liveIndicator');

let offset = 0;
let total = 0;

export async function initEvents() {
    if (!eventsBody) return;

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

    document.getElementById('uploadBtn').addEventListener('click', handleUpload);
    document.getElementById('pasteBtn').addEventListener('click', handlePaste);
    document.getElementById('generateBtn').addEventListener('click', handleGenerate);
    document.getElementById('clearEvents').addEventListener('click', handleClear);

    await populateHosts();
    await populateSamples();

    // The Events page is where newly collected records actually appear, so it
    // follows the collector on the same cadence as the dashboard. The current
    // filters and page are read afresh each time, so an auto-refresh never
    // drags the reader back to page one or discards what they filtered on.
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

// ======================= HOST + SAMPLE PICKERS =======================

async function populateHosts() {
    const importSelect = document.getElementById('importHost');
    const filterSelect = document.getElementById('filterHost');
    clearContainer(importSelect);

    try {
        const hosts = await fetchHosts();

        if (hosts.length === 0) {
            const option = createEl('option', [], 'No hosts — add one in Configuration first', importSelect);
            option.value = '';
            return;
        }

        hosts.forEach((host, index) => {
            const label = `${host.hostname} (${host.ip_address})`;

            const importOption = createEl('option', [], label, importSelect);
            importOption.value = host.id;
            if (index === 0) importOption.selected = true;

            const filterOption = createEl('option', [], label, filterSelect);
            filterOption.value = host.id;
        });
    } catch (err) {
        notify(`Could not load hosts: ${err.message}`, 'danger');
    }
}

async function populateSamples() {
    const list = document.getElementById('sampleList');
    clearContainer(list);

    try {
        const samples = await fetchSamples();
        if (samples.length === 0) {
            createEl('div', ['text-muted', 'small'], 'No sample files found in the samples folder.', list);
            return;
        }

        samples.forEach((sample) => {
            const item = createEl('div',
                ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center', 'px-0'],
                '', list);

            const info = createEl('div', [], '', item);
            createEl('div', ['font-monospace', 'small'], sample.name, info);
            createEl('small', ['text-muted'], `${(sample.size / 1024).toFixed(1)} KB`, info);

            const btn = createEl('button', ['btn', 'btn-sm', 'btn-outline-primary'], 'Import', item);
            btn.addEventListener('click', () => handleBundled(sample.name, btn));
        });
    } catch (err) {
        createEl('div', ['text-danger', 'small'], `Could not list samples: ${err.message}`, list);
    }
}

// ======================= IMPORT ACTIONS =======================

function selectedHost() {
    const value = document.getElementById('importHost').value;
    if (!value) {
        notify('Select a target host first. Add one in the Configuration panel if the list is empty.', 'warning');
        return null;
    }
    return parseInt(value, 10);
}

async function withBusy(btn, action) {
    if (!btn) return action();

    const original = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Working…';
    try {
        return await action();
    } finally {
        btn.disabled = false;
        btn.textContent = original;
    }
}

function showImportResult(result) {
    clearContainer(importResult);

    const counts = result.alerts || { total: 0 };
    const category = counts.total > 0 ? 'warning' : 'success';
    const box = createEl('div', ['alert', `alert-${category}`, 'mb-0'], '', importResult);

    createEl('div', ['fw-bold'], result.message, box);

    const detail = createEl('div', ['small', 'mt-1'], '', box);
    createEl('span', [], `Format: ${result.format} · `, detail);
    createEl('span', [], `Stored: ${result.events_stored} · `, detail);
    createEl('span', [], `Duplicates skipped: ${result.duplicates_skipped} · `, detail);
    createEl('span', [], `Archived: ${result.archive_file || 'n/a'}`, detail);

    const rules = createEl('div', ['small', 'mt-1'], '', box);
    createEl('span', ['fw-bold'], 'Alerts raised — ', rules);
    // Read the rule ids back off the response rather than listing them here,
    // so adding a rule to the engine does not silently drop it from this
    // summary. 'total' is a roll-up, not a rule, so it is excluded.
    Object.keys(counts)
        .filter((key) => key !== 'total')
        .sort()
        .forEach((rule) => {
            createEl('span', ['me-2'], `${rule}: ${counts[rule] || 0}`, rules);
        });

    if (counts['R-03'] === 0) {
        createEl('div', ['small', 'mt-2', 'fst-italic'],
            'Tip: mark a source IP as BANNED in Configuration, then use ' +
            '"Re-run detection" on the Alerts page to trigger rule R-03.', box);
    }
}

async function handleBundled(name, btn) {
    const hostId = selectedHost();
    if (!hostId) return;

    await withBusy(btn, async () => {
        try {
            const result = await importBundledSample(name, hostId);
            showImportResult(result);
            offset = 0;
            await load();
        } catch (err) {
            notify(`Import failed: ${err.message}`, 'danger');
        }
    });
}

async function handleUpload(event) {
    const hostId = selectedHost();
    if (!hostId) return;

    const input = document.getElementById('uploadFile');
    if (!input.files || input.files.length === 0) {
        notify('Choose a file to upload first.', 'warning');
        return;
    }

    await withBusy(event.currentTarget, async () => {
        try {
            const result = await uploadSample(input.files[0], hostId);
            showImportResult(result);
            input.value = '';
            offset = 0;
            await load();
        } catch (err) {
            notify(`Upload failed: ${err.message}`, 'danger');
        }
    });
}

async function handlePaste(event) {
    const hostId = selectedHost();
    if (!hostId) return;

    const area = document.getElementById('pasteArea');
    if (!area.value.trim()) {
        notify('Paste some log lines first.', 'warning');
        return;
    }

    await withBusy(event.currentTarget, async () => {
        try {
            const result = await importPastedLog(area.value, hostId);
            showImportResult(result);
            offset = 0;
            await load();
        } catch (err) {
            notify(`Import failed: ${err.message}`, 'danger');
        }
    });
}

async function handleGenerate(event) {
    const hostId = selectedHost();
    if (!hostId) return;

    const sourceIp = document.getElementById('genIP').value.trim() || '203.0.113.50';
    const attempts = parseInt(document.getElementById('genCount').value, 10) || 8;

    await withBusy(event.currentTarget, async () => {
        try {
            const result = await generateEvents(hostId, sourceIp, attempts);
            showImportResult(result);
            offset = 0;
            await load();
        } catch (err) {
            notify(`Generation failed: ${err.message}`, 'danger');
        }
    });
}

async function handleClear(event) {
    const hostFilter = document.getElementById('filterHost').value;
    const scope = hostFilter ? 'the selected host' : 'ALL hosts';

    if (!window.confirm(
        `Delete stored events for ${scope}? Their alerts are removed too. ` +
        'Archived Parquet files on disk are kept.'
    )) {
        return;
    }

    await withBusy(event.currentTarget, async () => {
        try {
            const result = await clearEvents(hostFilter || null);
            notify(result.message, 'info');
            clearContainer(importResult);
            offset = 0;
            await load();
        } catch (err) {
            notify(`Could not clear events: ${err.message}`, 'danger');
        }
    });
}

// ======================= EVENT TABLE =======================

/**
 * Fetch and draw the current page of events.
 *
 * `quiet` suppresses the "Loading…" placeholder. A deliberate action deserves
 * that feedback; the five-second auto-refresh does not, and showing it would
 * make the table flash once every five seconds for no reason.
 */
async function load({ quiet = false } = {}) {
    if (!quiet) {
        clearContainer(eventsBody);
        emptyRow(eventsBody, 7, 'Loading…');
    }

    try {
        const data = await fetchEvents({
            host_id: document.getElementById('filterHost').value,
            event_type: document.getElementById('filterType').value,
            source_ip: document.getElementById('filterIP').value.trim(),
            limit: PAGE_SIZE,
            offset,
        });

        total = data.total;
        render(data.events);
        updatePager();
    } catch (err) {
        // The rows already on screen are kept and dimmed rather than wiped.
        // The live indicator at the top of the page is what reports that the
        // connection is down; this table only stops claiming to be current.
        if (panelFailed(eventsBody)) {
            clearContainer(eventsBody);
            emptyRow(eventsBody, 7, `Error loading events: ${err.message}`);
        }
    }
}

function render(events) {
    clearContainer(eventsBody);

    if (events.length === 0) {
        emptyRow(eventsBody, 7, 'No events stored yet. Import a sample log above to get started.');
        countLabel.textContent = '0 events';
        return;
    }

    countLabel.textContent = `${total} event${total === 1 ? '' : 's'} matched`;
    markLoaded(eventsBody);

    events.forEach((event) => {
        const row = createEl('tr', [], '', eventsBody);

        createEl('td', ['text-nowrap', 'small'], formatTime(event.timestamp), row);
        createEl('td', ['small'], event.host_name, row);

        const typeCell = createEl('td', [], '', row);
        createEl('span', ['badge', ...eventTypeClasses(event.event_type)],
            event.event_type, typeCell);

        createEl('td', ['font-monospace', 'small'], event.source_ip || '-', row);
        createEl('td', ['small'], event.username || '-', row);
        createEl('td', ['small', 'text-truncate'], event.message || '', row).style.maxWidth = '340px';
        createEl('td', ['small', 'text-muted'], event.origin, row);
    });
}

/**
 * Badge styling per event type: failures amber, successful logons green,
 * removable media cyan, so a mixed Windows collection is readable at a glance.
 */
function eventTypeClasses(eventType) {
    switch (eventType) {
        case 'FAILED_LOGIN':
        case 'INVALID_USER':
        case 'WIN_FAILED_LOGIN':
            return ['bg-warning', 'text-dark'];
        case 'SUCCESSFUL_LOGIN':
            return ['bg-success'];
        // Post-compromise activity: privilege, persistence, anti-forensics.
        case 'ACCOUNT_LOCKOUT':
        case 'AUDIT_LOG_CLEARED':
        case 'ACCOUNT_CREATED':
        case 'GROUP_MEMBER_ADDED':
        case 'PASSWORD_RESET':
            return ['bg-danger'];
        case 'ADMIN_LOGON':
        case 'EXPLICIT_CREDENTIALS':
        case 'ACCOUNT_ENABLED':
            return ['bg-primary'];
        // Physical rather than network activity, so it gets its own colour
        // instead of sharing one with the logon events around it.
        case 'USB_DEVICE_CONNECTED':
            return ['bg-info', 'text-dark'];
        default:
            return ['bg-secondary'];
    }
}

function updatePager() {
    const page = Math.floor(offset / PAGE_SIZE) + 1;
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

    pageLabel.textContent = `Page ${page} of ${pages}`;
    prevBtn.disabled = offset === 0;
    nextBtn.disabled = offset + PAGE_SIZE >= total;
}
