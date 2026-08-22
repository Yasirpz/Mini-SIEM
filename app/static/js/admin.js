/**
 * Administration panel: host management and the Threat Intelligence registry.
 */
import { createEl, clearContainer, notify, formatTime } from './dom.js';
import {
    fetchHosts, createHost, updateHost, removeHost, triggerLogFetch,
    testHostConnection, fetchIPs, createIP, updateIP, removeIP,
    fetchSchedulerStatus, runSchedulerNow,
    fetchWatchedPaths, createWatchedPath, removeWatchedPath,
    runIntegrityScan, resetBaseline,
} from './api.js';

const hostsContainer = document.getElementById('hostsListAdmin');
const hostForm = document.getElementById('hostForm');
const ipContainer = document.getElementById('ipListAdmin');
const ipForm = document.getElementById('ipForm');

let hostModal = null;
let ipModal = null;
let fimModal = null;
// The host whose watched paths the integrity dialog is currently showing.
let fimHost = null;

export async function initAdmin() {
    const hostModalEl = document.getElementById('editHostModal');
    if (hostModalEl) hostModal = new bootstrap.Modal(hostModalEl);

    const ipModalEl = document.getElementById('editIPModal');
    if (ipModalEl) ipModal = new bootstrap.Modal(ipModalEl);

    const fimModalEl = document.getElementById('fileIntegrityModal');
    if (fimModalEl) fimModal = new bootstrap.Modal(fimModalEl);

    if (hostForm) hostForm.addEventListener('submit', handleAddHost);
    if (ipForm) ipForm.addEventListener('submit', handleAddIP);

    bindClick('saveHostBtn', handleSaveHost);
    bindClick('scanNowBtn', handleScanNow);
    bindClick('resetBaselineBtn', handleResetBaseline);

    const watchForm = document.getElementById('watchedPathForm');
    if (watchForm) watchForm.addEventListener('submit', handleAddWatchedPath);
    bindClick('saveIPBtn', handleSaveIP);
    bindClick('refreshHostsBtn', refreshHosts);
    bindClick('refreshIPsBtn', refreshIPs);

    const runNowBtn = document.getElementById('runSchedulerBtn');
    if (runNowBtn) {
        runNowBtn.addEventListener('click', () => handleRunSchedulerNow(runNowBtn));
    }

    if (hostsContainer) await refreshHosts();
    if (ipContainer) await refreshIPs();
}

function bindClick(id, handler) {
    const el = document.getElementById(id);
    if (el) el.addEventListener('click', handler);
}

// ======================= HOST MANAGEMENT =======================

async function refreshHosts() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        if (hosts.length === 0) {
            createEl('div', ['list-group-item', 'text-muted', 'small'],
                'No hosts yet. Add the first one using the form.', hostsContainer);
            return;
        }
        hosts.forEach(renderHostRow);
        await refreshSchedulerPanel();
    } catch (err) {
        createEl('div', ['list-group-item', 'text-danger', 'small'],
            `Error loading hosts: ${err.message}`, hostsContainer);
    }
}

function renderHostRow(host) {
    const item = createEl('div',
        ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'],
        '', hostsContainer);

    const info = createEl('div', ['overflow-hidden'], '', item);
    const title = createEl('div', [], '', info);
    createEl('span', ['me-2'], host.os_type === 'LINUX' ? '🐧' : '🪟', title);
    createEl('span', ['fw-bold', 'me-2'], host.hostname, title);
    createEl('small', ['text-muted', 'font-monospace', 'me-2'], host.ip_address, title);

    // Health first: it is the thing an operator looks for.
    const statusStyles = {
        ONLINE: ['bg-success', '🟢 online'],
        DEGRADED: ['bg-warning text-dark', '🟡 degraded'],
        OFFLINE: ['bg-danger', '🔴 offline'],
        UNKNOWN: ['bg-secondary', '⚪ not yet contacted'],
    };
    const [statusClass, statusLabel] = statusStyles[host.status] || statusStyles.UNKNOWN;
    const statusBadge = createEl('span',
        ['badge', ...statusClass.split(' '), 'me-2'], statusLabel, title);
    if (host.last_error) statusBadge.title = host.last_error;

    // Make it obvious whether a host is read locally or over the network.
    const methodLabels = {
        LOCAL: 'local',
        WINRM: 'remote · WinRM',
        SSH: 'remote · SSH',
    };
    const badgeClass = host.collection_method === 'LOCAL' ? 'bg-secondary' : 'bg-info';
    createEl('span', ['badge', badgeClass],
        methodLabels[host.collection_method] || host.collection_method, title);

    const facts = [];
    if (host.last_success) facts.push(`last collected ${formatTime(host.last_success)}`);
    if (host.last_latency_ms != null) facts.push(`${host.last_latency_ms} ms`);
    facts.push(`${host.event_count} events`, `${host.alert_count} alerts`);
    createEl('div', ['small', 'text-muted'], facts.join(' · '), info);

    if (host.last_error) {
        createEl('div', ['small', 'text-danger', 'text-truncate'],
            `Last error: ${host.last_error}`, info).style.maxWidth = '460px';
    }

    if (host.description) {
        createEl('small', ['d-block', 'text-muted', 'text-truncate'], host.description, info);
    }
    createEl('small', ['d-block', 'text-muted'],
        `${host.event_count} events · ${host.alert_count} alerts`, info);

    renderPollingControl(host, info);
    renderIntegritySummary(host, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm', 'flex-shrink-0'], '', item);

    const collectBtn = createEl('button', ['btn', 'btn-primary'], 'Collect Logs', btnGroup);
    collectBtn.title = {
        LOCAL: "Read this PC's own Windows Security log and run the detection rules",
        WINRM: `Read the Security log on ${host.ip_address} over WinRM and run the detection rules`,
        SSH: `Collect authentication logs from ${host.ip_address} over SSH and run the detection rules`,
    }[host.collection_method] || 'Collect logs and run the detection rules';
    collectBtn.addEventListener('click', () => handleCollectLogs(host, collectBtn));

    const testBtn = createEl('button', ['btn', 'btn-outline-primary'], 'Test', btnGroup);
    testBtn.title = 'Check reachability, authentication and log access separately';
    testBtn.addEventListener('click', () => handleTestConnection(host, testBtn));

    const filesBtn = createEl('button', ['btn', 'btn-outline-secondary'], 'Files', btnGroup);
    filesBtn.title = 'Watch files on this host for tampering (File Integrity Monitoring)';
    filesBtn.addEventListener('click', () => openIntegrityModal(host));

    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], 'Edit', btnGroup);
    editBtn.addEventListener('click', () => openHostModal(host));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], 'Delete', btnGroup);
    delBtn.addEventListener('click', async () => {
        if (!window.confirm(
            `Remove host "${host.hostname}"? Its ${host.event_count} event(s) and ` +
            `${host.alert_count} alert(s) are deleted too.`
        )) {
            return;
        }
        try {
            await removeHost(host.id);
            notify(`Host "${host.hostname}" removed.`, 'info');
            await refreshHosts();
        } catch (err) {
            notify(err.message, 'danger');
        }
    });
}

/**
 * The automatic-collection switch for one host.
 *
 * Rendered inline on the row rather than tucked inside the edit dialog:
 * whether a host is watched on its own is the second most important fact
 * about it after whether it is reachable, and finding that out should not
 * take two clicks.
 */
function renderPollingControl(host, parent) {
    const wrap = createEl('div', ['d-flex', 'align-items-center', 'gap-2', 'mt-1'], '', parent);

    const check = createEl('div', ['form-check', 'form-switch', 'mb-0'], '', wrap);
    const input = createEl('input', ['form-check-input'], '', check);
    input.type = 'checkbox';
    input.id = `poll-${host.id}`;
    input.checked = !!host.polling_enabled;
    input.title = 'Collect from this host automatically, without pressing Collect';

    const label = createEl('label', ['form-check-label', 'small', 'text-muted'], '', check);
    label.htmlFor = input.id;

    const interval = createEl('input', ['form-control', 'form-control-sm', 'py-0'], '', wrap);
    interval.type = 'number';
    interval.min = '5';
    interval.step = '5';
    interval.value = host.poll_interval_effective;
    interval.style.width = '84px';
    interval.title = 'Seconds between automatic collections';
    interval.disabled = !host.polling_enabled;

    createEl('span', ['small', 'text-muted'], 'sec', wrap);

    const describe = () => {
        if (!input.checked) {
            label.textContent = 'auto-collect off';
            return;
        }
        label.textContent = host.next_poll
            ? `auto-collect on \u00b7 next ${formatTime(host.next_poll)}`
            : 'auto-collect on';
    };
    describe();

    const save = async (patch) => {
        try {
            const updated = await updateHost(host.id, patch);
            // Re-read rather than trusting the local copy: the server clamps
            // the interval and recomputes when the next collection is due.
            Object.assign(host, updated);
            interval.value = host.poll_interval_effective;
            interval.disabled = !host.polling_enabled;
            describe();
            notify(
                host.polling_enabled
                    ? `"${host.hostname}" is now collected every ${host.poll_interval_effective}s.`
                    : `Automatic collection is off for "${host.hostname}".`,
                'info',
            );
        } catch (err) {
            notify(err.message, 'danger');
            input.checked = !!host.polling_enabled;
            interval.value = host.poll_interval_effective;
        }
    };

    input.addEventListener('change', () => save({ polling_enabled: input.checked }));
    interval.addEventListener('change', () => save({
        poll_interval_seconds: Number(interval.value),
    }));
}

/**
 * Whether the background collector is alive, shown above the host list.
 *
 * A scheduler that is switched off, or that has died, is indistinguishable
 * from a quiet network unless it says so - the same ambiguity the USB audit
 * badge exists to remove elsewhere in this project.
 */
async function refreshSchedulerPanel() {
    const box = document.getElementById('schedulerStatus');
    if (!box) return;
    clearContainer(box);

    try {
        const status = await fetchSchedulerStatus();

        const [cls, text] = status.running
            ? ['bg-success', 'running']
            : ['bg-secondary', 'not running'];
        createEl('span', ['badge', cls, 'me-2'], text, box);

        const facts = [];
        if (status.running) facts.push(`checks every ${status.tick_seconds}s`);
        facts.push(`${status.hosts_polled} host(s) on automatic collection`);
        if (status.next_poll) facts.push(`next ${formatTime(status.next_poll)}`);
        if (status.collections) facts.push(`${status.collections} collected`);
        if (status.failures) facts.push(`${status.failures} failed`);
        createEl('span', ['small', 'text-muted'], facts.join(' \u00b7 '), box);

        if (status.detail) {
            createEl('div', ['small', 'text-muted', 'mt-1'], status.detail, box);
        }
    } catch (err) {
        createEl('span', ['small', 'text-danger'],
            `Could not read the scheduler status: ${err.message}`, box);
    }
}

async function handleRunSchedulerNow(button) {
    if (button.disabled) return;
    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Running...';
    try {
        const result = await runSchedulerNow();
        notify(result.message, result.collected.length ? 'success' : 'info');
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    } finally {
        button.disabled = false;
        button.textContent = original;
    }
}

/**
 * A one-line summary of file integrity monitoring for a host.
 *
 * Deliberately terse. The detail belongs in the dialog; what the row has to
 * answer is whether anything is being watched at all, because a host with
 * monitoring switched on but no watched paths is the failure mode that looks
 * like success.
 */
function renderIntegritySummary(host, parent) {
    const line = createEl('div', ['small', 'text-muted', 'mt-1'], '', parent);

    if (!host.fim_enabled) {
        createEl('span', [], 'file integrity off', line);
        return;
    }

    if (!host.watched_path_count) {
        const warn = createEl('span', ['text-warning-emphasis'],
            'file integrity on, but no paths are being watched', line);
        warn.title = 'Nothing will be checked until a path is added.';
        return;
    }

    const parts = [
        `${host.watched_path_count} path(s) watched`,
        `${host.baseline_file_count} file(s) baselined`,
    ];
    if (host.last_integrity_scan) parts.push(`scanned ${formatTime(host.last_integrity_scan)}`);
    createEl('span', [], parts.join(' \u00b7 '), line);

    if (host.last_integrity_error) {
        const err = createEl('div', ['small', 'text-danger', 'text-truncate'],
            `Last scan error: ${host.last_integrity_error}`, parent);
        err.style.maxWidth = '460px';
    }
}

/** Open the file-integrity dialog for one host. */
async function openIntegrityModal(host) {
    fimHost = host;
    document.getElementById('fimHostName').textContent = host.hostname;

    const toggle = document.getElementById('fimEnabledToggle');
    toggle.checked = !!host.fim_enabled;
    toggle.onchange = async () => {
        try {
            const updated = await updateHost(host.id, { fim_enabled: toggle.checked });
            Object.assign(host, updated);
            notify(
                host.fim_enabled
                    ? `File integrity monitoring is on for "${host.hostname}".`
                    : `File integrity monitoring is off for "${host.hostname}".`,
                'info',
            );
            await refreshHosts();
        } catch (err) {
            notify(err.message, 'danger');
            toggle.checked = !!host.fim_enabled;
        }
    };

    await refreshWatchedPaths();
    fimModal.show();
}

async function refreshWatchedPaths() {
    const body = document.getElementById('watchedPathList');
    if (!body || !fimHost) return;
    clearContainer(body);

    try {
        const paths = await fetchWatchedPaths(fimHost.id);

        if (paths.length === 0) {
            createEl('div', ['list-group-item', 'text-muted', 'small'],
                'No paths watched yet. Add one below — a configuration file, a startup folder, or a directory that should never change.',
                body);
            return;
        }

        paths.forEach((entry) => {
            const row = createEl('div',
                ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center', 'gap-2'],
                '', body);

            const info = createEl('div', ['overflow-hidden'], '', row);
            createEl('div', ['font-monospace', 'small', 'text-truncate'], entry.path, info);

            const facts = [`${entry.file_count} file(s) baselined`];
            if (entry.recursive) facts.push('recursive');
            if (entry.description) facts.push(entry.description);
            createEl('div', ['small', 'text-muted', 'text-truncate'], facts.join(' \u00b7 '), info);

            const del = createEl('button',
                ['btn', 'btn-sm', 'btn-outline-danger', 'flex-shrink-0'], 'Remove', row);
            del.addEventListener('click', async () => {
                if (!window.confirm(
                    `Stop watching "${entry.path}"? Its ${entry.file_count} recorded ` +
                    'hash(es) are deleted too, so watching it again starts a fresh baseline.'
                )) {
                    return;
                }
                try {
                    await removeWatchedPath(entry.id);
                    notify(`Stopped watching ${entry.path}.`, 'info');
                    await refreshWatchedPaths();
                    await refreshHosts();
                } catch (err) {
                    notify(err.message, 'danger');
                }
            });
        });
    } catch (err) {
        createEl('div', ['list-group-item', 'text-danger', 'small'],
            `Could not load watched paths: ${err.message}`, body);
    }
}

async function handleAddWatchedPath(event) {
    event.preventDefault();
    if (!fimHost) return;

    const pathInput = document.getElementById('watchedPathValue');
    const data = {
        path: pathInput.value,
        recursive: document.getElementById('watchedPathRecursive').checked,
        description: document.getElementById('watchedPathDesc').value,
    };

    try {
        await createWatchedPath(fimHost.id, data);
        notify(`Now watching ${data.path}.`, 'success');
        event.target.reset();
        await refreshWatchedPaths();
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    }
}

async function handleScanNow() {
    if (!fimHost) return;
    const button = document.getElementById('scanNowBtn');
    button.disabled = true;
    const original = button.textContent;
    button.textContent = 'Scanning...';

    try {
        const result = await runIntegrityScan(fimHost.id);
        const changes = (result.changes || []).length;
        notify(result.message, changes ? 'warning' : 'success');
        renderScanResult(result);
        await refreshWatchedPaths();
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    } finally {
        button.disabled = false;
        button.textContent = original;
    }
}

/** Show what the last scan found, inside the dialog. */
function renderScanResult(result) {
    const box = document.getElementById('scanResult');
    if (!box) return;
    clearContainer(box);

    createEl('div', ['small', 'fw-semibold'], result.message, box);

    (result.truncated || []).forEach((path) => {
        createEl('div', ['small', 'text-warning-emphasis'],
            `Only the first files under ${path} were checked — narrow the path or turn off recursion.`,
            box);
    });

    (result.changes || []).forEach((change) => {
        const cls = change.event_type === 'FILE_ADDED' ? 'text-warning-emphasis' : 'text-danger';
        createEl('div', ['small', 'font-monospace', 'text-truncate', cls],
            `${change.event_type}: ${change.path}`, box);
    });
}

async function handleResetBaseline() {
    if (!fimHost) return;
    if (!window.confirm(
        `Clear the recorded hashes for "${fimHost.hostname}"?\n\n` +
        'Do this only after a change you know about, such as a software update. ' +
        'The next scan records a fresh baseline and reports nothing.'
    )) {
        return;
    }

    try {
        const result = await resetBaseline(fimHost.id);
        notify(result.message, 'info');
        clearContainer(document.getElementById('scanResult'));
        await refreshWatchedPaths();
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    }
}

/**
 * Run the staged connection test and show each check on its own line, so a
 * failure points at the specific thing that needs fixing.
 */
async function handleTestConnection(host, button) {
    if (button.disabled) return;

    const originalText = button.textContent;
    button.disabled = true;
    clearContainer(button);
    createEl('span', ['spinner-border', 'spinner-border-sm'], '', button);

    try {
        const result = await testHostConnection(host.id);
        renderTestResult(host, result);
        await refreshHosts();
    } catch (err) {
        notify(`Test failed for "${host.hostname}": ${err.message}`, 'danger');
    } finally {
        button.disabled = false;
        clearContainer(button);
        button.textContent = originalText;
    }
}

function renderTestResult(host, result) {
    const area = document.getElementById('toastArea');
    if (!area) return;

    clearContainer(area);
    const box = createEl('div',
        ['alert', result.ok ? 'alert-success' : 'alert-danger',
            'alert-dismissible', 'fade', 'show'], '', area);

    createEl('div', ['fw-bold', 'mb-2'],
        `${host.hostname} — ${result.ok ? 'all checks passed' : 'a check failed'} `
        + `(${result.latency_ms} ms, ${result.collection_method})`, box);

    const list = createEl('ul', ['mb-0', 'ps-3'], '', box);
    result.checks.forEach((check) => {
        const item = createEl('li', ['small'], '', list);
        // An advisory check reports an optional capability and never counts
        // towards the verdict, so it must not be marked with a failure cross
        // beside a banner that correctly says everything passed.
        const mark = check.advisory ? (check.ok ? '✓' : 'ⓘ') : (check.ok ? '✓' : '✗');
        createEl('span', ['fw-semibold', 'me-1'], `${mark} ${check.name}`, item);
        if (check.detail) {
            createEl('span', ['text-muted'], `— ${check.detail}`, item);
        }
    });

    const close = createEl('button', ['btn-close'], '', box);
    close.type = 'button';
    close.setAttribute('data-bs-dismiss', 'alert');
}

/**
 * Collect logs for one host through the existing authenticated endpoint,
 * then refresh the list so the event and alert counts reflect the result.
 */
async function handleCollectLogs(host, button) {
    if (button.disabled) return;

    const originalText = button.textContent;
    button.disabled = true;
    clearContainer(button);
    createEl('span', ['spinner-border', 'spinner-border-sm', 'me-1'], '', button);
    createEl('span', [], 'Collecting…', button);

    try {
        const result = await triggerLogFetch(host.id);
        const stored = result.events_stored || 0;
        const received = result.events_received || 0;
        const newAlerts = (result.alerts && result.alerts.total) || 0;

        if (received === 0) {
            notify(
                `No new log entries on "${host.hostname}". ` +
                'Sign in incorrectly a few times, then collect again.',
                'info',
            );
        } else {
            let message = `Collected ${received} log entries, stored ${stored} new events`;
            if (result.duplicates_skipped) {
                message += ` (${result.duplicates_skipped} already seen)`;
            }
            message += newAlerts > 0
                ? `. Detection raised ${newAlerts} new alert(s) — see the Alerts page.`
                : '. No new alerts; the detection thresholds were not reached.';
            notify(message, newAlerts > 0 ? 'warning' : 'success');
        }

        await refreshHosts();
    } catch (err) {
        notify(`Collection failed for "${host.hostname}": ${err.message}`, 'danger');
        button.disabled = false;
        clearContainer(button);
        button.textContent = originalText;
    }
}

async function handleAddHost(event) {
    event.preventDefault();

    const data = {
        hostname: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIP').value,
        os_type: document.getElementById('hostOS').value,
        collection_method: document.getElementById('hostMethod').value,
        remote_user: document.getElementById('hostRemoteUser').value,
        description: document.getElementById('hostDesc').value,
        polling_enabled: document.getElementById('hostPolling').checked,
        poll_interval_seconds: document.getElementById('hostPollInterval').value || null,
    };

    try {
        const host = await createHost(data);
        notify(`Host "${host.hostname}" added.`, 'success');
        event.target.reset();
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    }
}

function openHostModal(host) {
    document.getElementById('editHostId').value = host.id;
    document.getElementById('editHostName').value = host.hostname;
    document.getElementById('editHostIP').value = host.ip_address;
    document.getElementById('editHostOS').value = host.os_type;
    document.getElementById('editHostMethod').value = host.collection_method || '';
    document.getElementById('editHostRemoteUser').value = host.remote_user || '';
    document.getElementById('editHostDesc').value = host.description || '';
    document.getElementById('editHostPolling').checked = !!host.polling_enabled;
    document.getElementById('editHostPollInterval').value = host.poll_interval_effective;
    hostModal.show();
}

async function handleSaveHost() {
    const id = document.getElementById('editHostId').value;
    const data = {
        hostname: document.getElementById('editHostName').value,
        ip_address: document.getElementById('editHostIP').value,
        os_type: document.getElementById('editHostOS').value,
        collection_method: document.getElementById('editHostMethod').value,
        remote_user: document.getElementById('editHostRemoteUser').value,
        description: document.getElementById('editHostDesc').value,
        polling_enabled: document.getElementById('editHostPolling').checked,
        poll_interval_seconds: document.getElementById('editHostPollInterval').value || null,
    };

    try {
        await updateHost(id, data);
        hostModal.hide();
        notify('Host updated.', 'success');
        await refreshHosts();
    } catch (err) {
        notify(err.message, 'danger');
    }
}

// ======================= THREAT INTELLIGENCE REGISTRY =======================

async function refreshIPs() {
    clearContainer(ipContainer);
    try {
        const entries = await fetchIPs();
        if (entries.length === 0) {
            createEl('div', ['list-group-item', 'text-muted', 'small'],
                'No entries yet. Addresses are also registered automatically ' +
                'when the detection engine sees them.', ipContainer);
            return;
        }
        entries.forEach(renderIPRow);
    } catch (err) {
        createEl('div', ['list-group-item', 'text-danger', 'small'],
            `Error loading the registry: ${err.message}`, ipContainer);
    }
}

function renderIPRow(entry) {
    const item = createEl('div',
        ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'],
        '', ipContainer);

    const info = createEl('div', ['overflow-hidden'], '', item);
    const title = createEl('div', [], '', info);

    let color = 'bg-secondary';
    if (entry.status === 'TRUSTED') color = 'bg-success';
    if (entry.status === 'BANNED') color = 'bg-danger';
    createEl('span', ['badge', color, 'me-2'], entry.status, title);
    createEl('span', ['fw-bold', 'font-monospace'], entry.ip_address, title);

    if (entry.hit_count > 0) {
        createEl('span', ['badge', 'bg-light', 'text-dark', 'ms-2'],
            `${entry.hit_count} hits`, title);
    }

    if (entry.notes) {
        createEl('small', ['d-block', 'text-muted', 'text-truncate'], entry.notes, info);
    }
    createEl('small', ['d-block', 'text-muted'],
        `${entry.source || 'Manual entry'} · last seen ${formatTime(entry.last_seen)}`, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm', 'flex-shrink-0'], '', item);

    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], 'Edit', btnGroup);
    editBtn.addEventListener('click', () => openIPModal(entry));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], 'Delete', btnGroup);
    delBtn.addEventListener('click', async () => {
        if (!window.confirm(`Remove ${entry.ip_address} from the registry?`)) return;
        try {
            await removeIP(entry.id);
            notify(`${entry.ip_address} removed from the registry.`, 'info');
            await refreshIPs();
        } catch (err) {
            notify(err.message, 'danger');
        }
    });
}

async function handleAddIP(event) {
    event.preventDefault();

    const data = {
        ip_address: document.getElementById('regIP').value,
        status: document.getElementById('regStatus').value,
        source: document.getElementById('regSource').value,
        notes: document.getElementById('regNotes').value,
    };

    try {
        const entry = await createIP(data);
        notify(
            `${entry.ip_address} added as ${entry.status}.` +
            (entry.status === 'BANNED'
                ? ' Use "Re-run detection" on the Alerts page to apply rule R-03.'
                : ''),
            'success',
        );
        event.target.reset();
        await refreshIPs();
    } catch (err) {
        notify(err.message, 'danger');
    }
}

function openIPModal(entry) {
    document.getElementById('editIPId').value = entry.id;
    document.getElementById('editIPVal').value = entry.ip_address;
    document.getElementById('editIPStatus').value = entry.status;
    document.getElementById('editIPSource').value = entry.source || '';
    document.getElementById('editIPNotes').value = entry.notes || '';
    ipModal.show();
}

async function handleSaveIP() {
    const id = document.getElementById('editIPId').value;
    const data = {
        ip_address: document.getElementById('editIPVal').value,
        status: document.getElementById('editIPStatus').value,
        source: document.getElementById('editIPSource').value,
        notes: document.getElementById('editIPNotes').value,
    };

    try {
        const entry = await updateIP(id, data);
        ipModal.hide();
        notify(
            `${entry.ip_address} updated to ${entry.status}.` +
            (entry.status === 'BANNED'
                ? ' Use "Re-run detection" on the Alerts page to apply rule R-03.'
                : ''),
            'success',
        );
        await refreshIPs();
    } catch (err) {
        notify(err.message, 'danger');
    }
}
