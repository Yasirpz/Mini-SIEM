/**
 * Administration panel: host management and the Threat Intelligence registry.
 */
import { createEl, clearContainer, notify, formatTime } from './dom.js';
import {
    fetchHosts, createHost, updateHost, removeHost,
    fetchIPs, createIP, updateIP, removeIP,
} from './api.js';

const hostsContainer = document.getElementById('hostsListAdmin');
const hostForm = document.getElementById('hostForm');
const ipContainer = document.getElementById('ipListAdmin');
const ipForm = document.getElementById('ipForm');

let hostModal = null;
let ipModal = null;

export async function initAdmin() {
    const hostModalEl = document.getElementById('editHostModal');
    if (hostModalEl) hostModal = new bootstrap.Modal(hostModalEl);

    const ipModalEl = document.getElementById('editIPModal');
    if (ipModalEl) ipModal = new bootstrap.Modal(ipModalEl);

    if (hostForm) hostForm.addEventListener('submit', handleAddHost);
    if (ipForm) ipForm.addEventListener('submit', handleAddIP);

    bindClick('saveHostBtn', handleSaveHost);
    bindClick('saveIPBtn', handleSaveIP);
    bindClick('refreshHostsBtn', refreshHosts);
    bindClick('refreshIPsBtn', refreshIPs);

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
    createEl('small', ['text-muted', 'font-monospace'], host.ip_address, title);

    if (host.description) {
        createEl('small', ['d-block', 'text-muted', 'text-truncate'], host.description, info);
    }
    createEl('small', ['d-block', 'text-muted'],
        `${host.event_count} events · ${host.alert_count} alerts`, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm', 'flex-shrink-0'], '', item);

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

async function handleAddHost(event) {
    event.preventDefault();

    const data = {
        hostname: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIP').value,
        os_type: document.getElementById('hostOS').value,
        description: document.getElementById('hostDesc').value,
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
    document.getElementById('editHostDesc').value = host.description || '';
    hostModal.show();
}

async function handleSaveHost() {
    const id = document.getElementById('editHostId').value;
    const data = {
        hostname: document.getElementById('editHostName').value,
        ip_address: document.getElementById('editHostIP').value,
        os_type: document.getElementById('editHostOS').value,
        description: document.getElementById('editHostDesc').value,
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
