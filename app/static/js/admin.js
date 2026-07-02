import { createEl, clearContainer } from './dom.js';
import { fetchHosts, createHost, updateHost, removeHost } from './api.js';
import { fetchIPs, createIP, updateIP, removeIP } from './api.js';

// --- HOSTS SECTION ---
const hostsContainer = document.getElementById('hostsListAdmin');
const hostForm = document.getElementById('hostForm');

// --- IP REGISTRY SECTION ---
const ipContainer = document.getElementById('ipListAdmin');
const ipForm = document.getElementById('ipForm');
const refreshIPsBtn = document.getElementById('refreshIPsBtn');

// --- MODALS ---
let hostModal = null;
let ipModal = null;

export async function initAdmin() {
    const hostModalEl = document.getElementById('editHostModal');
    if (hostModalEl) hostModal = new bootstrap.Modal(hostModalEl);

    const ipModalEl = document.getElementById('editIPModal');
    if (ipModalEl) ipModal = new bootstrap.Modal(ipModalEl);

    // Host event listeners
    if (hostForm) hostForm.addEventListener('submit', handleAddHost);
    if (document.getElementById('saveHostBtn')) {
        document.getElementById('saveHostBtn').addEventListener('click', handleSaveHost);
    }

    // IP registry event listeners
    if (ipForm) ipForm.addEventListener('submit', handleAddIP);
    if (refreshIPsBtn) refreshIPsBtn.addEventListener('click', refreshIPs);
    if (document.getElementById('saveIPBtn')) {
        document.getElementById('saveIPBtn').addEventListener('click', handleSaveIP);
    }

    if (ipContainer) await refreshIPs();

    if (hostsContainer) await refreshHosts();
}

// ======================= HOST LOGIC =======================

async function refreshHosts() {
    clearContainer(hostsContainer);
    try {
        const hosts = await fetchHosts();
        hosts.forEach(renderHostRow);
    } catch (e) { console.error(e); }
}

function renderHostRow(host) {
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', hostsContainer);

    const info = createEl('div', [], '', item);
    const icon = host.os_type === 'LINUX' ? '🐧' : '🪟';
    createEl('span', ['me-2'], icon, info);
    createEl('span', ['fw-bold', 'me-2'], host.hostname, info);
    createEl('small', ['text-muted'], host.ip_address, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);

    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '✏️', btnGroup);
    editBtn.addEventListener('click', () => openHostModal(host));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '🗑️', btnGroup);
    delBtn.addEventListener('click', async () => {
        if (confirm(`Remove host ${host.hostname}?`)) {
            await removeHost(host.id);
            await refreshHosts();
        }
    });
}

async function handleAddHost(e) {
    e.preventDefault();
    const data = {
        hostname: document.getElementById('hostName').value,
        ip_address: document.getElementById('hostIP').value,
        os_type: document.getElementById('hostOS').value
    };
    try {
        await createHost(data);
        e.target.reset();
        await refreshHosts();
    } catch (err) { alert(err.message); }
}

function openHostModal(host) {
    document.getElementById('editHostId').value = host.id;
    document.getElementById('editHostName').value = host.hostname;
    document.getElementById('editHostIP').value = host.ip_address;
    document.getElementById('editHostOS').value = host.os_type;
    hostModal.show();
}

async function handleSaveHost() {
    const id = document.getElementById('editHostId').value;
    const data = {
        hostname: document.getElementById('editHostName').value,
        ip_address: document.getElementById('editHostIP').value,
        os_type: document.getElementById('editHostOS').value
    };
    try {
        await updateHost(id, data);
        hostModal.hide();
        await refreshHosts();
    } catch (err) { alert(err.message); }
}


// ======================= IP REGISTRY LOGIC =======================

async function refreshIPs() {
    clearContainer(ipContainer);
    try {
        const ips = await fetchIPs();
        if (ips.length === 0) createEl('div', ['p-2', 'text-muted', 'small'], 'No entries yet.', ipContainer);
        ips.forEach(renderIPRow);
    } catch (e) { console.error("IP registry error:", e); }
}

function renderIPRow(ip) {
    const item = createEl('div', ['list-group-item', 'd-flex', 'justify-content-between', 'align-items-center'], '', ipContainer);

    const info = createEl('div', [], '', item);
    let color = 'bg-secondary';
    if (ip.status === 'TRUSTED') color = 'bg-success';
    if (ip.status === 'BANNED') color = 'bg-danger';
    createEl('span', ['badge', color, 'me-2'], ip.status[0], info);

    createEl('span', ['fw-bold', 'font-monospace', 'me-2'], ip.ip_address, info);

    let timeStr = '-';
    if (ip.last_seen && ip.last_seen !== '-') {
        const utcDate = new Date(ip.last_seen.replace(" ", "T") + "Z");
        timeStr = utcDate.toLocaleString();
    }
    createEl('small', ['text-muted'], timeStr, info);

    const btnGroup = createEl('div', ['btn-group', 'btn-group-sm'], '', item);

    const editBtn = createEl('button', ['btn', 'btn-outline-secondary'], '✏️', btnGroup);
    editBtn.addEventListener('click', () => openIPModal(ip));

    const delBtn = createEl('button', ['btn', 'btn-outline-danger'], '🗑️', btnGroup);
    delBtn.addEventListener('click', async () => {
        if (confirm(`Remove IP address ${ip.ip_address} from the registry?`)) {
            try {
                await removeIP(ip.id);
                await refreshIPs();
            } catch (err) { alert("Error removing IP: " + err.message); }
        }
    });
}

async function handleAddIP(e) {
    e.preventDefault();
    const data = {
        ip_address: document.getElementById('regIP').value,
        status: document.getElementById('regStatus').value
    };
    try {
        await createIP(data);
        e.target.reset();
        await refreshIPs();
    } catch (err) { alert(err.message); }
}

function openIPModal(ip) {
    document.getElementById('editIPId').value = ip.id;
    document.getElementById('editIPVal').value = ip.ip_address;
    document.getElementById('editIPStatus').value = ip.status;
    ipModal.show();
}

async function handleSaveIP() {
    const id = document.getElementById('editIPId').value;
    const data = {
        ip_address: document.getElementById('editIPVal').value,
        status: document.getElementById('editIPStatus').value
    };
    try {
        await updateIP(id, data);
        ipModal.hide();
        await refreshIPs();
    } catch (err) { alert(err.message); }
}
