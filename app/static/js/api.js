/**
 * Fetch API wrapper for talking to the Mini-SIEM Flask backend.
 */

// --- HOSTS ---
export async function fetchHosts() {
    const res = await fetch('/api/hosts');
    return await res.json();
}
export async function createHost(data) {
    const res = await fetch('/api/hosts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error((await res.json()).error);
    return await res.json();
}
export async function updateHost(id, data) {
    const res = await fetch(`/api/hosts/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Error updating host');
    return await res.json();
}
export async function removeHost(id) {
    await fetch(`/api/hosts/${id}`, { method: 'DELETE' });
}

// --- LIVE MONITORING / LOG COLLECTION ---
export async function checkHostStatus(id, osType) {
    const endpoint = (osType === 'LINUX')
        ? `/api/hosts/${id}/ssh-info`
        : `/api/hosts/${id}/windows-info`;

    const res = await fetch(endpoint);
    if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `HTTP error ${res.status}`);
    }
    return await res.json();
}

export async function triggerLogFetch(hostId) {
    const res = await fetch(`/api/hosts/${hostId}/logs`, {
        method: 'POST'
    });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Error collecting logs');
    }
    return await res.json();
}

// --- THREAT INTELLIGENCE (IP REGISTRY) ---

export async function fetchIPs() {
    const res = await fetch('/api/ips');
    if (!res.ok) throw new Error('Error fetching IP addresses');
    return await res.json();
}

export async function createIP(data) {
    const res = await fetch('/api/ips', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Error adding IP');
    return await res.json();
}

export async function updateIP(id, data) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error('Error updating IP status');
    return await res.json();
}

export async function removeIP(id) {
    const res = await fetch(`/api/ips/${id}`, {
        method: 'DELETE'
    });
    if (!res.ok) throw new Error('Error removing IP');
    return await res.json();
}

// --- ALERTS ---

export async function fetchAlerts() {
    const res = await fetch('/api/alerts');
    if (!res.ok) throw new Error('Error fetching alerts');
    return await res.json();
}
