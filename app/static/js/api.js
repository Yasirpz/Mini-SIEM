/**
 * Fetch wrapper for the Mini-SIEM JSON API.
 *
 * Every state-changing request carries the CSRF token that base.html puts in
 * a <meta> tag, so the API stays protected by Flask-WTF rather than exempted
 * from it.
 */

function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
}

/**
 * Perform a request and unwrap the JSON body, turning an error status into a
 * thrown Error carrying the server's message.
 */
async function request(url, options = {}) {
    const opts = { headers: {}, ...options };

    if (opts.method && opts.method !== 'GET') {
        opts.headers['X-CSRFToken'] = csrfToken();
    }
    // Let the browser set the multipart boundary itself for FormData bodies.
    if (opts.body && !(opts.body instanceof FormData)) {
        opts.headers['Content-Type'] = 'application/json';
    }

    const res = await fetch(url, opts);

    if (res.status === 401) {
        throw new Error('Your session has expired. Please log in again.');
    }

    let payload = null;
    try {
        payload = await res.json();
    } catch (err) {
        payload = null;
    }

    if (!res.ok) {
        // The server may add `detail` (what actually failed) and `hint` (what
        // to do about it). Losing those leaves the user with a generic message
        // and nothing to act on, so fold them into the thrown error.
        const parts = [
            (payload && payload.error) || `Request failed (HTTP ${res.status})`,
            payload && payload.detail,
            payload && payload.hint,
        ].filter(Boolean);
        throw new Error(parts.join(' — '));
    }
    return payload;
}

const jsonBody = (data) => JSON.stringify(data);

// --- HOSTS ---
export const fetchHosts = () => request('/api/hosts');
export const createHost = (data) => request('/api/hosts', { method: 'POST', body: jsonBody(data) });
export const updateHost = (id, data) => request(`/api/hosts/${id}`, { method: 'PUT', body: jsonBody(data) });
export const removeHost = (id) => request(`/api/hosts/${id}`, { method: 'DELETE' });

// --- LIVE MONITORING / LOG COLLECTION ---
export function checkHostStatus(id, osType) {
    const endpoint = osType === 'LINUX'
        ? `/api/hosts/${id}/ssh-info`
        : `/api/hosts/${id}/windows-info`;
    return request(endpoint);
}

export const triggerLogFetch = (hostId) =>
    request(`/api/hosts/${hostId}/logs`, { method: 'POST' });

export const testHostConnection = (hostId) =>
    request(`/api/hosts/${hostId}/test`, { method: 'POST' });

// --- FILE INTEGRITY MONITORING ---
export const fetchWatchedPaths = (hostId) =>
    request(`/api/hosts/${hostId}/watched-paths`);

export const createWatchedPath = (hostId, data) =>
    request(`/api/hosts/${hostId}/watched-paths`, { method: 'POST', body: jsonBody(data) });

export const removeWatchedPath = (pathId) =>
    request(`/api/watched-paths/${pathId}`, { method: 'DELETE' });

// Recent file integrity findings with their before/after hashes. A dedicated
// route rather than three filtered /api/events calls, because the events
// endpoint deliberately does not return raw_log and the hashes live there.
export const fetchIntegrityChanges = (limit = 10) =>
    request(`/api/integrity/changes?limit=${limit}`);

export const runIntegrityScan = (hostId) =>
    request(`/api/hosts/${hostId}/integrity-scan`, { method: 'POST' });

export const fetchBaselines = (hostId, limit = 100) =>
    request(`/api/hosts/${hostId}/baselines?limit=${limit}`);

export const resetBaseline = (hostId) =>
    request(`/api/hosts/${hostId}/baselines`, { method: 'DELETE' });

// --- AUTOMATIC COLLECTION (BACKGROUND SCHEDULER) ---
export const fetchSchedulerStatus = () => request('/api/scheduler');

export const runSchedulerNow = () => request('/api/scheduler/run', { method: 'POST' });

// --- THREAT INTELLIGENCE (IP REGISTRY) ---
export const fetchIPs = () => request('/api/ips');
export const createIP = (data) => request('/api/ips', { method: 'POST', body: jsonBody(data) });
export const updateIP = (id, data) => request(`/api/ips/${id}`, { method: 'PUT', body: jsonBody(data) });
export const removeIP = (id) => request(`/api/ips/${id}`, { method: 'DELETE' });

// --- ALERTS ---
export function fetchAlerts(params = {}) {
    const query = new URLSearchParams(
        Object.entries(params).filter(([, value]) => value !== '' && value != null)
    );
    const suffix = query.toString() ? `?${query}` : '';
    return request(`/api/alerts${suffix}`);
}

export const acknowledgeAlert = (id, acknowledged = true) =>
    request(`/api/alerts/${id}/acknowledge`, { method: 'POST', body: jsonBody({ acknowledged }) });

export const removeAlert = (id) => request(`/api/alerts/${id}`, { method: 'DELETE' });

// --- EVENTS ---
export function fetchEvents(params = {}) {
    const query = new URLSearchParams(
        Object.entries(params).filter(([, value]) => value !== '' && value != null)
    );
    const suffix = query.toString() ? `?${query}` : '';
    return request(`/api/events${suffix}`);
}

export const fetchSamples = () => request('/api/events/samples');

export const importBundledSample = (name, hostId) =>
    request(`/api/events/samples/${encodeURIComponent(name)}`, {
        method: 'POST',
        body: jsonBody({ host_id: hostId }),
    });

export function uploadSample(file, hostId) {
    const form = new FormData();
    form.append('file', file);
    form.append('host_id', hostId);
    return request('/api/events/import', { method: 'POST', body: form });
}

export const importPastedLog = (content, hostId) =>
    request('/api/events/import', {
        method: 'POST',
        body: jsonBody({ host_id: hostId, content }),
    });

export const generateEvents = (hostId, sourceIp, attempts) =>
    request('/api/events/import', {
        method: 'POST',
        body: jsonBody({ host_id: hostId, generate: true, source_ip: sourceIp, attempts }),
    });

export const clearEvents = (hostId) =>
    request(`/api/events${hostId ? `?host_id=${hostId}` : ''}`, { method: 'DELETE' });

export const runDetection = (hostId) =>
    request('/api/detection/run', { method: 'POST', body: jsonBody({ host_id: hostId || null }) });

// --- DASHBOARD STATISTICS ---
export const fetchSummary = () => request('/api/stats/summary');
export const fetchHostStats = () => request('/api/stats/hosts');
export const fetchSeverityStats = () => request('/api/stats/severity');
export const fetchRuleStats = () => request('/api/stats/rules');
export const fetchTimeline = (days = 7) => request(`/api/stats/timeline?days=${days}`);
export const fetchTopSources = (limit = 5) => request(`/api/stats/top-sources?limit=${limit}`);
// Which MITRE ATT&CK techniques the rule set covers, and which have
// actually fired. Rules that have never fired are included on purpose --
// see app/rule_catalog.py.
export const fetchAttackCoverage = () => request('/api/stats/attack');
