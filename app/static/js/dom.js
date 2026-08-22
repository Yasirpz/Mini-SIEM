/**
 * Small helpers for building DOM nodes.
 *
 * Everything here sets textContent rather than innerHTML, so log messages and
 * usernames coming out of the database can never be interpreted as markup.
 */
export function createEl(tag, classes = [], text = '', parent = null) {
    const el = document.createElement(tag);
    if (classes.length > 0) {
        el.classList.add(...classes);
    }
    if (text !== '' && text != null) {
        el.textContent = text;
    }
    if (parent) {
        parent.appendChild(el);
    }
    return el;
}

export function clearContainer(container) {
    while (container.firstChild) {
        container.removeChild(container.firstChild);
    }
}

/** Render a "no data" row spanning the whole table. */
export function emptyRow(tbody, columns, message) {
    const row = createEl('tr', [], '', tbody);
    const cell = createEl('td', ['text-center', 'text-muted', 'py-3'], message, row);
    cell.colSpan = columns;
    return row;
}

/** Bootstrap contextual class for a severity level. */
export function severityClass(severity) {
    switch (severity) {
        case 'HIGH': return 'bg-danger';
        case 'MEDIUM': return 'bg-warning text-dark';
        default: return 'bg-info text-dark';
    }
}

/** Bootstrap row-highlight class for a severity level. */
export function severityRowClass(severity) {
    switch (severity) {
        case 'HIGH': return 'table-danger';
        case 'MEDIUM': return 'table-warning';
        default: return '';
    }
}

/**
 * A severity badge carrying a shape, a word and a colour.
 *
 * Colour alone is not enough. Around one man in twelve cannot reliably
 * separate the red badge from the amber one, a projector in a demonstration
 * room washes both out, and a printed report has neither. The triangle,
 * diamond and disc differ in outline, so the ranking survives all three.
 *
 * The three levels are LOW, MEDIUM and HIGH as specified in the project
 * proposal; HIGH is the top of the scale, and nothing here invents a fourth.
 */
const SEVERITY_MARKS = { HIGH: '▲', MEDIUM: '◆', LOW: '●' };

export function severityBadge(severity, parent) {
    const level = SEVERITY_MARKS[severity] ? severity : 'LOW';
    const badge = createEl('span', ['sev', `sev--${level.toLowerCase()}`], '', parent);
    createEl('span', ['sev-mark'], SEVERITY_MARKS[level], badge);
    createEl('span', ['sev-text'], level, badge);
    badge.title = `${level} severity`;
    return badge;
}

/**
 * The timezone every stored time is rendered against.
 *
 * The API always sends UTC. base.html publishes the configured zone in a
 * <meta> tag; it is Asia/Karachi by default, so the dashboard reads in
 * Pakistan Standard Time no matter how the machine looking at it happens to
 * be configured. Blank means "use this machine's own timezone", which is what
 * MINISIEM_DISPLAY_TIMEZONE=local selects.
 *
 * An unrecognised zone name falls back to the machine's own rather than
 * throwing, because a typo in a configuration file must not blank out every
 * timestamp on the dashboard.
 */
const DISPLAY_TIMEZONE = (() => {
    const configured = document
        .querySelector('meta[name="display-timezone"]')?.content?.trim();
    if (!configured) return undefined;
    try {
        new Intl.DateTimeFormat(undefined, { timeZone: configured });
        return configured;
    } catch (err) {
        console.warn(`Unknown display timezone "${configured}"; using this machine's.`);
        return undefined;
    }
})();

/**
 * Abbreviations the browser does not know.
 *
 * Intl renders Asia/Karachi as "GMT+5", which is correct but is not what a
 * Pakistani reader calls it, and a report that says "GMT+5" invites the
 * question of whether the developer simply never set the timezone. CLDR has
 * no abbreviation for these zones, so the few that matter here are named
 * explicitly and everything else keeps the browser's own label.
 */
const ZONE_ABBREVIATIONS = {
    'Asia/Karachi': 'PKT',
    'Asia/Kolkata': 'IST',
    'Asia/Dhaka': 'BST',
    'Asia/Kabul': 'AFT',
    UTC: 'UTC',
};

// "22 Aug 2026, 01:35:42" — day-first, because that is how a date is written
// in Pakistan, and a fixed en-GB locale so the dashboard reads the same way
// on every machine rather than following the browser's regional settings.
const TIME_FORMAT = new Intl.DateTimeFormat('en-GB', {
    timeZone: DISPLAY_TIMEZONE,
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
});

/** Parse an API timestamp ("YYYY-MM-DD HH:MM:SS", UTC) into a Date. */
function parseUtc(value) {
    // The trailing Z is what makes this unambiguous: without it the browser
    // reads the string as local time and the whole dashboard shifts by the
    // machine's offset.
    const parsed = new Date(`${value.replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
}

/**
 * Format an API timestamp (UTC) for display, e.g. "22 Aug 2026, 01:35:42 PKT".
 *
 * The zone abbreviation is part of the string rather than a note somewhere
 * else on the page, because a time without its zone is not evidence: an
 * analyst copying a row into an incident report has to be able to state when
 * it happened without also having to remember how the dashboard was set up.
 */
export function formatTime(value) {
    if (!value) return '-';
    const parsed = parseUtc(value);
    if (!parsed) return value;

    const label = displayTimeZoneLabel();
    return label ? `${TIME_FORMAT.format(parsed)} ${label}` : TIME_FORMAT.format(parsed);
}

/**
 * The same instant without the zone suffix, for places that already say which
 * clock is being read — a column header, or a repeated list where the suffix
 * on every row would be noise rather than information.
 */
export function formatTimeShort(value) {
    if (!value) return '-';
    const parsed = parseUtc(value);
    return parsed ? TIME_FORMAT.format(parsed) : value;
}

/** A short name for the zone times are shown in, e.g. "PKT". */
export function displayTimeZoneLabel() {
    const named = ZONE_ABBREVIATIONS[DISPLAY_TIMEZONE];
    if (named) return named;

    try {
        const parts = new Intl.DateTimeFormat('en-GB', {
            timeZone: DISPLAY_TIMEZONE,
            timeZoneName: 'short',
        }).formatToParts(new Date());
        return parts.find((part) => part.type === 'timeZoneName')?.value || '';
    } catch (err) {
        return '';
    }
}

/** The IANA zone times are rendered in, resolved for display. */
export function displayTimeZoneName() {
    return DISPLAY_TIMEZONE
        || Intl.DateTimeFormat().resolvedOptions().timeZone
        || 'this machine';
}

/**
 * Draw the "is this page still being updated?" indicator.
 *
 * Every live page shows the same pill, so it is rendered in one place: three
 * pages that each described a lost connection slightly differently would
 * teach the reader three things to interpret instead of one.
 *
 * `status` is what live.js reports -- see createLiveRefresh. Returns the state
 * that was applied, so a caller with extra work to do for a particular state
 * (the dashboard updates its "last updated" clock) can branch on it without
 * repeating the mapping.
 */
const LIVE_STATES = {
    live: ['live', 'Live'],
    working: ['working', 'Updating\u2026'],
    lost: ['lost', 'Connection lost \u2014 retrying\u2026'],
    off: ['off', 'Auto-refresh off'],
};

export function renderLivePill(pill, status) {
    if (!pill) return null;

    const [state, label] = LIVE_STATES[status.state] || LIVE_STATES.working;
    pill.dataset.state = state;

    const text = pill.querySelector('.live-text');
    if (text) text.textContent = label;

    return state;
}

/**
 * Note that a panel has real content in it.
 *
 * Call this after a panel draws rows successfully. It is what lets a later
 * failure tell "I have nothing and cannot load anything" apart from "I have
 * last minute's data and could not get this minute's" — two states that look
 * identical to the code and could not be more different to the reader.
 */
export function markLoaded(container) {
    container.dataset.loaded = 'true';
    container.removeAttribute('data-stale');
}

/**
 * Handle a panel's fetch failure, and say whether it should draw an error.
 *
 * Returns false when the panel already had content: the rows stay exactly
 * where they are and are dimmed instead. Wiping a table of alerts because one
 * refresh failed would destroy the last known good picture at the moment the
 * operator most needs it — and the failure is usually a laptop's wifi rather
 * than anything wrong with the SIEM. The live indicator at the top of the
 * page is what states the connection is down; the panels only have to stop
 * pretending their contents are current.
 *
 * Returns true when the panel is genuinely empty, in which case the caller
 * draws its own message: on a first load there is nothing to preserve and
 * silence would be worse than an error.
 */
export function panelFailed(container) {
    if (container.dataset.loaded === 'true') {
        container.dataset.stale = 'true';
        return false;
    }
    return true;
}

/** Show a dismissible message in the shared toast area. */
export function notify(message, category = 'info') {
    const area = document.getElementById('toastArea');
    if (!area) return;

    clearContainer(area);
    const box = createEl('div', ['alert', `alert-${category}`, 'alert-dismissible', 'fade', 'show'], message, area);
    const close = createEl('button', ['btn-close'], '', box);
    close.type = 'button';
    close.setAttribute('data-bs-dismiss', 'alert');

    if (category === 'success' || category === 'info') {
        setTimeout(() => box.remove(), 6000);
    }
}
