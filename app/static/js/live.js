/**
 * The shared "keep this page in step with the collector" timer.
 *
 * Automatic collection happens in a background thread on the server, so
 * without something like this a page shows whatever was true when it loaded
 * and stays that way until somebody presses F5 — which makes a system that
 * collects on its own no more useful than one that does not.
 *
 * The rules are the same on every page, which is why they live here once:
 *
 *   - Nothing is fetched while the tab is hidden. A dashboard left open
 *     overnight must not spend the night querying a laptop that is asleep.
 *   - Returning to the tab refreshes immediately rather than waiting out the
 *     remainder of an interval, because the first thing anyone does on coming
 *     back is read the screen.
 *   - Refreshes never overlap. A refresh still in flight when the next tick
 *     arrives causes that tick to be skipped, so a slow response cannot build
 *     a queue of requests that all arrive at once.
 *   - Only the changed parts of the page are re-fetched and redrawn. This is
 *     deliberately not a meta-refresh: reloading the whole document every few
 *     seconds would throw away scroll position, open menus and any filter the
 *     reader had set.
 */

/** How often a live page re-reads the server, in milliseconds. */
export const LIVE_REFRESH_MS = 5000;

/**
 * The intervals offered in the dashboard's refresh picker.
 *
 * Two seconds exists for a demonstration, where somebody is watching the
 * screen while a colleague plugs in a USB drive. Thirty is for leaving the
 * dashboard up on a wall. Off is not a courtesy option: a reader working
 * through a long alert table needs the rows to stop moving, and taking that
 * away would make the table harder to use, not more live.
 */
export const REFRESH_CHOICES = [
    { label: '2s', ms: 2000 },
    { label: '5s', ms: 5000 },
    { label: '10s', ms: 10000 },
    { label: '30s', ms: 30000 },
    { label: 'Off', ms: 0 },
];

const STORAGE_KEY = 'liveRefreshMs';

/** The reader's saved choice, or the default if they have never set one. */
export function savedInterval() {
    const raw = window.localStorage.getItem(STORAGE_KEY);

    // Nothing saved means nothing was chosen, and the default applies. This
    // has to be checked before the value is converted, because Number(null)
    // is 0 -- which is a real choice here, meaning "off". Reading an absent
    // preference as a deliberate "off" left a first-time visitor with a
    // dashboard that quietly never refreshed itself.
    if (raw === null) return LIVE_REFRESH_MS;

    const stored = Number(raw);
    if (!Number.isFinite(stored)) return LIVE_REFRESH_MS;
    if (stored === 0) return 0;

    // A value that is not one of the offered choices came from an older
    // version or a hand-edited store, and is discarded rather than honoured.
    return REFRESH_CHOICES.some((choice) => choice.ms === stored)
        ? stored
        : LIVE_REFRESH_MS;
}

function rememberInterval(ms) {
    try {
        window.localStorage.setItem(STORAGE_KEY, String(ms));
    } catch (err) {
        // Private browsing can refuse storage. Losing the preference between
        // visits is a far smaller problem than the page failing to start.
        console.warn('Could not save the refresh interval:', err);
    }
}

/**
 * A live refresh whose interval can be changed and whose state can be
 * reported to the page.
 *
 * `onStatus` is called with one of:
 *
 *   { state: 'live',    at: Date }     a refresh just succeeded
 *   { state: 'working' }               a refresh is in flight
 *   { state: 'lost',    error: Error } a refresh failed; the timer keeps
 *                                      running, so this is "retrying", not
 *                                      "given up"
 *   { state: 'off' }                   the reader turned refreshing off
 *
 * A failure never clears what is already on screen. Stale data that is
 * labelled stale is more useful than a blank page, and the failure itself is
 * usually a laptop's wifi rather than anything wrong with the SIEM.
 */
export function createLiveRefresh({ refresh, onStatus = () => {}, intervalMs }) {
    let interval = intervalMs === undefined ? savedInterval() : intervalMs;
    let timer = null;
    let inFlight = false;
    let healthy = true;

    async function run({ force = false } = {}) {
        if (inFlight) return;
        if (!force && document.hidden) return;

        inFlight = true;
        onStatus({ state: 'working' });
        try {
            await refresh();
            healthy = true;
            onStatus({ state: 'live', at: new Date() });
        } catch (err) {
            healthy = false;
            onStatus({ state: 'lost', error: err });
        } finally {
            inFlight = false;
        }
    }

    function schedule() {
        if (timer !== null) {
            window.clearInterval(timer);
            timer = null;
        }
        if (interval > 0) {
            timer = window.setInterval(() => run(), interval);
        }
    }

    document.addEventListener('visibilitychange', () => {
        // Coming back to the tab should show current data at once rather than
        // whatever was on screen when it was hidden.
        if (!document.hidden && interval > 0) run();
    });

    schedule();

    return {
        /** Refresh now, whether or not a tick is due. */
        refreshNow: () => run({ force: true }),

        /** Change the cadence, remembering it for next time. */
        setInterval(ms) {
            interval = ms;
            rememberInterval(ms);
            schedule();
            if (ms === 0) {
                onStatus({ state: 'off' });
            } else {
                run({ force: true });
            }
        },

        get intervalMs() {
            return interval;
        },

        get connected() {
            return healthy;
        },

        stop() {
            if (timer !== null) window.clearInterval(timer);
            timer = null;
        },
    };
}
