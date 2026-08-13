/**
 * Front-end entry point: applies the saved theme and starts the module that
 * matches the current page.
 */
import { initDashboard } from './dashboard.js';
import { initAdmin } from './admin.js';
import { initAlerts } from './alerts.js';
import { initEvents } from './events.js';

function initTheme() {
    const toggleBtn = document.getElementById('themeToggle');
    const htmlEl = document.documentElement;

    const savedTheme = localStorage.getItem('theme') || 'light';
    applyTheme(savedTheme, toggleBtn, htmlEl);

    if (!toggleBtn) return;

    toggleBtn.addEventListener('click', () => {
        const next = htmlEl.getAttribute('data-bs-theme') === 'dark' ? 'light' : 'dark';
        localStorage.setItem('theme', next);
        applyTheme(next, toggleBtn, htmlEl);
    });
}

function applyTheme(theme, toggleBtn, htmlEl) {
    htmlEl.setAttribute('data-bs-theme', theme);
    if (toggleBtn) {
        toggleBtn.textContent = theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
    }
}

const ROUTES = {
    '/': initDashboard,
    '/alerts': initAlerts,
    '/events': initEvents,
    '/config': initAdmin,
};

function main() {
    initTheme();

    const init = ROUTES[window.location.pathname];
    if (init) {
        // A failure in one page module shouldn't leave the console silent.
        Promise.resolve(init()).catch((err) => console.error('Page init failed:', err));
    }
}

main();
