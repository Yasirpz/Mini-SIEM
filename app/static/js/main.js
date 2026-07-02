import { initDashboard } from './dashboard.js';
import { initAdmin } from './admin.js';

function initTheme() {
    const toggleBtn = document.getElementById('themeToggle');
    const htmlEl = document.documentElement;

    const savedTheme = localStorage.getItem('theme') || 'light';
    htmlEl.setAttribute('data-bs-theme', savedTheme);
    if (toggleBtn) toggleBtn.textContent = savedTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';

    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const currentTheme = htmlEl.getAttribute('data-bs-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

            htmlEl.setAttribute('data-bs-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            toggleBtn.textContent = newTheme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
        });
    }
}

function main() {
    initTheme();
    const path = window.location.pathname;

    if (path === '/' || path === '/index') {
        initDashboard();
    }
    else if (path === '/config') {
        initAdmin();
    }
}

main();
