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

/** Format an API timestamp ("YYYY-MM-DD HH:MM:SS", UTC) in local time. */
export function formatTime(value) {
    if (!value) return '-';
    const parsed = new Date(`${value.replace(' ', 'T')}Z`);
    return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
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
