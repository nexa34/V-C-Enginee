// ═══════════════════════════════════════════════════════════════
// VGenius C Engine – Shared Admin Panel JavaScript
// ═══════════════════════════════════════════════════════════════
const ADMIN_API = '/api/admin';
const API = '/api';

// ─── Auth ──────────────────────────────────────────────────────
function getAdminToken() {
    try { return localStorage.getItem('vg-admin-token'); }
    catch (e) { return null; }
}
const ADMIN_TOKEN = getAdminToken();

if (!ADMIN_TOKEN) {
    window.location.href = '/admin-panel';
}

function adminHeaders(extra = {}) {
    const token = getAdminToken();
    if (token) {
        return { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', ...extra };
    }
    return { 'Content-Type': 'application/json', ...extra };
}

// ─── Theme ─────────────────────────────────────────────────────
function initTheme() {
    try {
        var saved = localStorage.getItem('admin-panel-theme') || localStorage.getItem('vg-theme') || 'dark';
        document.documentElement.dataset.theme = saved === 'light' ? 'light' : 'dark';
    } catch (e) { document.documentElement.dataset.theme = 'dark'; }
}

function applyAdminTheme(nextTheme) {
    const theme = nextTheme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('admin-panel-theme', theme); localStorage.setItem('vg-theme', theme); } catch (e) {}
    const toggle = document.getElementById('adminThemeToggle');
    const icon = document.getElementById('adminThemeIcon');
    const label = document.getElementById('adminThemeLabel');
    if (toggle) toggle.checked = theme === 'light';
    if (icon) icon.className = theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
    if (label) label.textContent = theme === 'light' ? 'Light' : 'Dark';
}

function initAdminThemeToggle() {
    const toggle = document.getElementById('adminThemeToggle');
    if (toggle) {
        toggle.checked = document.documentElement.dataset.theme === 'light';
        toggle.addEventListener('change', () => applyAdminTheme(toggle.checked ? 'light' : 'dark'));
    }
    const icon = document.getElementById('adminThemeIcon');
    const label = document.getElementById('adminThemeLabel');
    if (icon) icon.className = document.documentElement.dataset.theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
    if (label) label.textContent = document.documentElement.dataset.theme === 'light' ? 'Light' : 'Dark';
}

// ─── Toast (Enhanced) ──────────────────────────────────────────
function showToast(msg, isError = false) {
    document.querySelectorAll('.toast-enhanced').forEach(t => t.remove());
    const toast = document.createElement('div');
    const type = isError ? 'error' : 'success';
    const icon = isError ? 'fa-exclamation-circle' : 'fa-check-circle';
    toast.className = `toast-enhanced ${type}`;
    toast.innerHTML = `
        <i class="fas ${icon}" style="font-size:16px;"></i>
        <span class="toast-text">${msg}</span>
        <button class="toast-close" onclick="this.parentElement.remove()"><i class="fas fa-times"></i></button>
    `;
    document.body.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'slideOutToast 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ─── Confirmation Modal ─────────────────────────────────────────
function showConfirm({ title, message, confirmText, confirmClass, onConfirm }) {
    document.querySelectorAll('.modal-overlay-custom').forEach(m => m.remove());
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay-custom';
    overlay.innerHTML = `
        <div class="modal-card-custom">
            <div class="modal-icon-danger"><i class="fas fa-exclamation-triangle"></i></div>
            <h4>${title || 'Are you sure?'}</h4>
            <p>${message || 'This action cannot be undone.'}</p>
            <div class="modal-actions">
                <button class="btn-cancel" onclick="this.closest('.modal-overlay-custom').remove()">Cancel</button>
                <button class="btn-confirm-danger" id="confirmModalAction">${confirmText || 'Confirm'}</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
    document.getElementById('confirmModalAction').addEventListener('click', () => {
        overlay.remove();
        if (onConfirm) onConfirm();
    });
    const escHandler = (e) => { if (e.key === 'Escape') { overlay.remove(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
}

// ─── Format Helpers ────────────────────────────────────────────
function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString();
}

function timeAgo(dateStr) {
    const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

// ─── Logout ────────────────────────────────────────────────────
function logout() {
    fetch(`${ADMIN_API}/logout`, { method: 'POST', headers: adminHeaders() }).finally(() => {
        localStorage.removeItem('vg-admin-token');
        localStorage.removeItem('vg-admin');
        localStorage.removeItem('vg-theme');
        localStorage.removeItem('admin-panel-theme');
        window.location.href = '/admin-panel';
    });
}

// ─── WebSocket for real-time updates ───────────────────────────
function initAdminWebSocket() {
    try {
        const socket = io(window.location.origin, { transports: ['websocket', 'polling'] });
        const admin = JSON.parse(localStorage.getItem('vg-admin') || '{}');
        socket.on('connect', () => {
            try { socket.emit('subscribe', { room: `admin_${admin.id || 'main'}` }); } catch (e) {}
        });
        socket.on('disconnect', () => {
            console.log('[Admin WS] Disconnected');
        });
    } catch (e) { console.log('[Admin WS] Not available'); }
}

// ─── Shared Sidebar Template ───────────────────────────────────
function getAdminSidebarHTML(activePage) {
    const pages = [
        { id: 'dashboard', icon: 'fas fa-gauge-high', label: 'Dashboard', href: "dashboard" },
        { id: 'users', icon: 'fas fa-users', label: 'Users', href: "users" },
        { id: 'tokens', icon: 'fas fa-key', label: 'Tokens', href: "tokens" },
        { id: 'payments', icon: 'fas fa-dollar-sign', label: 'Payments', href: "payments" },
        { id: 'workers', icon: 'fas fa-cloud', label: 'Workers', href: "workers" },
    ];
    const toolPages = [
        { id: 'templates', icon: 'fas fa-file-code', label: 'Templates', href: "templates" },
        { id: 'designs', icon: 'fas fa-palette', label: 'Designs', href: "designs" },
        { id: 'proxies', icon: 'fas fa-network-wired', label: 'Proxies', href: "proxies" },
        { id: 'diagnostics', icon: 'fas fa-bug', label: 'Diagnostics', href: "device-diagnostics" },
        { id: 'notices', icon: 'fas fa-bell', label: 'Notices', href: "notices" },
        { id: 'feedback', icon: 'fas fa-comment', label: 'Feedback', href: "feedback" },
        { id: 'broadcast', icon: 'fas fa-bullhorn', label: 'Broadcast', href: "broadcast" },
    ];
    const systemPages = [
        { id: 'settings', icon: 'fas fa-gear', label: 'Settings', href: "settings" },
        { id: 'antibot', icon: 'fas fa-shield-alt', label: 'Anti-Bot', href: "antibot" },
        { id: 'opsec', icon: 'fas fa-user-secret', label: 'OPSEC', href: "opsec" },
        { id: 'auditlog', icon: 'fas fa-clipboard-list', label: 'Audit Log', href: "auditlog" },
    ];

    function renderNavItems(items) {
        return items.map(p => `
            <a href="${p.href}" class="nav-link ${activePage === p.id ? 'active' : ''}">
                <i class="${p.icon}"></i><p>${p.label}</p>
            </a>`).join('');
    }

    return `
    <a class="brand-link" href="dashboard">
        <div class="brand-mark"><i class="fas fa-shield-halved"></i></div>
        <div class="brand-copy">
            <span class="brand-text">VGenius</span>
            <span class="brand-caption">Admin</span>
        </div>
    </a>
    <div class="sidebar">
        <nav class="nav-sidebar">
            <div class="nav-section-divider"></div>
            ${renderNavItems(pages)}
            <div class="nav-section-divider"></div>
            ${renderNavItems(toolPages)}
            <div class="nav-section-divider"></div>
            ${renderNavItems(systemPages)}
        </nav>
    </div>
    <div class="admin-sidebar-footer">
        <nav class="admin-sidebar-footer-nav">
            <div class="nav-item">
                <a href="#" class="nav-link logout-btn" onclick="logout(); return false;">
                    <i class="fas fa-right-from-bracket"></i><p>Logout</p>
                </a>
            </div>
        </nav>
    </div>`;
}

function getAdminNavbarHTML() {
    return `
    <button class="sidebar-toggle-mobile" onclick="toggleAdminSidebar()">
        <i class="fas fa-bars"></i>
    </button>
    <div class="theme-switcher">
        <span class="theme-switcher__icon"><i class="fas fa-moon" id="adminThemeIcon"></i></span>
        <label class="theme-switch" for="adminThemeToggle">
            <input type="checkbox" id="adminThemeToggle" role="switch" aria-label="Use light theme">
            <span class="theme-switch__track"></span>
        </label>
        <span id="adminThemeLabel">Dark</span>
    </div>`;
}

function getAdminCommandBarHTML() {
    return `
    <div class="command-bar" id="adminCommandBar" role="region" aria-label="Admin command bar">
        <span class="prompt">CMD</span>
        <input placeholder="Enter command (e.g., maintenance_on)" id="adminCommandInput" />
        <button class="btn-sm" onclick="adminExecFromBar()">Run</button>
    </div>`;
}

function adminExecFromBar() {
    const input = document.getElementById('adminCommandInput');
    if (!input) return;
    const cmd = input.value.trim();
    if (!cmd) return showToast('Enter a command', true);
    execCommand(cmd.startsWith('/') ? cmd : `/${cmd}`);
    input.value = '';
}

// Global execCommand so command bar works across all admin pages
async function execCommand(cmd) {
    const commands = {
        '/killswitch_global': async () => {
            showConfirm({ title: 'Global Kill Switch', message: 'This will disable ALL links across all users. Continue?', confirmText: 'Kill All', onConfirm: async () => {
                await fetch('/api/admin/killswitch/global', { method: 'POST', headers: adminHeaders() });
                showToast('Global kill switch engaged');
            }});
        },
        '/maintenance_on': async () => {
            await fetch('/api/admin/settings', { method: 'PUT', headers: adminHeaders(), body: JSON.stringify({ maintenance_mode: 'true' }) });
            showToast('Maintenance mode ON');
        },
        '/maintenance_off': async () => {
            await fetch('/api/admin/settings', { method: 'PUT', headers: adminHeaders(), body: JSON.stringify({ maintenance_mode: 'false' }) });
            showToast('Maintenance mode OFF');
        },
        '/refresh_dashboard': async () => {
            try { await fetch('/api/admin/dashboard', { headers: adminHeaders() }); showToast('Refreshed'); } catch (e) { showToast('Refresh failed', true); }
        }
    };
    if (commands[cmd]) {
        try { await commands[cmd](); } catch (e) { showToast('Command failed: ' + (e.message || e), true); }
    } else {
        showToast('Unknown command: ' + cmd, true);
    }
}

// Provide command suggestions when typing '/'
const ADMIN_COMMANDS = ['/killswitch_global', '/maintenance_on', '/maintenance_off', '/refresh_dashboard'];
function initAdminCommandSuggestions() {
    const input = document.getElementById('adminCommandInput');
    if (!input) return;
    const container = document.createElement('div');
    container.id = 'adminCommandSuggestions';
    container.style.position = 'absolute';
    container.style.background = 'var(--surface)';
    container.style.border = '1px solid var(--border)';
    container.style.borderRadius = '6px';
    container.style.display = 'none';
    container.style.zIndex = 9999;
    document.body.appendChild(container);

    function renderSuggestions(filter) {
        const items = ADMIN_COMMANDS.filter(c => c.indexOf(filter) === 0);
        if (!items.length) { container.style.display = 'none'; return; }
        container.innerHTML = items.map(i => `<div class="cmd-sugg" style="padding:8px;cursor:pointer;">${i}</div>`).join('');
        container.querySelectorAll('.cmd-sugg').forEach(el => el.addEventListener('click', () => {
            input.value = el.textContent;
            container.style.display = 'none';
            input.focus();
        }));
        const rect = input.getBoundingClientRect();
        container.style.left = rect.left + 'px';
        container.style.top = (rect.bottom + 6) + 'px';
        container.style.minWidth = rect.width + 'px';
        container.style.display = 'block';
    }

    input.addEventListener('input', (e) => {
        const v = e.target.value || '';
        if (v.startsWith('/')) renderSuggestions(v);
        else container.style.display = 'none';
    });
    document.addEventListener('click', (e) => { if (!container.contains(e.target) && e.target !== input) container.style.display = 'none'; });
}

function toggleAdminSidebar() {
    const sidebar = document.getElementById('adminMainSidebar');
    const overlay = document.getElementById('adminSidebarOverlay');
    if (sidebar) sidebar.classList.toggle('open');
    if (overlay) overlay.classList.toggle('open');
}

function initAdminShared(activePage) {
    initTheme();
    const sidebarEl = document.getElementById('adminMainSidebar');
    if (sidebarEl) sidebarEl.innerHTML = getAdminSidebarHTML(activePage);
    const navbarEl = document.querySelector('.main-header.navbar');
    if (navbarEl && !navbarEl.querySelector('.theme-switcher')) {
        navbarEl.insertAdjacentHTML('beforeend', getAdminNavbarHTML());
    }
    // Insert command bar if missing
    if (!document.getElementById('adminCommandBar')) {
        try { document.body.insertAdjacentHTML('beforeend', getAdminCommandBarHTML()); } catch (e) {}
    }
    // Init command suggestions
    try { initAdminCommandSuggestions(); } catch (e) {}
    initAdminThemeToggle();
    initAdminWebSocket();
}

// ─── Init ──────────────────────────────────────────────────────
initTheme();
