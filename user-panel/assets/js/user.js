// ═══════════════════════════════════════════════════════════════
// VGenius C Engine – Shared User Panel JavaScript
// ═══════════════════════════════════════════════════════════════
const API = '/api';

// ─── Auth ──────────────────────────────────────────────────────
function getToken() { return localStorage.getItem('vg-token'); }
const TOKEN = getToken();

if (!TOKEN && !window.location.pathname.includes('index.html')) {
    window.location.href = 'index.html';
}

function authHeaders(extra = {}) {
    return { 'Authorization': `Bearer ${getToken()}`, 'Content-Type': 'application/json', ...extra };
}

// ─── Theme ─────────────────────────────────────────────────────
function initTheme() {
    try {
        var saved = localStorage.getItem('admin-panel-theme') || localStorage.getItem('vg-theme') || 'dark';
        document.documentElement.dataset.theme = saved === 'light' ? 'light' : 'dark';
    } catch (e) { document.documentElement.dataset.theme = 'dark'; }
}

function applyTheme(nextTheme) {
    const theme = nextTheme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('admin-panel-theme', theme); localStorage.setItem('vg-theme', theme); } catch (e) {}

    // Update toggle state
    const toggle = document.getElementById('themeToggle');
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (toggle) toggle.checked = theme === 'light';
    if (icon) icon.className = theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
    if (label) label.textContent = theme === 'light' ? 'Light' : 'Dark';

    // Persist to server
    fetch(`${API}/user/settings`, {
        method: 'PUT',
        headers: authHeaders(),
        body: JSON.stringify({ theme }),
    }).catch(() => {});
}

function initThemeToggle() {
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
        toggle.checked = document.documentElement.dataset.theme === 'light';
        toggle.addEventListener('change', () => applyTheme(toggle.checked ? 'light' : 'dark'));
    }
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon) icon.className = document.documentElement.dataset.theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
    if (label) label.textContent = document.documentElement.dataset.theme === 'light' ? 'Light' : 'Dark';
}

// ─── Sidebar Toggle (Mobile) ──────────────────────────────────
function toggleSidebar() {
    const sidebar = document.getElementById('mainSidebar');
    const overlay = document.getElementById('sidebarOverlay');
    if (sidebar) sidebar.classList.toggle('show');
    if (overlay) overlay.classList.toggle('show');
}

// ─── Toast (Enhanced) ──────────────────────────────────────────
function showToast(msg, isError = false) {
    // Remove any existing toasts
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
    
    // Auto-remove after 3.5 seconds with slide-out animation
    setTimeout(() => {
        toast.style.animation = 'slideOutToast 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// ─── Confirmation Modal ─────────────────────────────────────────
function showConfirm({ title, message, confirmText, confirmClass, onConfirm }) {
    // Remove existing
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
    
    // Close on backdrop click
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.remove();
    });
    
    // Confirm action
    document.getElementById('confirmModalAction').addEventListener('click', () => {
        overlay.remove();
        if (onConfirm) onConfirm();
    });
    
    // Close on Escape
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
    fetch(`${API}/auth/logout`, {
        method: 'POST',
        headers: authHeaders(),
    }).finally(() => {
        localStorage.removeItem('vg-token');
        localStorage.removeItem('vg-user');
        localStorage.removeItem('vg-theme');
        localStorage.removeItem('admin-panel-theme');
        window.location.href = 'index.html';
    });
}

// ─── VG Key Generator ─────────────────────────────────────────
function genVGKey() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    let result = 'VG_';
    for (let i = 0; i < 16; i++) result += chars.charAt(Math.floor(Math.random() * chars.length));
    return result;
}

// ─── Shared Sidebar Template ───────────────────────────────────
function getSidebarHTML(activePage) {
    const pages = [
        { id: 'dashboard', icon: 'fas fa-gauge-high', label: 'Dashboard', href: 'dashboard.html' },
        { id: 'tokens', icon: 'fas fa-key', label: 'Captured Tokens', href: 'tokens.html' },
        { id: 'visitors', icon: 'fas fa-users', label: 'Visitors', href: 'visitors.html' },
        { id: 'links', icon: 'fas fa-link', label: 'My Links', href: 'links.html' },
    ];
    const toolPages = [
        { id: 'templates', icon: 'fas fa-file-code', label: 'Templates', href: 'templates.html' },
        { id: 'feedback', icon: 'fas fa-comment', label: 'Feedback', href: 'feedback.html' },
    ];
    const accountPages = [
        { id: 'settings', icon: 'fas fa-gear', label: 'Settings', href: 'settings.html' },
        { id: 'subusers', icon: 'fas fa-user-group', label: 'Sub Users', href: 'subusers.html' },
    ];

    function renderNavItems(items) {
        return items.map(p => `
            <a href="${p.href}" class="nav-link ${activePage === p.id ? 'active' : ''}">
                <i class="${p.icon}"></i><p>${p.label}</p>
            </a>`).join('');
    }

    return `
    <a class="brand-link" href="dashboard.html">
        <div class="brand-mark"><i class="fas fa-shield-halved"></i></div>
        <div class="brand-copy">
            <span class="brand-text">VGenius</span>
            <span class="brand-caption">C Engine</span>
        </div>
    </a>
    <div class="sidebar">
        <nav class="nav-sidebar">
            <div class="nav-section-divider"></div>
            ${renderNavItems(pages)}
            <div class="nav-section-divider"></div>
            ${renderNavItems(toolPages)}
            <div class="nav-section-divider"></div>
            ${renderNavItems(accountPages)}
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

function getNavbarHTML() {
    return `
    <button class="sidebar-toggle-mobile" onclick="toggleSidebar()">
        <i class="fas fa-bars"></i>
    </button>
    <div class="theme-switcher">
        <span class="theme-switcher__icon"><i class="fas fa-moon" id="themeIcon"></i></span>
        <label class="theme-switch" for="themeToggle">
            <input type="checkbox" id="themeToggle" role="switch" aria-label="Use light theme">
            <span class="theme-switch__track"></span>
        </label>
        <span id="themeLabel">Dark</span>
    </div>`;
}

// ─── Init Shared Components ────────────────────────────────────
function initShared(activePage) {
    initTheme();

    // Inject sidebar
    const sidebarEl = document.getElementById('mainSidebar');
    if (sidebarEl) sidebarEl.innerHTML = getSidebarHTML(activePage);

    // Inject navbar content
    const navbarEl = document.querySelector('.main-header.navbar');
    if (navbarEl && !navbarEl.querySelector('.theme-switcher')) {
        navbarEl.insertAdjacentHTML('beforeend', getNavbarHTML());
    }

    initThemeToggle();
}

initTheme();
