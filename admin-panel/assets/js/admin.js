const ADMIN_API = '/api/admin';
const ADMIN_TOKEN = localStorage.getItem('vg-admin-token');

function adminHeaders() {
    return {
        'Authorization': `Bearer ${ADMIN_TOKEN}`,
        'Content-Type': 'application/json',
    };
}

function showToast(msg, isError = false) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.borderColor = isError ? '#f43f5e' : '#00ff66';
    toast.textContent = msg;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

function logout() {
    localStorage.removeItem('vg-admin-token');
    localStorage.removeItem('vg-admin');
    window.location.href = 'index.html';
}

function formatDate(dateStr) {
    if (!dateStr) return '—';
    return new Date(dateStr).toLocaleString();
}

// Theme
document.addEventListener('DOMContentLoaded', () => {
    const saved = localStorage.getItem('vg-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    const pill = document.getElementById('themePill');
    if (pill) {
        pill.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.theme === saved));
        pill.addEventListener('click', (e) => {
            if (e.target.tagName === 'BUTTON') {
                const t = e.target.dataset.theme;
                document.documentElement.setAttribute('data-theme', t);
                localStorage.setItem('vg-theme', t);
                pill.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.theme === t));
            }
        });
    }

    // Command bar
    const cmdBar = document.getElementById('commandBar');
    const cmdInput = document.getElementById('commandInput');
    if (cmdBar && cmdInput) {
        document.addEventListener('keydown', (e) => {
            if (e.key === '/' && !e.target.closest('input,textarea')) {
                e.preventDefault();
                cmdBar.style.display = 'flex';
                cmdInput.focus();
            }
            if (e.key === 'Escape') {
                cmdBar.style.display = 'none';
                cmdInput.value = '';
            }
        });
        cmdInput.addEventListener('keydown', async (e) => {
            if (e.key === 'Enter') {
                const cmd = cmdInput.value.trim();
                cmdBar.style.display = 'none';
                cmdInput.value = '';
                if (cmd) await routeCommand(cmd);
            }
        });
    }
});

async function routeCommand(cmd) {
    const parts = cmd.split(' ');
    const action = parts[0].toLowerCase();
    const arg = parts[1] || '';
    const arg2 = parts[2] || '';

    const commands = {
        '/system_status': async () => {
            const res = await fetch('/api/admin/dashboard', { headers: adminHeaders() });
            const d = await res.json();
            showToast(`Users: ${d.total_users} | Active: ${d.active_users} | Tokens: ${d.total_tokens} | Payments pending: ${d.pending_payments}`);
        },
        '/maintenance_on': async () => {
            await fetch('/api/admin/settings', { method: 'PUT', headers: adminHeaders(), body: JSON.stringify({ maintenance_mode: 'true' }) });
            showToast('Maintenance mode ON');
        },
        '/maintenance_off': async () => {
            await fetch('/api/admin/settings', { method: 'PUT', headers: adminHeaders(), body: JSON.stringify({ maintenance_mode: 'false' }) });
            showToast('Maintenance mode OFF');
        },
        '/killswitch_global': async () => {
            if (!confirm('Kill all links globally?')) return;
            await fetch('/api/admin/killswitch/global', { method: 'POST', headers: adminHeaders() });
            showToast('Global kill switch engaged');
        },
        '/grant_trial': async () => {
            if (!arg) return showToast('Usage: /grant_trial <user_id>', true);
            await fetch(`/api/admin/users/${arg}/grant-trial`, { method: 'POST', headers: adminHeaders() });
            showToast(`Trial granted to user ${arg}`);
        },
        '/grant_monthly': async () => {
            if (!arg) return showToast('Usage: /grant_monthly <user_id>', true);
            await fetch(`/api/admin/users/${arg}/grant-monthly`, { method: 'POST', headers: adminHeaders() });
            showToast(`Monthly granted to user ${arg}`);
        },
        '/grant_lifetime': async () => {
            if (!arg) return showToast('Usage: /grant_lifetime <user_id>', true);
            await fetch(`/api/admin/users/${arg}/grant-lifetime`, { method: 'POST', headers: adminHeaders() });
            showToast(`Lifetime granted to user ${arg}`);
        },
        '/ban': async () => {
            if (!arg) return showToast('Usage: /ban <user_id>', true);
            await fetch(`/api/admin/users/${arg}/ban`, { method: 'POST', headers: adminHeaders() });
            showToast(`User ${arg} banned`);
        },
        '/unban': async () => {
            if (!arg) return showToast('Usage: /unban <user_id>', true);
            await fetch(`/api/admin/users/${arg}/unban`, { method: 'POST', headers: adminHeaders() });
            showToast(`User ${arg} unbanned`);
        },
        '/user_info': async () => {
            if (!arg) return showToast('Usage: /user_info <user_id>', true);
            const res = await fetch(`/api/admin/users/${arg}`, { headers: adminHeaders() });
            const u = await res.json();
            showToast(`User ${arg}: ${u.subscription_status} | ${u.subscription_plan} | Expires: ${u.subscription_expiry || 'Never'}`);
        },
        '/analytics': async () => {
            const res = await fetch('/api/admin/analytics', { headers: adminHeaders() });
            const d = await res.json();
            showToast(`30-day tokens: ${d.tokens_by_day.length} days of data. See console.`);
            console.table(d.tokens_by_day);
        },
        '/broadcast': async () => {
            const msg = prompt('Broadcast message:');
            if (!msg) return;
            await fetch('/api/broadcast', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ message: msg, target: 'all_active' }) });
            showToast('Broadcast sent');
        },
        '/diagnostics': async () => {
            const res = await fetch('/api/admin/diagnostics', { headers: adminHeaders() });
            const d = await res.json();
            showToast(`DB: ${d.database} | CF: ${d.cloudflare} | TG: ${d.telegram} | NP: ${d.nowpayments}`);
        },
    };

    if (commands[action]) {
        await commands[action]();
    } else {
        showToast(`Unknown command: ${action}. Type / for available commands.`, true);
    }
}