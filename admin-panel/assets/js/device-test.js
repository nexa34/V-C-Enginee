/* VGenius - Device Test Panel controller */
(function () {
    'use strict';

    var API = '/api/admin';
    var lastResult = null;

    function getToken() {
        try { return localStorage.getItem('vg-admin-token'); } catch (e) { return null; }
    }

    function headers() {
        var t = getToken();
        var h = { 'Content-Type': 'application/json' };
        if (t) h['Authorization'] = 'Bearer ' + t;
        return h;
    }

    function $(id) { return document.getElementById(id); }

    function toast(msg, isErr) {
        var el = $('toast');
        if (!el) return;
        el.textContent = msg;
        el.className = 'toast show' + (isErr ? ' err' : '');
        setTimeout(function () { el.className = 'toast'; }, 2400);
    }

    function escapeHtml(s) {
        if (s == null) return '';
        return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function escapeAttr(s) {
        return String(s == null ? '' : s)
            .replace(/\\/g, '\\\\')
            .replace(/'/g, "\\'")
            .replace(/"/g, '&quot;');
    }

    function fallbackCopy(text, done) {
        var ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done && done(); } catch (e) { toast('Copy failed', true); }
        document.body.removeChild(ta);
    }

    function copyText(text, btn) {
        if (!text) { toast('Nothing to copy', true); return; }
        var done = function () {
            if (btn) {
                var orig = btn.textContent;
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(function () { btn.textContent = orig; btn.classList.remove('copied'); }, 1400);
            }
        };
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
        } else {
            fallbackCopy(text, done);
        }
    }

    function buildSteps(steps) {
        var items = [
            ['rsa_keypair_generated', 'RSA keypair generated'],
            ['csr_generated', 'CSR generated'],
            ['drs_registered', 'DRS registration'],
            ['prt_exchange_succeeded', 'PRT exchange']
        ];
        var html = '';
        items.forEach(function (pair) {
            var ok = steps && steps[pair[0]];
            var cls = ok ? 'ok' : 'bad';
            var icon = ok ? '<i class="fas fa-check"></i>' : '<i class="fas fa-xmark"></i>';
            html += '<div class="dt-step"><span class="icon ' + cls + '">' + icon + '</span><span>' + pair[1] + '</span></div>';
        });
        return '<div>' + html + '</div>';
    }

    function buildResultModal(result) {
        var parts = [];
        if (result.success) {
            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Elapsed</span></div><div class="dt-kv">' +
                '<span class="k">Time</span><span class="v">' + (result.elapsed_ms || 0) + ' ms</span>' +
                '<span class="k">Tenant</span><span class="v">' + escapeHtml(result.tenant_id || '') + '</span>' +
                '<span class="k">Target Domain</span><span class="v">' + escapeHtml(result.target_domain || '') + '</span>' +
                '<span class="k">Assertion Audience</span><span class="v">' + escapeHtml(result.assertion_audience || '') + '</span>' +
                '</div></div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Flow Steps</span></div>' + buildSteps(result.steps) + '</div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Device ID</span>' +
                '<button class="dt-copy-btn" onclick="window.dt.copy(\'' + escapeAttr(result.device_id || '') + '\', this)">Copy</button>' +
                '</div><div class="dt-block">' + escapeHtml(result.device_id || '') + '</div></div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Certificate Thumbprint</span>' +
                '<button class="dt-copy-btn" onclick="window.dt.copy(\'' + escapeAttr(result.certificate_thumbprint || '') + '\', this)">Copy</button>' +
                '</div><div class="dt-block">' + escapeHtml(result.certificate_thumbprint || '') + '</div></div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">PRT Cookie (raw)</span>' +
                '<button class="dt-copy-btn" onclick="window.dt.copy(\'' + escapeAttr(result.prt_cookie || '') + '\', this)">Copy</button>' +
                '</div><div class="dt-block">' + escapeHtml(result.prt_cookie || '') + '</div></div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">PRT Cookie (URL-encoded)</span>' +
                '<button class="dt-copy-btn" onclick="window.dt.copy(\'' + escapeAttr(result.prt_cookie_encoded || '') + '\', this)">Copy</button>' +
                '</div><div class="dt-block">' + escapeHtml(result.prt_cookie_encoded || '') + '</div></div>');

            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Certificate PEM</span>' +
                '<button class="dt-copy-btn" onclick="window.dt.copy(\'' + escapeAttr(result.certificate_pem || '') + '\', this)">Copy</button>' +
                '</div><div class="dt-block">' + escapeHtml(result.certificate_pem || '') + '</div></div>');

            var st = result.storage || {};
            var cls = st.stored ? 'ok' : (st.error ? 'bad' : 'warn');
            var icon = st.stored ? '<i class="fas fa-check"></i>' : (st.error ? '<i class="fas fa-xmark"></i>' : '<i class="fas fa-circle-info"></i>');
            var msg = st.stored
                ? ('Stored under user_id=' + st.user_id + ', tenant=' + escapeHtml(st.tenant_id || ''))
                : (st.error ? ('Store failed: ' + escapeHtml(st.error)) : ('Not stored: ' + escapeHtml(st.reason || 'inMemory mode')));
            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Storage</span></div>' +
                '<div class="dt-storage ' + cls + '">' + icon + '<span>' + msg + '</span></div></div>');
        } else {
            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Elapsed</span></div><div class="dt-kv">' +
                '<span class="k">Time</span><span class="v">' + (result.elapsed_ms || 0) + ' ms</span></div></div>');
            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Flow Steps</span></div>' + buildSteps(result.steps) + '</div>');
            parts.push('<div class="dt-section"><div class="dt-section-head"><span class="lbl">Error</span></div>' +
                '<div class="dt-error-block">' + escapeHtml(result.error || 'Unknown error') + '</div></div>');
        }
        return parts.join('');
    }

    function openModalHtml(titleHtml, bodyHtml, kind) {
        var titleEl = $('modalTitle');
        var bodyEl = $('modalBody');
        if (!titleEl || !bodyEl) return;
        titleEl.innerHTML = titleHtml;
        titleEl.className = 'dt-modal-title ' + (kind === 'success' ? 'success' : 'error');
        bodyEl.innerHTML = bodyHtml;
        $('resultModal').classList.add('active');
    }

    window.closeModal = function () {
        var m = $('resultModal');
        if (m) m.classList.remove('active');
    };

    function inspectTokens() {
        var body = {
            access_token: $('accessToken').value,
            refresh_token: $('refreshToken').value
        };
        if (!body.access_token && !body.refresh_token) {
            toast('Paste at least one token first', true);
            return;
        }
        var btn = $('inspectBtn');
        btn.disabled = true;
        fetch(API + '/device-test/inspect', { method: 'POST', headers: headers(), body: JSON.stringify(body) })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.success) { toast(data.error || 'Inspect failed', true); return; }
                var box = $('inspectBox');
                var rows = [];
                var at = data.access_token || {};
                if (at.parsed) {
                    rows.push(['Access Token', 'Valid JWT']);
                    rows.push(['Tenant ID (tid)', at.tenant_id || '—']);
                    rows.push(['UPN', at.upn || at.iss || '—']);
                    rows.push(['Target Domain', at.target_domain || '—']);
                    rows.push(['Expires', at.exp_human || '—']);
                    if (at.tenant_id && !$('tenantId').value) $('tenantId').value = at.tenant_id;
                    if (at.target_domain && !$('targetDomain').value) $('targetDomain').value = at.target_domain;
                } else {
                    rows.push(['Access Token', 'Not a parseable JWT']);
                }
                var rt = data.refresh_token || {};
                rows.push(['Refresh Token prefix', rt.prefix || '—']);
                rows.push(['Refresh Token parsed', rt.parsed ? 'Yes' : 'No (may be refresh token format)']);
                box.innerHTML = rows.map(function (r) {
                    return '<div class="row"><span class="k">' + escapeHtml(r[0]) + '</span><span class="v">' + escapeHtml(r[1]) + '</span></div>';
                }).join('');
                box.style.display = 'block';
            })
            .catch(function (e) { toast('Inspect failed: ' + e.message, true); })
            .finally(function () { btn.disabled = false; });
    }

    function runDrsTest() {
        var access = $('accessToken').value.trim();
        var refresh = $('refreshToken').value.trim();
        if (!access || !refresh) { toast('Both access_token and refresh_token are required', true); return; }

        var body = {
            access_token: access,
            refresh_token: refresh,
            tenant_id: $('tenantId').value.trim() || undefined,
            target_domain: $('targetDomain').value.trim() || undefined,
            user_id: Number($('userId').value) || 0,
            store: $('storeToggle').checked
        };

        var btn = $('runBtn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Running...';

        fetch(API + '/device-test/run', { method: 'POST', headers: headers(), body: JSON.stringify(body) })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                lastResult = data;
                $('downloadBtn').disabled = false;
                var kind = data.success ? 'success' : 'error';
                var title = data.success
                    ? '<i class="fas fa-circle-check"></i> DRS Test Succeeded'
                    : '<i class="fas fa-circle-xmark"></i> DRS Test Failed';
                openModalHtml(title, buildResultModal(data), kind);
                toast(data.success ? 'DRS test completed' : 'DRS test failed', !data.success);
            })
            .catch(function (e) { toast('Request failed: ' + e.message, true); })
            .finally(function () {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-bolt"></i> Run DRS Test';
            });
    }

    function renewAll() {
        var refresh = $('refreshToken').value.trim();
        if (!refresh) { toast('Paste a refresh_token first', true); return; }
        var btn = $('renewAllBtn');
        btn.disabled = true;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Renewing...';

        fetch(API + '/device-test/renew-all', { method: 'POST', headers: headers(), body: JSON.stringify({ refresh_token: refresh }) })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.success) { toast(data.error || 'Renew all failed', true); return; }
                lastResult = { success: true, renew_all: data, timestamp: new Date().toISOString() };
                $('downloadBtn').disabled = false;
                var summary = '<div class="dt-renew-summary">' +
                    '<div class="dt-stat neutral"><div class="n">' + data.processed + '</div><div class="l">Processed</div></div>' +
                    '<div class="dt-stat ok"><div class="n">' + data.succeeded + '</div><div class="l">Succeeded</div></div>' +
                    '<div class="dt-stat bad"><div class="n">' + data.failed + '</div><div class="l">Failed</div></div>' +
                    '</div>';
                var list = (data.results || []).map(function (r) {
                    var cls = r.success ? 'ok' : 'bad';
                    var icon = r.success ? '<i class="fas fa-check"></i>' : '<i class="fas fa-xmark"></i>';
                    var val = r.success
                        ? ('PRT: ' + escapeHtml((r.prt_cookie || '').substring(0, 40)) + '...')
                        : ('Error: ' + escapeHtml(r.error || ''));
                    return '<div style="padding:8px 10px;border-radius:8px;margin-bottom:6px;background:' +
                        (r.success ? 'rgba(16,185,129,0.06)' : 'rgba(239,68,68,0.06)') +
                        ';border:1px solid ' + (r.success ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)') +
                        ';font-size:12px;"><div style="font-weight:600;margin-bottom:4px;">' + icon +
                        ' user_id=' + r.user_id + ' - tenant=' + escapeHtml(r.tenant_id) + ' - device=' + escapeHtml(r.device_id || '') + '</div>' +
                        '<div style="font-family:monospace;word-break:break-all;">' + val + '</div></div>';
                }).join('');
                var html = summary + '<div class="dt-section"><div class="dt-section-head"><span class="lbl">Per-Row Results</span></div>' + (list || '<div class="dt-empty">No rows</div>') + '</div>';
                openModalHtml('<i class="fas fa-rotate"></i> Renew All Results (' + data.succeeded + '/' + data.processed + ')', html, 'success');
            })
            .catch(function (e) { toast('Renew all failed: ' + e.message, true); })
            .finally(function () {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-rotate"></i> Renew All Stored';
            });
    }

    function shortId(s) {
        if (!s) return '—';
        s = String(s);
        return s.length > 12 ? s.substring(0, 8) + '...' + s.substring(s.length - 4) : s;
    }

    function loadStored() {
        var wrap = $('storedTableWrap');
        wrap.innerHTML = '<div class="dt-empty"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
        fetch(API + '/device-test/stored', { headers: headers() })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.success) { wrap.innerHTML = '<div class="dt-empty">Error: ' + escapeHtml(data.error || '') + '</div>'; return; }
                var rows = data.credentials || [];
                $('storedCount').textContent = rows.length + ' credential' + (rows.length === 1 ? '' : 's');
                if (!rows.length) {
                    wrap.innerHTML = '<div class="dt-empty"><i class="fas fa-inbox"></i> No stored credentials yet. Enable "Store" and run a DRS test to persist one.</div>';
                    return;
                }
                var html = '<table class="dt-stored"><thead><tr>' +
                    '<th>ID</th><th>User ID</th><th>Tenant</th><th>Device ID</th><th>UPN</th><th>Last Used</th><th>Actions</th>' +
                    '</tr></thead><tbody>' +
                    rows.map(function (r) {
                        var lastUsed = r.last_used ? new Date(r.last_used).toLocaleString() : 'never';
                        return '<tr>' +
                            '<td>' + r.id + '</td>' +
                            '<td class="mono">' + r.user_id + '</td>' +
                            '<td class="mono" title="' + escapeAttr(r.tenant_id || '') + '">' + escapeHtml(shortId(r.tenant_id)) + '</td>' +
                            '<td class="mono" title="' + escapeAttr(r.device_id || '') + '">' + escapeHtml(shortId(r.device_id)) + '</td>' +
                            '<td>' + escapeHtml(r.user_principal_name || '—') + '</td>' +
                            '<td>' + escapeHtml(lastUsed) + '</td>' +
                            '<td>' +
                                '<button class="dt-mini-btn primary" onclick="window.dt.copy(\'' + escapeAttr(r.tenant_id || '') + '\', this)">Tenant</button>' +
                                '<button class="dt-mini-btn primary" onclick="window.dt.copy(\'' + escapeAttr(r.device_id || '') + '\', this)">Device</button>' +
                                '<button class="dt-mini-btn danger" onclick="window.dt.clearStored(' + r.user_id + ', \'' + escapeAttr(r.tenant_id || '') + '\')">Clear</button>' +
                            '</td>' +
                            '</tr>';
                    }).join('') + '</tbody></table>';
                wrap.innerHTML = html;
            })
            .catch(function (e) { wrap.innerHTML = '<div class="dt-empty">Error: ' + escapeHtml(e.message) + '</div>'; });
    }

    function clearStored(userId, tenantId) {
        if (!confirm('Clear device_credentials row for user_id=' + userId + ' tenant=' + tenantId + '?')) return;
        var url = API + '/device-test/stored/' + encodeURIComponent(userId) + '/' + encodeURIComponent(tenantId);
        fetch(url, { method: 'DELETE', headers: headers() })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                toast(data.deleted ? 'Cleared' : 'No matching row', !data.deleted);
                loadStored();
            })
            .catch(function (e) { toast('Clear failed: ' + e.message, true); });
    }

    function downloadJson() {
        if (!lastResult) { toast('Nothing to download', true); return; }
        var json = JSON.stringify(lastResult, null, 2);
        var blob = new Blob([json], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'device-test-' + new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19) + '.json';
        document.body.appendChild(a); a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    function clearInputs() {
        $('accessToken').value = '';
        $('refreshToken').value = '';
        $('tenantId').value = '';
        $('targetDomain').value = '';
        $('userId').value = '0';
        $('storeToggle').checked = false;
        $('inspectBox').style.display = 'none';
        $('inspectBox').innerHTML = '';
        toast('Inputs cleared');
    }

    function bind() {
        $('inspectBtn').addEventListener('click', inspectTokens);
        $('runBtn').addEventListener('click', runDrsTest);
        $('renewAllBtn').addEventListener('click', renewAll);
        $('loadStoredBtn').addEventListener('click', loadStored);
        $('clearInputsBtn').addEventListener('click', clearInputs);
        $('downloadBtn').addEventListener('click', downloadJson);
        var dm = $('downloadModalBtn');
        if (dm) dm.addEventListener('click', downloadJson);
        $('resultModal').addEventListener('click', function (e) {
            if (e.target === $('resultModal')) window.closeModal();
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') window.closeModal();
        });
    }

    window.dt = {
        copy: copyText,
        clearStored: clearStored,
        closeModal: window.closeModal
    };

    document.addEventListener('DOMContentLoaded', function () {
        bind();
        loadStored();
        if (typeof initAdminShared === 'function') {
            try { initAdminShared('device_test'); } catch (e) { console.warn('[DeviceTest] initAdminShared failed:', e); }
        }
    });
})();