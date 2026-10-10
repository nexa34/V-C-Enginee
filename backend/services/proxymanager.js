const db = require('../database/connection');
const proxyagent = require('./proxyagent');

// `user:pass@host:port` carries no protocol, so the parser has to guess. Port
// 1080 is the IANA-registered SOCKS port and is what residential pools
// (luxproxy and most others) serve SOCKS5 on; plain HTTP/HTTPS usually sits on
// 80/8080/3128. Defaulting every row to `http` - which the parser used to do -
// is correct for most residential lists but wrong for the very common 1080
// pools, and a SOCKS proxy handed to axios's HTTP CONNECT path hangs until
// timeout instead of failing fast. Inferring from the port is the best
// available default; testProxy() additionally probes the other protocol and
// writes back the winner, so a wrong guess self-heals on the first Test click.
const SOCKS_PORTS = new Set([1080, 10801, 10802, 10803, 10804, 10805, 10806,
    10807, 10808, 10809, 10810, 10811, 10812]);
const HTTP_PORTS = new Set([80, 8080, 3128, 8888]);

/** Guess a proxy protocol from its port. Never throws. */
function inferType(port) {
    const p = Number(port);
    if (SOCKS_PORTS.has(p)) return 'socks5';
    if (HTTP_PORTS.has(p)) return 'http';
    return 'http';
}

/**
 * Parse proxy string in format: username:password@host:port
 * @param {string} proxyStr - Proxy string
 * @returns {Object} Parsed proxy object
 */
function parseProxyString(proxyStr) {
    proxyStr = proxyStr.trim();

    if (!proxyStr) return null;

    const match = proxyStr.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
    if (match) {
        return {
            host: match[3],
            port: parseInt(match[4]),
            username: match[1],
            password: match[2],
            type: inferType(match[4])
        };
    }

    // Format: host:port (no auth)
    const simpleMatch = proxyStr.match(/^([^:]+):(\d+)$/);
    if (simpleMatch) {
        return {
            host: simpleMatch[1],
            port: parseInt(simpleMatch[2]),
            username: null,
            password: null,
            type: inferType(simpleMatch[2])
        };
    }

    // Log failed parse for debugging
    return null;
}

/**
 * Add a single proxy to the database
 */
async function addProxy(proxyData) {
    const {
        host,
        port,
        username,
        password,
        type = 'http',
        notes = null
    } = proxyData;

    // Validate required fields
    if (!host || !port) {
        throw new Error(`Invalid proxy data: host=${host}, port=${port}`);
    }

    // Validate port range
    if (port < 1 || port > 65535) {
        throw new Error(`Invalid port: ${port}`);
    }

    const [result] = await db.query(
        `INSERT INTO proxies (
            proxy_host,
            proxy_port,
            proxy_username,
            proxy_password,
            proxy_type,
            notes
        )
        VALUES (?, ?, ?, ?, ?, ?)`,
        [host, port, username || null, password || null, type, notes]
    );

    return { id: result.insertId, host, port, username, password, type, notes };
}

/**
 * Import multiple proxies from a list.
 *
 * Batched on purpose. A line-by-line import costs two awaited round-trips per
 * line (a dedup SELECT, then the INSERT), so a 10k-line upload was 20k serial
 * queries - several minutes, which nginx then killed at its 60s
 * proxy_read_timeout and the panel saw a 504 HTML page instead of JSON.
 * Now: parse + dedupe in memory, ONE SELECT per chunk of hosts, then bulk
 * INSERTs of 500 rows. A 10k upload is ~68 queries and finishes in a couple
 * of seconds.
 */
async function importProxies(proxyList, type = 'http') {
    const results = {
        success: 0,
        failed: 0,
        duplicates: 0,
        errors: [],
        errorCount: 0,
        lines: 0
    };

    if (!proxyList || typeof proxyList !== 'string') {
        results.errors.push('Invalid input: proxyList must be a string');
        return results;
    }

    // Only keep the first N error messages - a 10k-line list with thousands of
    // bad rows would otherwise return a multi-MB errors array to the browser.
    const pushErr = (m) => {
        results.errorCount++;
        if (results.errors.length < 20) results.errors.push(m);
    };

    const lines = proxyList.split(/\r?\n/);
    results.lines = lines.length;

    // \u0000 cannot appear in a host, port, username or password, so it is a
    // safe composite-key delimiter. null and '' both mean "no credentials" and
    // must produce the same key.
    const identityKey = (p) =>
        `${p.host}\u0000${p.port}\u0000${p.username || null}\u0000${p.password || null}`;

    const parsed = [];
    const seen = new Set();

    for (const line of lines) {
        const proxyStr = line.trim();
        if (!proxyStr || proxyStr.startsWith('#')) continue;

        const p = parseProxyString(proxyStr);
        if (!p) {
            results.failed++;
            pushErr(`Invalid format: "${proxyStr}"`);
            continue;
        }
        if (!p.host || !p.port) {
            results.failed++;
            pushErr(`Invalid parsed data for: "${proxyStr}"`);
            continue;
        }

        // Dedupe within the upload first. Without this, a repeated line would
        // only be caught later by the per-row SELECT fallback.
        const key = identityKey(p);
        if (seen.has(key)) { results.duplicates++; continue; }
        seen.add(key);
        parsed.push(p);
    }

    if (parsed.length === 0) return results;

    // Load every existing identity for the hosts involved - one query per chunk
    // instead of one per line. NULL-safe compare in JS: null and undefined both
    // mean "no credentials".
    await ensureProxyHostIndex();

    const hosts = [...new Set(parsed.map(p => p.host))];
    const HOST_CHUNK = 200;
    const existing = new Set();

    for (let i = 0; i < hosts.length; i += HOST_CHUNK) {
        const part = hosts.slice(i, i + HOST_CHUNK);
        const [rows] = await db.query(
            'SELECT proxy_host, proxy_port, proxy_username, proxy_password FROM proxies WHERE proxy_host IN (?)',
            [part]
        );
        for (const r of rows) {
            // r comes back with DB column names; identityKey reads parsed-object
            // names. Without this mapping every existing row keyed as
            // "undefined\u0000undefined\u0000null\u0000null" and nothing ever matched, so a
            // re-import re-inserted the entire list.
            existing.add(identityKey({
                host: r.proxy_host,
                port: r.proxy_port,
                username: r.proxy_username,
                password: r.proxy_password,
            }));
        }
    }

    const toInsert = parsed.filter(p => !existing.has(identityKey(p)));
    results.duplicates += parsed.length - toInsert.length;

    // Multi-row INSERTs. Each statement is a single transaction, so a failing
    // chunk rolls back entirely instead of leaving a half-imported batch. One
    // bad row then falls back to row-by-row so it cannot sink 499 good ones.
    const ROW_CHUNK = 500;
    for (let i = 0; i < toInsert.length; i += ROW_CHUNK) {
        const part = toInsert.slice(i, i + ROW_CHUNK);
        const placeholders = part.map(() => '(?, ?, ?, ?, ?, ?)').join(', ');
        const values = [];
        for (const p of part) {
            values.push(
                p.host, p.port,
                p.username || null, p.password || null,
                p.type || type, 'Imported from bulk upload'
            );
        }

        try {
            await db.query(
                `INSERT INTO proxies (proxy_host, proxy_port, proxy_username, proxy_password, proxy_type, notes) VALUES ${placeholders}`,
                values
            );
            results.success += part.length;
        } catch (err) {
            pushErr(`bulk insert failed: ${err.message}`);
            await insertOneByOne(part, type, results, pushErr);
        }
    }

    return results;
}

// Attribute every row individually, so a single bad row cannot sink its chunk.
// success/failed are tallied here; the caller must not count the chunk again.
async function insertOneByOne(part, type, results, pushErr) {
    for (const p of part) {
        try {
            await addProxy({
                host: p.host,
                port: p.port,
                username: p.username,
                password: p.password,
                type: p.type || type,
                notes: 'Imported from bulk upload'
            });
            results.success++;
        } catch (e) {
            results.failed++;
            pushErr(e.message);
        }
    }
}

// The proxies table ships without any index on proxy_host, so the bulk dedup
// SELECT above would be a full table scan per chunk. Add one, once, and only if
// missing. MySQL 8 has no "ADD INDEX IF NOT EXISTS", so probe information_schema.
let _indexChecked = false;
async function ensureProxyHostIndex() {
    if (_indexChecked) return;
    _indexChecked = true;   // cache even on failure - one ALTER per process
    try {
        const [rows] = await db.query(
            `SELECT INDEX_NAME FROM information_schema.STATISTICS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'proxies'
               AND INDEX_NAME = 'idx_proxy_host'`,
            []
        );
        if (rows.length === 0) {
            await db.query('ALTER TABLE proxies ADD INDEX idx_proxy_host (proxy_host)');
        }
    } catch (err) {
        // Non-fatal: import still works, the SELECT is just slower.
    }
}



/**
 * Get a random active proxy
 */
async function getRandomProxy() {
    try {
        const [rows] = await db.query(
            `SELECT *
             FROM proxies
             WHERE status = 'active'
             AND (fail_count < max_failures OR max_failures = 0)
             ORDER BY RAND()
             LIMIT 1`
        );

        if (rows.length === 0) return null;

        return rows[0];
    } catch (err) {
        return null;
    }
}

/**
 * Get all proxies
 */
async function getAllProxies() {
    try {
        const [rows] = await db.query(
            'SELECT * FROM proxies ORDER BY created_at DESC'
        );

        return rows;
    } catch (err) {
        return [];
    }
}

/**
 * Mark proxy as successful
 */
async function markSuccess(proxyId) {
    try {
        await db.query(
            `UPDATE proxies
             SET success_count = success_count + 1,
                 last_used = NOW(),
                 fail_count = 0
             WHERE id = ?`,
            [proxyId]
        );
    } catch (err) {
    }
}

/**
 * Mark proxy as failed
 */
async function markFailure(proxyId) {
    try {
        const [rows] = await db.query(
            `UPDATE proxies
             SET fail_count = fail_count + 1,
                 last_used = NOW()
             WHERE id = ?`,
            [proxyId]
        );

        // Auto-disable if too many failures
        const [proxy] = await db.query(
            'SELECT fail_count, max_failures FROM proxies WHERE id = ?',
            [proxyId]
        );

        if (
            proxy.length > 0 &&
            proxy[0].fail_count >= proxy[0].max_failures
        ) {
            await db.query(
                "UPDATE proxies SET status = 'failed' WHERE id = ?",
                [proxyId]
            );
        }
    } catch (err) {
    }
}

/**
 * Test proxy connectivity
 */
async function testProxy(proxyId) {
    try {
        const [rows] = await db.query(
            'SELECT * FROM proxies WHERE id = ?',
            [proxyId]
        );

        if (rows.length === 0) {
            return {
                success: false,
                message: 'Proxy not found'
            };
        }

        const proxy = rows[0];

        // Validate proxy data
        if (!proxy.proxy_host || !proxy.proxy_port) {
            return {
                success: false,
                message: `Invalid proxy data: host=${proxy.proxy_host}, port=${proxy.proxy_port}`
            };
        }

        const axios = require('axios');

        // One stored type is not always the truth. parseProxyString cannot tell
        // whether `host:port` is SOCKS or HTTP, so it writes `http` by default -
        // correct for most entries, wrong for the common residential pools (port
        // 1080, luxproxy, most of them) that speak SOCKS5. Feeding that row to
        // axios's HTTP CONNECT path opens a TCP connection, sends
        // `CONNECT host:443 HTTP/1.1`, gets no HTTP reply from the SOCKS server,
        // and hangs until the timeout. The Test button then reported failure for
        // a perfectly good proxy, for the wrong reason, on every click.
        //
        // Probe the stored type first and fall back to the other one. The winner
        // is written back, so a single Test click heals the row for good, and
        // getAxiosProxyConfig (the device flow) then picks the corrected type up
        // without needing to be re-tested.
        const storedType = proxy.proxy_type || 'http';
        const candidates = [storedType];
        candidates.push(proxyagent.isSocksType(storedType) ? 'http' : 'socks5');

        const startTime = Date.now();
        let lastErr = null;

        for (let i = 0; i < candidates.length; i++) {
            const candidateType = candidates[i];
            const agentConfig = proxyagent.buildAxiosProxyConfig(Object.assign({}, proxy, {
                proxy_type: candidateType
            }));

            if (Object.keys(agentConfig).length === 0) {
                return {
                    success: false,
                    message: `Invalid proxy data: host=${proxy.proxy_host}, port=${proxy.proxy_port}`
                };
            }

            try {
                const response = await axios.get('https://api.ipify.org?format=json', Object.assign({}, agentConfig, {
                    timeout: 15000,
                    validateStatus: null
                }));

                const ip = response && response.data && response.data.ip;
                if (typeof ip !== 'string' || !ip) {
                    lastErr = new Error('Proxy tunnel opened but returned no external IP. Body: ' + String(response && response.data).slice(0, 120));
                    continue;
                }

                const elapsed = Date.now() - startTime;

                if (i > 0) {
                    try {
                        await db.query('UPDATE proxies SET proxy_type = ?, updated_at = NOW() WHERE id = ?', [candidateType, proxyId]);
                    } catch (e) {
                        // Non-fatal - the test itself succeeded.
                    }
                }

                return {
                    success: true,
                    message: `Connected successfully via ${candidateType}. External IP: ${ip}`,
                    externalIp: ip,
                    responseTime: elapsed,
                    usedType: candidateType,
                    typeCorrected: i > 0
                };
            } catch (err) {
                lastErr = err;
            }
        }

        return {
            success: false,
            message: proxyagent.describeProxyError(lastErr, proxy),
            responseTime: Date.now() - startTime,
            triedTypes: candidates
        };
    } catch (err) {
        return {
            success: false,
            message: err.message
        };
    }
}

/**
 * Delete proxy
 */
async function deleteProxy(proxyId) {
    try {
        await db.query(
            'DELETE FROM proxies WHERE id = ?',
            [proxyId]
        );

        return true;
    } catch (err) {
        return false;
    }
}

/**
 * Update proxy status
 */
async function updateProxyStatus(proxyId, status) {
    try {
        await db.query(
            'UPDATE proxies SET status = ?, updated_at = NOW() WHERE id = ?',
            [status, proxyId]
        );

        return true;
    } catch (err) {
        return false;
    }
}

/**
 * Get proxy statistics
 */
async function getStats() {
    try {
        const [stats] = await db.query(
            `SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN status = 'inactive' THEN 1 ELSE 0 END) AS inactive,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                SUM(success_count) AS total_success,
                SUM(fail_count) AS total_fail
             FROM proxies`
        );

        return (
            stats[0] || {
                total: 0,
                active: 0,
                inactive: 0,
                failed: 0,
                total_success: 0,
                total_fail: 0
            }
        );
    } catch (err) {

        return {
            total: 0,
            active: 0,
            inactive: 0,
            failed: 0,
            total_success: 0,
            total_fail: 0
        };
    }
}

async function claimProxy() {
    try {
        // Sort order, not a filter: proven proxies first, least-recently-used
        // among equals. A freshly imported pool is all success_count = 0, so it
        // still yields a proxy (the device flow can fall back to direct in
        // microsoftclient if that endpoint is dead) rather than refusing to use
        // any. Filtering on success_count > 0 would be a no-op here because the
        // ORDER BY already puts the high-success rows on top.
        const [rows] = await db.query(
            `SELECT *
             FROM proxies
             WHERE status = 'active'
             AND (max_failures = 0 OR fail_count < max_failures)
             ORDER BY success_count DESC, fail_count ASC, last_used ASC
             LIMIT 1`
        );

        if (rows.length === 0) return null;

        const proxy = rows[0];
        await db.query('UPDATE proxies SET last_used = NOW() WHERE id = ?', [proxy.id]);
        return proxy;
    } catch (err) {
        return null;
    }
}

async function releaseProxy(proxyId, success, note) {
    if (!proxyId) return;
    try {
        if (success) await markSuccess(proxyId);
        else await markFailure(proxyId);
    } catch (err) {
    }
}

/**
 * Get axios proxy config for a given proxy.
 *
 * Thin wrapper over the shared proxyagent module so every caller (test button,
 * device flow, bulk test) gets the same agent selection. The previous version
 * built a full proxy URL and then threw it away - it returned
 * `{ proxy: { host, port, auth } }` with no protocol, so a stored `socks5` type
 * was silently downgraded to an HTTP CONNECT tunnel.
 */
function getAxiosProxyConfig(proxy) {
    return proxyagent.buildAxiosProxyConfig(proxy);
}

/**
 * @param {number} concurrency - Max simultaneous tests
 * @returns {Promise<object>} { total, success, failed, details[] }
 */
async function testAllProxies(concurrency = 10) {
    let proxies;
    try {
        proxies = await getAllProxies();
    } catch (err) {
        return { total: 0, success: 0, failed: 0, details: [] };
    }

    const results = { total: proxies.length, success: 0, failed: 0, details: [] };

    const queue = proxies.slice();
    const poolSize = Math.max(1, Math.min(concurrency, queue.length || 1));

    const workers = [];
    for (let i = 0; i < poolSize; i++) {
        workers.push((async () => {
            while (queue.length) {
                const proxy = queue.shift();
                let result;
                try {
                    result = await testProxy(proxy.id);
                } catch (err) {
                    result = { success: false, message: err.message };
                }

                if (result.success) {
                    await markSuccess(proxy.id);
                    results.success++;
                } else {
                    await markFailure(proxy.id);
                    results.failed++;
                }

                results.details.push({
                    id: proxy.id,
                    host: proxy.proxy_host,
                    port: proxy.proxy_port,
                    success: !!result.success,
                    message: result.message || null,
                    externalIp: result.externalIp || null,
                    responseTime: result.responseTime || null,
                });
            }
        })());
    }

    await Promise.all(workers);

    return results;
}

/**
 * Test every proxy in the background, polled by the panel.
 *
 * Testing 10,000 proxies cannot happen inside one HTTP request: at a realistic
 * ~1-2s per test and bounded concurrency it runs for many minutes, and nginx's
 * proxy_read_timeout (60s) kills the request mid-run. The browser then shows
 * "load failed" - a network error, not a proxy error - and nothing completed.
 *
 * So the run is detached and polled. POST returns a jobId immediately, the
 * panel polls progress?jobId= every couple of seconds, and the job keeps
 * counting as it goes. Finished jobs are held 30 minutes so a slow poller
 * still finds them. Single-process only, which matches how the app runs.
 */
const _testJobs = new Map();

async function startTestAllJob({ concurrency = 25 } = {}) {
    const jobId = `t${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const job = {
        id: jobId,
        status: 'running',
        total: 0,
        done: 0,
        success: 0,
        failed: 0,
        startedAt: Date.now(),
        finishedAt: null,
        error: null,
    };
    _testJobs.set(jobId, job);
    runTestAllJob(job, Math.max(1, concurrency)).catch((err) => {
        job.status = 'error';
        job.error = err.message;
        job.finishedAt = Date.now();
    });
    return jobId;
}

function getTestAllJob(jobId) {
    const job = _testJobs.get(jobId);
    if (!job) return null;
    return {
        id: job.id,
        status: job.status,
        total: job.total,
        done: job.done,
        success: job.success,
        failed: job.failed,
        error: job.error,
        startedAt: job.startedAt,
        finishedAt: job.finishedAt,
        elapsedMs: (job.finishedAt || Date.now()) - job.startedAt,
    };
}

async function runTestAllJob(job, concurrency) {
    let proxies;
    try {
        proxies = await getAllProxies();
    } catch (err) {
        job.status = 'error';
        job.error = err.message;
        job.finishedAt = Date.now();
        return;
    }

    job.total = proxies.length;
    if (!proxies.length) {
        job.status = 'done';
        job.finishedAt = Date.now();
        return;
    }

    const queue = proxies.slice();
    const workers = [];
    for (let i = 0; i < Math.max(1, Math.min(concurrency, queue.length)); i++) {
        workers.push((async () => {
            while (queue.length) {
                const proxy = queue.shift();
                let result;
                try {
                    result = await testProxy(proxy.id);
                } catch (err) {
                    result = { success: false, message: err.message };
                }

                try {
                    if (result.success) { await markSuccess(proxy.id); job.success++; }
                    else { await markFailure(proxy.id); job.failed++; }
                } catch (err) {
                    // Counter upkeep must never kill the job.
                }

                job.done++;
            }
        })());
    }

    await Promise.all(workers);
    job.status = 'done';
    job.finishedAt = Date.now();

    const cleanup = setTimeout(() => { _testJobs.delete(job.id); }, 30 * 60 * 1000);
    if (typeof cleanup.unref === 'function') cleanup.unref();
}

/**
 * Re-infer proxy_type from the stored port for rows already in the table.
 *
 * Rows imported before the port inference landed are still all `http`, so a
 * 1080 SOCKS pool sits mislabelled and every device flow through it fails.
 * This flips the obvious cases over in place instead of forcing a re-import.
 * It only touches ports it is confident about - an unusual port is left alone
 * for a manual Test click to probe and correct.
 *
 * SOCKS_PORTS / HTTP_PORTS are module constants, not user input, so inlining
 * them into the IN clause is safe.
 *
 * @returns {Promise<object>} { toSocks5, toHttp, total }
 */
async function reclassifyTypesByPort() {
    const socksList = [...SOCKS_PORTS].join(',');
    const httpList = [...HTTP_PORTS].join(',');

    const [r1] = await db.query(
        `UPDATE proxies SET proxy_type='socks5', updated_at=NOW()
         WHERE LOWER(proxy_type) IN ('http','https') AND proxy_port IN (${socksList})`
    );
    const [r2] = await db.query(
        `UPDATE proxies SET proxy_type='http', updated_at=NOW()
         WHERE LOWER(proxy_type) LIKE 'socks%' AND proxy_port IN (${httpList})`
    );

    const toSocks5 = (r1 && r1.affectedRows) || 0;
    const toHttp = (r2 && r2.affectedRows) || 0;
    return { toSocks5, toHttp, total: toSocks5 + toHttp };
}

/**
 * Delete every stored proxy.
 * @returns {Promise<number>} Number of rows removed
 */
async function deleteAllProxies() {
    try {
        const [result] = await db.query('DELETE FROM proxies');
        const deleted = result.affectedRows || 0;
        return deleted;
    } catch (err) {
        throw err;
    }
}

module.exports = {
    parseProxyString,
    inferType,
    SOCKS_PORTS,
    HTTP_PORTS,
    addProxy,
    importProxies,
    getRandomProxy,
    claimProxy,
    releaseProxy,
    getAllProxies,
    markSuccess,
    markFailure,
    testProxy,
    testAllProxies,
    startTestAllJob,
    getTestAllJob,
    reclassifyTypesByPort,
    deleteProxy,
    deleteAllProxies,
    updateProxyStatus,
    getStats,
    getAxiosProxyConfig
};
