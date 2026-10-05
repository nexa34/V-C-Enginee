const db = require('../database/connection');

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
            type: 'http'
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
            type: 'http'
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
 * Import multiple proxies from a list
 */
async function importProxies(proxyList, type = 'http') {
    const results = {
        success: 0,
        failed: 0,
        duplicates: 0,
        errors: []
    };

    if (!proxyList || typeof proxyList !== 'string') {
        results.errors.push('Invalid input: proxyList must be a string');
        return results;
    }

    // Split by newlines (handle both \n and \r\n)
    const lines = proxyList.split(/\r?\n/);


    for (const line of lines) {
        const proxyStr = line.trim();

        if (!proxyStr || proxyStr.startsWith('#')) continue;

        const parsed = parseProxyString(proxyStr);

        if (!parsed) {
            results.failed++;
            results.errors.push(`Invalid format: "${proxyStr}" - expected username:password@host:port`);
            continue;
        }


        // Validate parsed data
        if (!parsed.host || !parsed.port) {
            results.failed++;
            results.errors.push(`Invalid parsed data for: "${proxyStr}"`);
            continue;
        }

        // Check for duplicates
        const [existing] = await db.query(
            'SELECT id FROM proxies WHERE proxy_host = ? AND proxy_port = ?',
            [parsed.host, parsed.port]
        );

        if (existing.length > 0) {
            results.duplicates++;
            continue;
        }

        try {
            await addProxy({
                host: parsed.host,
                port: parsed.port,
                username: parsed.username,
                password: parsed.password,
                type: parsed.type || type,
                notes: 'Imported from bulk upload'
            });

            results.success++;
        } catch (err) {
            results.failed++;
            results.errors.push(`${err.message} (${proxyStr})`);
        }
    }


    return results;
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

        const proxyType = proxy.proxy_type || 'http';


        const startTime = Date.now();

        try {
            // Try using proxy object format instead of URL string for better error handling
            const proxyConfig = {
                host: proxy.proxy_host,
                port: proxy.proxy_port,
                protocol: proxyType
            };

            if (proxy.proxy_username && proxy.proxy_password) {
                proxyConfig.auth = {
                    username: proxy.proxy_username,
                    password: proxy.proxy_password
                };
            }

            const response = await axios.get(
                'https://api.ipify.org?format=json',
                {
                    proxy: proxyConfig,
                    timeout: 15000,
                    validateStatus: null
                }
            );

            const elapsed = Date.now() - startTime;
            const ip = response.data.ip;

            return {
                success: true,
                message: `Connected successfully. External IP: ${ip}`,
                externalIp: ip,
                responseTime: elapsed
            };
        } catch (err) {
            const elapsed = Date.now() - startTime;

            // Parse the actual error
            let errorMsg = err.message;
            if (err.code === 'EAI_AGAIN') {
                errorMsg = `DNS resolution failed for ${proxy.proxy_host}:${proxy.proxy_port}. Check your VPS DNS settings.`;
            } else if (err.code === 'ECONNREFUSED') {
                errorMsg = `Connection refused by ${proxy.proxy_host}:${proxy.proxy_port}. The proxy may be down.`;
            } else if (err.code === 'ETIMEDOUT') {
                errorMsg = `Connection timed out to ${proxy.proxy_host}:${proxy.proxy_port}.`;
            } else if (err.response && err.response.status === 503) {
                errorMsg = `Proxy returned 503 Service Unavailable. The proxy credentials may be invalid, expired, or the account has no balance. Contact your proxy provider.`;
            } else if (err.response && err.response.status === 407) {
                errorMsg = `Proxy authentication failed (407). Check username and password.`;
            } else if (err.response && err.response.status === 403) {
                errorMsg = `Proxy access denied (403). Your IP may be blocked by the proxy provider.`;
            }


            return {
                success: false,
                message: errorMsg,
                responseTime: elapsed
            };
        }
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
 * Get axios proxy config for a given proxy
 */
function getAxiosProxyConfig(proxy) {
    if (!proxy) return null;

    const proxyUrl = proxy.proxy_username
        ? `${proxy.proxy_type || 'http'}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`
        : `${proxy.proxy_type || 'http'}://${proxy.proxy_host}:${proxy.proxy_port}`;

    return {
        proxy: {
            host: proxy.proxy_host,
            port: proxy.proxy_port,
            auth: proxy.proxy_username
                ? {
                      username: proxy.proxy_username,
                      password: proxy.proxy_password
                  }
                : undefined
        }
    };
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
    deleteProxy,
    deleteAllProxies,
    updateProxyStatus,
    getStats,
    getAxiosProxyConfig
};
