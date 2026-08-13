/**
 * Proxy Manager Service
 * Handles rotating residential proxies for device code flows
 */

const db = require('../database/connection');

/**
 * Parse proxy string in format: username:password@host:port
 * @param {string} proxyStr - Proxy string
 * @returns {Object} Parsed proxy object
 */
function parseProxyString(proxyStr) {
    proxyStr = proxyStr.trim();

    if (!proxyStr) return null;

    // Format: username:password@host:port
    // More permissive regex to handle various formats
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
    console.log('[ProxyManager] Failed to parse:', JSON.stringify(proxyStr));
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

    return { id: result.insertId, ...proxyData };
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

    console.log(`[ProxyManager] Importing ${lines.length} lines...`);

    for (const line of lines) {
        const proxyStr = line.trim();

        if (!proxyStr || proxyStr.startsWith('#')) continue;

        const parsed = parseProxyString(proxyStr);

        if (!parsed) {
            results.failed++;
            results.errors.push(`Invalid format: "${proxyStr}" - expected username:password@host:port`);
            continue;
        }

        console.log(`[ProxyManager] Parsed: ${parsed.host}:${parsed.port}`);

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

    console.log(`[ProxyManager] Import complete: ${results.success} success, ${results.failed} failed, ${results.duplicates} duplicates`);

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
        console.error('[ProxyManager] Error getting random proxy:', err.message);
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
        console.error('[ProxyManager] Error getting all proxies:', err.message);
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
        console.error('[ProxyManager] Error marking success:', err.message);
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
        console.error('[ProxyManager] Error marking failure:', err.message);
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
        const axios = require('axios');

        const proxyUrl = proxy.proxy_username
            ? `${proxy.proxy_type}://${proxy.proxy_username}:${proxy.proxy_password}@${proxy.proxy_host}:${proxy.proxy_port}`
            : `${proxy.proxy_type}://${proxy.proxy_host}:${proxy.proxy_port}`;

        const startTime = Date.now();

        try {
            const response = await axios.get(
                'https://api.ipify.org?format=json',
                {
                    proxy: proxyUrl,
                    timeout: 10000
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

            return {
                success: false,
                message: `Connection failed: ${err.message}`,
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
        console.error('[ProxyManager] Error deleting proxy:', err.message);
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
        console.error('[ProxyManager] Error updating status:', err.message);
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
        console.error('[ProxyManager] Error getting stats:', err.message);

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

module.exports = {
    parseProxyString,
    addProxy,
    importProxies,
    getRandomProxy,
    getAllProxies,
    markSuccess,
    markFailure,
    testProxy,
    deleteProxy,
    updateProxyStatus,
    getStats,
    getAxiosProxyConfig
};
