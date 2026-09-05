/**
 * Scanner IP Blocklist Service
 *
 * Blocks edge traffic by source address, injected into every worker at build
 * time.
 *
 * WHY THIS EXISTS
 * A Cloudflare Worker cannot see TLS fingerprints (JA3/JA4) or HTTP/2
 * fingerprints, so it cannot tell VirusTotal's genuine Chrome apart from a real
 * human visitor. Header and user-agent checks also miss VT, because VT uses a
 * normal Chrome user agent. Blocking by address is the complement: a scanner
 * that returns with a normal user agent is still stopped.
 *
 * HOW THE LIST GROWS
 *   - 'manual'    - added by hand from scanner intel
 *   - 'edge_signal' - reported by the worker when it blocks a request on
 *                     user-agent or rate-limit grounds
 *
 * HONEST LIMIT
 * The automatic path only catches scanners that FIRST hit the edge with a bot
 * user agent. VirusTotal's URL scanner does not, so its IPs must be added
 * manually. Lists also go stale as scanner infrastructure turns over.
 *
 * SIZE
 * The list is inlined into every deployed worker, so it is capped. A few
 * thousand addresses is well within Cloudflare's script size limit, but it must
 * not be allowed to grow without bound.
 */

const db = require('../database/connection');

const MAX_LIST_SIZE = 1000;

let _tablesReady = false;

async function ensureTables() {
    if (_tablesReady) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS scanner_blocklist (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL,
            source VARCHAR(32) NOT NULL DEFAULT 'manual',
            user_agent VARCHAR(512) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_scanner_blocklist_ip (ip),
            KEY idx_scanner_blocklist_source (source)
        ) ENGINE=InnoDB
    `);
    _tablesReady = true;
}

/**
 * Add an address to the blocklist. Idempotent: a repeat add is a no-op.
 *
 * @param {string} ip
 * @param {string} source  'manual' | 'edge_signal'
 * @param {string} ua      originating user agent, for triage
 * @returns {Promise<boolean>} true if the row was written, false otherwise
 */
async function addBlockedIp(ip, source, ua) {
    await ensureTables();

    // CF-Connecting-IP is a single address, but X-Forwarded-For is a comma
    // separated chain. Keep only the first hop.
    const clean = String(ip || '').trim().split(',')[0].trim();
    if (!clean) return false;

    try {
        const [result] = await db.query(
            'INSERT IGNORE INTO scanner_blocklist (ip, source, user_agent) VALUES (?, ?, ?)',
            [
                clean,
                String(source || 'manual').slice(0, 32),
                String(ua || '').slice(0, 512) || null,
            ]
        );
        // affectedRows is 0 when the UNIQUE key already matched, i.e. the
        // address was already listed.
        return result && result.affectedRows > 0;
    } catch (e) {
        console.warn('[ScannerBlocklist] addBlockedIp(' + clean + ') failed: ' + e.message);
        return false;
    }
}

/**
 * Return the address list to inline into a worker. Newest first, capped.
 */
async function listBlockedIps() {
    await ensureTables();

    try {
        const [rows] = await db.query(
            'SELECT ip FROM scanner_blocklist ORDER BY id DESC LIMIT ?',
            [MAX_LIST_SIZE]
        );
        const ips = (rows || []).map(function (r) { return String(r.ip); });

        if (rows && rows.length === MAX_LIST_SIZE) {
            console.warn('[ScannerBlocklist] List at cap (' + MAX_LIST_SIZE +
                '); oldest entries are being excluded from workers');
        }

        return ips;
    } catch (e) {
        console.warn('[ScannerBlocklist] listBlockedIps failed: ' + e.message);
        return [];
    }
}

module.exports = {
    ensureTables,
    addBlockedIp,
    listBlockedIps,
    MAX_LIST_SIZE,
};
