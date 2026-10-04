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
 * True for addresses that identify a network hop rather than a visitor.
 * Listing these in scanner_blocklist would hard-block everyone behind the same
 * proxy or NAT once a single one of them is rate-limited.
 */
function isPrivateIp(addr) {
    const a = String(addr || '').replace(/^::ffff:/, '').trim();
    if (!a) return true;
    // Unspecified / loopback / link-local / IPv4-mapped.
    if (a === '::' || a === '::1' || a.indexOf('fe80:') === 0 || a.indexOf('fc') === 0 || a.indexOf('fd') === 0) {
        return true;
    }
    const m = a.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return false;
    const o = m.slice(1, 5).map(Number);
    if (o.some(function (n) { return n > 255; })) return true;
    if (o[0] === 0 || o[0] === 10 || o[0] === 127 || o[0] === 169) return true;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;
    if (o[0] === 192 && o[1] === 168) return true;
    return false;
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

    // Never list RFC1918/reserved addresses. Behind a shared proxy or tunnel
    // the first forwarded hop is a private address shared by many unrelated
    // visitors, so listing it would block real users as soon as one of them is
    // rate-limited - which is exactly how a single visitor's address ended up in
    // scanner_blocklist and then got baked into the next worker as a hard
    // block.
    if (isPrivateIp(clean)) {
        console.warn('[ScannerBlocklist] Skipping private/reserved address: ' + clean);
        return false;
    }

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
