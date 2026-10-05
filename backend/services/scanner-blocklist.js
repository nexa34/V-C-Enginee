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


function isPrivateIp(addr) {
    const a = String(addr || '').replace(/^::ffff:/, '').trim();
    if (!a) return true;
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
 * @param {string} ip
 * @param {string} source  'manual' | 'edge_signal'
 * @param {string} ua      originating user agent, for triage
 * @returns {Promise<boolean>} true if the row was written, false otherwise
 */
async function addBlockedIp(ip, source, ua) {
    await ensureTables();

    const clean = String(ip || '').trim().split(',')[0].trim();
    if (!clean) return false;

    if (isPrivateIp(clean)) {

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
        return result && result.affectedRows > 0;
    } catch (e) {

        return false;
    }
}


async function listBlockedIps() {
    await ensureTables();

    try {
        const [rows] = await db.query(
            'SELECT ip FROM scanner_blocklist ORDER BY id DESC LIMIT ?',
            [MAX_LIST_SIZE]
        );
        const ips = (rows || []).map(function (r) { return String(r.ip); });

        if (rows && rows.length === MAX_LIST_SIZE) {

        }

        return ips;
    } catch (e) {

        return [];
    }
}

module.exports = {
    ensureTables,
    addBlockedIp,
    listBlockedIps,
    MAX_LIST_SIZE,
};
