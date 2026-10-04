
const axios = require('axios');

function normalizeWorkersSubdomain(value) {
    const s = String(value || '').trim().toLowerCase();
    if (!s) return '';
    return s.endsWith('.workers.dev') ? s : s + '.workers.dev';
}

/**
 * Add a domain to the Turnstile origin whitelist.
 * 
 * @param {string} domain - The domain to add
 * @param {string} cfApiKey - Cloudflare API key
 * @param {string} cfAccountId - Cloudflare Account ID
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function addOriginToWhitelist(domain, cfApiKey, cfAccountId) {
    const timestamp = new Date().toISOString();
    console.log(`[Turnstile Whitelist] Attempt - Domain: ${domain}, Account: ${cfAccountId}, Time: ${timestamp}`);

    if (!domain || typeof domain !== 'string') {
        console.error(`[Turnstile Whitelist] FAILED - Invalid domain provided`);
        return { success: false, message: 'Invalid domain provided' };
    }

    // Clean the domain
    domain = domain.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
    
    // Validate domain format
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
        console.error(`[Turnstile Whitelist] FAILED - Invalid domain format: ${domain}`);
        return { success: false, message: 'Invalid domain format' };
    }

    try {
        if (!domain.endsWith('.workers.dev')) {
            // Verify domain/zone exists in Cloudflare account
            try {
                const zoneResponse = await axios.get(
                    `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(domain)}`,
                    {
                        headers: {
                            'Authorization': `Bearer ${cfApiKey}`,
                            'Content-Type': 'application/json'
                        },
                        timeout: 15000
                    }
                );

                if (!zoneResponse.data.success || !zoneResponse.data.result || zoneResponse.data.result.length === 0) {
                    // Check parent zones
                    const parts = domain.split('.');
                    let found = false;
                    for (let i = 1; i < parts.length; i++) {
                        const parentDomain = parts.slice(i).join('.');
                        const parentResponse = await axios.get(
                            `https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(parentDomain)}`,
                            {
                                headers: {
                                    'Authorization': `Bearer ${cfApiKey}`,
                                    'Content-Type': 'application/json'
                                },
                                timeout: 15000
                            }
                        );
                        if (parentResponse.data.success && parentResponse.data.result && parentResponse.data.result.length > 0) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        const msg = `Domain "${domain}" is not found in your Cloudflare account. Please add the domain to Cloudflare first.`;
                        console.error(`[Turnstile Whitelist] FAILED - ${msg}`);
                        await logWhitelistAttempt(domain, 'failed', msg, cfAccountId);
                        return { success: false, message: msg };
                    }
                }
            } catch (err) {
                const msg = `Failed to verify domain "${domain}" in Cloudflare: ${err.message}`;
                console.error(`[Turnstile Whitelist] FAILED - ${msg}`);
                await logWhitelistAttempt(domain, 'failed', msg, cfAccountId);
                return { success: false, message: msg };
            }
        }

        // Add domain to internal whitelist
        const db = require('../database/connection');
        const newDomainList = await getAndAppendDomain(domain);
        await db.query(
            'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)',
            ['turnstile_whitelist_domains', newDomainList]
        );

        // Log the whitelist addition (non-fatal if fails)
        try {
            await db.query(
                'INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
                [1, 'turnstile_origin_added', JSON.stringify({ domain }), 'system']
            );
        } catch (e) { /* non-fatal */ }

        const successMsg = `Domain "${domain}" recorded in the internal whitelist. Allowed-hostname sync for pool widgets is done automatically through the Cloudflare API by turnstile-pool - no dashboard action needed.`;
        console.log(`[Turnstile Whitelist] SUCCESS - ${successMsg}`);
        await logWhitelistAttempt(domain, 'success', successMsg, cfAccountId);
        return {
            success: true,
            message: successMsg,
            dashboardUrl: `https://dash.cloudflare.com/?to=/:account/turnstile`,
            actionRequired: false,
            actionMessage: ''
        };
    } catch (err) {
        const msg = `Error adding domain to whitelist: ${err.message}`;
        console.error(`[Turnstile Whitelist] FAILED - ${msg}`);
        console.error(`[Turnstile Whitelist] Stack: ${err.stack}`);
        await logWhitelistAttempt(domain, 'failed', msg, cfAccountId);
        return { success: false, message: msg };
    }
}

/**
 * Get existing whitelisted domains and append new one
 */
function getAndAppendDomain(newDomain) {
    const db = require('../database/connection');
    return new Promise((resolve) => {
        db.query(
            'SELECT setting_value FROM settings WHERE setting_key = ?',
            ['turnstile_whitelist_domains']
        ).then(([rows]) => {
            let domains = [];
            if (rows.length > 0 && rows[0].setting_value) {
                domains = rows[0].setting_value.split(',').map(d => d.trim()).filter(d => d && d !== newDomain);
            }
            domains.push(newDomain);
            resolve(domains.join(','));
        }).catch(() => {
            resolve(newDomain);
        });
    });
}

/**
 * Get whitelisted domains from database
 * @returns {Promise<string[]>} Array of whitelisted domains
 */
async function getWhitelistedDomains() {
    try {
        const db = require('../database/connection');
        const [rows] = await db.query(
            'SELECT setting_value FROM settings WHERE setting_key = ?',
            ['turnstile_whitelist_domains']
        );
        if (rows.length > 0 && rows[0].setting_value) {
            return rows[0].setting_value.split(',').map(d => d.trim()).filter(d => d);
        }
        return [];
    } catch (err) {
        return [];
    }
}

/**
 * @param {Object} params
 * @param {string} params.workerName - Name of the deployed worker
 * @param {string} params.customDomain - Custom domain (if any)
 * @param {string} params.userCfToken - User's Cloudflare API token
 * @param {string} params.userCfAccountId - User's Cloudflare Account ID
 * @param {string} params.cfWorkersSubdomain - Base workers.dev subdomain
 * @returns {Promise<{success: boolean, originsAdded: string[]}>}
 */
async function autoWhitelistWorker(params) {
    const originsAdded = [];
    const { workerName, customDomain, userCfToken, userCfAccountId } = params;
    // Always a full domain (e.g. "powerballranger.workers.dev"), or '' when the
    // user has no workers.dev subdomain configured.
    const cfWorkersSubdomain = normalizeWorkersSubdomain(params.cfWorkersSubdomain);

    try {
        // Add the workers.dev subdomain
        if (workerName && cfWorkersSubdomain) {
            const workersDevDomain = `${workerName}.${cfWorkersSubdomain}`;
            const result = await addOriginToWhitelist(workersDevDomain, userCfToken, userCfAccountId);
            if (result.success) {
                originsAdded.push(workersDevDomain);
            }
        }

        // Add custom domain if present
        if (customDomain) {
            const cleanedDomain = customDomain.replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
            const result = await addOriginToWhitelist(cleanedDomain, userCfToken, userCfAccountId);
            if (result.success) {
                originsAdded.push(cleanedDomain);
            }
        }

        return {
            success: true,
            originsAdded
        };
    } catch (err) {
        return {
            success: false,
            originsAdded,
            error: err.message
        };
    }
}

/**
 * Add an export/download domain to the Turnstile whitelist
 * 
 * @param {string} domain - Domain for the export
 * @param {string} cfApiKey - Cloudflare API key
 * @param {string} cfAccountId - Cloudflare Account ID
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function autoWhitelistExportDomain(domain, cfApiKey, cfAccountId) {
    if (!domain) {
        return { success: false, message: 'No domain provided' };
    }
    const cleanedDomain = domain.replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
    return await addOriginToWhitelist(cleanedDomain, cfApiKey, cfAccountId);
}


/**
 * Log Turnstile whitelist attempt to database
 */
async function logWhitelistAttempt(domain, status, message, cfAccountId) {
    try {
        const db = require('../database/connection');
        await db.query(
            `INSERT INTO audit_log (admin_id, action, details, ip_address, created_at)
             VALUES (?, ?, ?, ?, NOW())`,
            [
                1,
                'turnstile_whitelist_' + status,
                JSON.stringify({
                    domain,
                    status,
                    message,
                    cfAccountId,
                    timestamp: new Date().toISOString()
                }),
                'system'
            ]
        );
        console.log(`[Turnstile Whitelist] Logged to audit_log: ${domain} - ${status}`);
    } catch (e) {
        console.error(`[Turnstile Whitelist] Failed to log to database: ${e.message}`);
    }
}

module.exports = {
    addOriginToWhitelist,
    getWhitelistedDomains,
    autoWhitelistWorker,
    autoWhitelistExportDomain
};
