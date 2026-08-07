/**
 * Cloudflare Turnstile Origin Whitelist Service
 * 
 * Cloudflare Turnstile site keys are restricted to specific origins/domains.
 * When deploying workers or exporting HTML to new domains, those domains
 * must be added to the Turnstile site's origin whitelist.
 * 
 * This service:
 * 1. Tracks whitelisted domains in the database 
 * 2. Verifies domains exist in Cloudflare account
 * 3. Provides dashboard links for manual origin addition
 * 
 * For .workers.dev subdomains: Turnstile typically auto-accepts these
 * when they share the same base workers.dev domain configured in the site key.
 * 
 * For custom domains: These MUST be explicitly added to the Turnstile origin list
 * in the Cloudflare dashboard.
 */

const axios = require('axios');

/**
 * Add a domain to the Turnstile origin whitelist.
 * 
 * @param {string} domain - The domain to add
 * @param {string} cfApiKey - Cloudflare API key
 * @param {string} cfAccountId - Cloudflare Account ID
 * @returns {Promise<{success: boolean, message: string}>}
 */
async function addOriginToWhitelist(domain, cfApiKey, cfAccountId) {
    if (!domain || typeof domain !== 'string') {
        return { success: false, message: 'Invalid domain provided' };
    }

    // Clean the domain
    domain = domain.trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
    
    // Validate domain format
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(domain)) {
        return { success: false, message: 'Invalid domain format' };
    }

    try {
        // For workers.dev subdomains, skip zone verification
        // They share the base workers.dev origin with Turnstile
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
                        return {
                            success: false,
                            message: `Domain "${domain}" is not found in your Cloudflare account. Please add the domain to Cloudflare first.`
                        };
                    }
                }
            } catch (err) {
                return {
                    success: false,
                    message: `Failed to verify domain "${domain}" in Cloudflare: ${err.message}`
                };
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

        return {
            success: true,
            message: `Domain "${domain}" registered for Turnstile whitelist.`,
            dashboardUrl: `https://one.dash.cloudflare.com/?to=/${cfAccountId || ''}/turnstile`
        };
    } catch (err) {
        return {
            success: false,
            message: `Error adding domain to whitelist: ${err.message}`
        };
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
 * Automatically add deployed worker domains to Turnstile whitelist
 * Called after worker deployment succeeds
 * 
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
    const { workerName, customDomain, userCfToken, userCfAccountId, cfWorkersSubdomain } = params;

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

module.exports = {
    addOriginToWhitelist,
    getWhitelistedDomains,
    autoWhitelistWorker,
    autoWhitelistExportDomain
};