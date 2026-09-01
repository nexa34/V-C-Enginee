const db = require('../database/connection');

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
  'httpclient', 'java/', 'apache-http', 'go-http',
  // SEO scrapers
  'ahrefsbot', 'semrush', 'majestic', 'moz', 'screaming frog',
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

// Known datacenter/VPN/Tor IP ranges (major providers)
const DATACENTER_ASN_RANGES = [
  // Cloud providers often used for scanning
  '104.16.0.0', '172.64.0.0', // Cloudflare
  '52.0.0.0', '54.0.0.0', // AWS
  '13.0.0.0', // AWS
  '20.0.0.0', // Azure
  '40.0.0.0', // Azure
  '35.0.0.0', // GCP
  '8.8.8.0', '8.8.4.0', // Google DNS (often proxied)
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
    if (uaLower.includes(pattern.toLowerCase())) {
      return true;
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

function isLikelyDatacenter(ip) {
  if (!ip) return false;
  for (const prefix of DATACENTER_ASN_RANGES) {
    if (ip.startsWith(prefix)) return true;
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
  const whitelist = whitelistStr.split(',').map(i => i.trim()).filter(i => i);
  return whitelist.includes(ip);
}

/**
 * Main OPSEC middleware
 */
async function opsecCheck(req, res, next) {
  try {
    // Get client IP
    const ip = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'] || '';
    const cleanIp = ip.replace(/^::ffff:/, ''); // Strip IPv6 prefix

    // Load OPSEC settings from cache or DB
    const settings = await getOpsecSettings();

    // Always allow admin panel and API
    if (req.path.startsWith('/admin-panel') || req.path.startsWith('/api/admin') || req.path.startsWith('/user-panel')) {
      // But still check IP whitelist for admin panel if enabled
      if (req.path.startsWith('/admin-panel') && settings.admin_ip_whitelist_enabled === 'true') {
        const whitelisted = await isIpWhitelisted(cleanIp, settings.admin_whitelist_ips);
        if (!whitelisted) {
          logBlocked(cleanIp, req.headers['user-agent'], 'Admin IP not whitelisted');
          return res.status(403).json({ error: 'Access denied' });
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
      return res.status(405).json({ error: 'Method not allowed' });
    }

    // 4. Check scan path patterns
    if (settings.block_scanners === 'true' && isScanPath(req.path)) {
      logBlocked(cleanIp, req.headers['user-agent'], `Scan path detected: ${req.path}`);
      return res.status(403).json({ error: 'Access denied' });
    }

    // 5. Check attack payloads in query
    if (settings.block_scanners === 'true' && hasAttackPayload(req)) {
      logBlocked(cleanIp, req.headers['user-agent'], 'Attack payload in query');
      return res.status(403).json({ error: 'Access denied' });
    }

    // 6. Check attack payloads in POST body
    if (settings.block_scanners === 'true' && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
      if (req.body && typeof req.body === 'object') {
        const bodyStr = JSON.stringify(req.body);
        if (containsAttackPayload(bodyStr)) {
          logBlocked(cleanIp, req.headers['user-agent'], 'Attack payload in body');
          return res.status(403).json({ error: 'Access denied' });
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
    console.error('[OPSEC] Error:', err.message);
    next(); // Fail open - don't block legitimate traffic on error
  }
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
    console.error('[OPSEC] Failed to load settings:', err.message);
    return { ...FALLBACK_SETTINGS };
  }
}

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

  // Also log to console in dev
  if (config.NODE_ENV === 'development') {
    console.log(`[OPSEC BLOCKED] ${ip} - ${reason} - UA: ${ua}`);
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
  isBlockedUserAgent,
  isTorExitNode,
  isScanPath,
  containsAttackPayload,
  getBlockLog,
  logBlocked
};
