const path = require('path');
const db = require('../database/connection');

const config = require('../config/env');

// Reuse existing opsec helpers where possible.
const { getOpsecSettings } = require('./opsec');

const BLOCKED_USER_AGENTS = [
  'nikto','nmap','sqlmap','dirbuster','gobuster','wpscan','w3af',
  'acunetix','nessus','qualys','openvas','burpsuite','burp',
  'arachni','skipfish','wapiti','whatweb','cmsmap',
  'vulnerability scanner','vuln','exploit','metasploit',
  'hydra','medusa','patator','crowbar',
  'crawler','spider','crawl','scrapy','wget','curl','python-requests',
  'httpclient','java/','apache-http',
  'ahrefsbot','semrush','majestic','screaming frog',
  'dotbot','rogerbot','petalbot','dataforseobot',
  'httrack','teleport','webcopier','webreaper',
  'getright','flashget','wget','curl','lwp-trivial',
  'selenium','puppeteer','playwright','phantomjs','headlesschrome',
  'slimerjs','zombie','casperjs','nightmare',
  'bot','slurp','yahoo','baiduspider','yandexbot','duckduckbot','facebot','ia_archiver',
  'archive.org','wayback','turnitin','grammarly',
  'havij','sqlninja','commix','fimap','xsser',
  'masscan','zmap','nmap scripting engine',
  'gptbot','chatgpt-user','claudebot','anthropic-ai',
  'google-extended','cohere-ai','perplexity','youbot',
  'bytespider','magpie-crawler','meta-externalagent',
  'hydra','medusa','ncrack','patator','thc-scan',
  'dnsrecon','dig','host','fierce','recon-ng',
  'theharvester','maltego','shodan','censys'
];

function isBotUserAgent(ua) {
  if (!ua || ua.length < 5) return true;
  const lower = ua.toLowerCase();
  return BLOCKED_USER_AGENTS.some(pattern => lower.includes(pattern));
}

function isScanPath(urlPath) {
  if (!urlPath) return false;
  return [
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
    /\/debug/i, /\/trace/i, /\/dump/i
  ].some(re => re.test(urlPath));
}

function getHarmlessPage(status) {
  const contentType = status === 404 ? '404 Not Found' : 'OK';
  const body = status === 404
    ? '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title></head><body></body></html>'
    : '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title></title></head><body></body></html>';
  return { contentType, body };
}

async function classifyRequest(req) {
  const ua = req.headers['user-agent'] || '';
  const ip =
    req.ip ||
    req.connection?.remoteAddress ||
    (req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : '') ||
    '';

  if (isBotUserAgent(ua)) {
    return { action: 'block', type: 'bot_ua', reason: 'Bot user agent' };
  }

  if (isScanPath(req.originalUrl || req.url)) {
    return { action: 'block', type: 'scan_path', reason: 'Scanner path pattern' };
  }

  try {
    const settings = await getOpsecSettings();
    const cfIpType = (req.headers['cf-ip-type'] || '').toLowerCase();
    if (settings.block_datacenter === 'true' && (cfIpType === 'datacenter' || cfIpType === 'hosting')) {
      return { action: 'block', type: 'datacenter', reason: 'Cloudflare datacenter IP' };
    }
    if (settings.block_vpn === 'true' && (cfIpType === 'vpn' || cfIpType === 'proxy')) {
      return { action: 'block', type: 'vpn', reason: 'Cloudflare VPN/proxy IP' };
    }
    if (settings.block_tor === 'true' && cfIpType === 'tor') {
      return { action: 'block', type: 'tor', reason: 'Tor exit node' };
    }
  } catch (e) {

  }

  return { action: 'allow', type: 'residential', reason: 'No bot indicators' };
}

async function rejectBotRequest(req, res, next) {
  try {
    const classification = await classifyRequest(req);
    if (classification.action !== 'allow') {
      const { contentType, body } = getHarmlessPage(classification.reason === 'Scanner path pattern' ? 404 : 200);
      res.set({
        'Content-Type': 'text/html; charset=utf-8',
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store',
      });
      return res.status(contentType.includes('404') ? 404 : 200).send(body);
    }
    next();
  } catch (e) {

    next();
  }
}

module.exports = { rejectBotRequest, classifyRequest, getHarmlessPage };
