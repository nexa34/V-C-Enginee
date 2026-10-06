/**
 * No-console invariant.
 *
 * The whole codebase ships with NO console output except four approved
 * server-boot lines:
 *
 *   [Telegram Bot] Started          -> telegram-bot/bot.js
 *   [VGenius C Engine] Running on port 3000   -> server.js
 *   [VGenius C Engine] Environment: production -> server.js
 *   [DB] Connected to MySQL          -> backend/database/connection.js
 *
 * (backend/services/kerberos.js contains one console.log that is a STRING
 *  literal embedded in the PRT bookmarklet a user pastes into their own
 *  browser - it is data, not a log call.)
 *
 * Everything else - visitor pages (templates/assets + every template),
 * the Cloudflare worker, the owner panels, and every backend route/service -
 * must emit ZERO console output. This test walks the repo and enforces it,
 * so a stray console.* can never silently come back.
 *
 * Static source check only - no DB, no network.
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; process.stdout.write('  PASS  ' + name + '\n'); }
  else { fail++; process.stdout.write('  FAIL  ' + name + (extra ? ' -> ' + extra : '') + '\n'); }
}

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'tests' && dir.endsWith('backend')) continue; // test files print to console by design
      // build/ is manual developer tooling that never runs in production. It must
      // keep its console output - build/deploy-enhanced.js prints the obfuscation
      // key the operator has to save, so stripping it would destroy that feature.
      if (e.name === 'build') continue;
      walk(p, out);
    } else if (/\.(js|html)$/.test(e.name) && !(e.name === 'no-console.test.js')) {
      out.push(p);
    }
  }
  return out;
}

// Files allowed to contain console, and the exact substrings permitted in each.
const ALLOWED = {
  'server.js': ['[VGenius C Engine] Running on port', '[VGenius C Engine] Environment:'],
  'telegram-bot/bot.js': ['[Telegram Bot] Started'],
  'backend/database/connection.js': ['[DB] Connected to MySQL'],
  // The ONE place the device-code / capture flow is traced on the server.
  // Everything else in that flow calls dcdiag.log()/dcdiag.fail() instead of
  // console.*, which is what makes the invariant above mean something.
  // DC_DIAG=0 in .env turns the whole trace off without any code change.
  'backend/utils/dcdiag.js': ["console.log('[DevCode] '", "console.error('[DevCode][ERROR] '" ],
  // The two entries below are NOT log calls - they are string content of a
  // feature the operator pastes into their OWN browser. Removing them would
  // break the bookmarklet, so they are kept on purpose.
  'backend/services/kerberos.js': ['[Vgenius] PRT cookie set'],
  'user-panel/tokens.html': [
    '[VGenius] Set: ',
    '[VGenius] Failed: ',
    '[VGenius] Injected ',
  ],
};
const CONSOLE_RE = /console\s*\.\s*(log|warn|error|info|debug|trace)\s*\(|console\s*\[/;

const files = walk(ROOT, []);
const violations = [];
for (const abs of files) {
  const rel = path.relative(ROOT, abs).split(path.sep).join('/');
  const lines = fs.readFileSync(abs, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (!CONSOLE_RE.test(line)) return;
    if (rel in ALLOWED && ALLOWED[rel].some((s) => line.includes(s))) return; // an approved line
    violations.push(rel + ':' + (i + 1) + '  ' + line.trim().slice(0, 80));
  });
}

console.log('\n== No-console invariant ==');
check('walked ' + files.length + ' shipped js/html files', files.length > 20);
check('zero unexpected console.* across the whole codebase', violations.length === 0,
  violations.slice(0, 8).join('\n      '));
// every approved line is actually present (guards against accidental deletion)
for (const rel of Object.keys(ALLOWED)) {
  const abs = path.join(ROOT, rel);
  const src = fs.readFileSync(abs, 'utf8');
  check(rel + ' still carries its approved line',
    ALLOWED[rel].some((s) => src.includes(s)), 'none of: ' + ALLOWED[rel].join(' / '));
}

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====\n');
process.exit(fail ? 1 : 0);
