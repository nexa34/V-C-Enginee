/**
 * DC_DIAG diagnostics switch: the device-code diagnostics added for the
 * link-147 investigation must be removable in one place. This test verifies
 * the wiring so the switch cannot silently rot:
 *
 *   1. server.js reads the DC_DIAG env flag and defines dcDiag().
 *   2. /api/verify routes its [DevCode] logs through dcDiag.
 *   3. /api/log drops [DevCode][DIAG] records outright when DC_DIAG is off,
 *      and gates its printing on DC_DIAG (records are still stored).
 *   4. backend/routes/device.js routes its [DevCode][DIAG] traces through its
 *      own dcDiag helper.
 *   5. The worker's diag() channel is present and tagged [DevCode][DIAG].
 *   6. vg-engine hijacks console.* so none of it reaches the visitor's
 *      browser console.
 *
 * Static wiring checks only - no DB, no network.
 */
const fs = require('fs');
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? ' -> ' + extra : '')); }
}

const server = read('server.js');
const device = read('backend/routes/device.js');
const worker = read('worker/devicecode-worker.js');
const vgEngine = read('templates/assets/vg-engine.js');

console.log('\n== DC_DIAG diagnostics switch ==');
check('server.js reads the DC_DIAG env flag',
  server.includes("DC_DIAG = String(process.env.DC_DIAG || '1') === '1'"));
check('server.js defines the dcDiag() helper',
  server.includes('function dcDiag(msg)'));
check('server.js /api/verify routes [DevCode] logs through dcDiag',
  server.includes("dcDiag('[DevCode] /api/verify hit"));
check('server.js /api/log drops [DevCode][DIAG] records when DC_DIAG is off',
  server.includes('[DevCode][DIAG]') && server.includes('if (!DC_DIAG'));
check('server.js gates /api/log batch printing on DC_DIAG',
  server.includes("DC_DIAG && (log.level === 'error'"));
check('server.js gates /api/log single printing on DC_DIAG',
  server.includes('if (DC_DIAG) console.error'));
check('device.js defines its own dcDiag helper',
  device.includes('const dcDiag = function (m)'));
check('device.js /api/device/start traces route through dcDiag',
  device.includes("dcDiag('[DevCode][DIAG] /api/device/start ENTER"));
check('worker diag() channel is tagged [DevCode][DIAG]',
  worker.includes('function diag(step, detail, waitUntil)') && worker.includes('[DevCode][DIAG] step='));
check('vg-engine hijacks console.* (nothing reaches the browser console)',
  vgEngine.includes('console.log = function') && vgEngine.includes('console.error = function'));

console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====\n');
process.exit(fail ? 1 : 0);
