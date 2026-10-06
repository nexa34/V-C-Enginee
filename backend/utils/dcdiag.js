/**
 * Device-flow diagnostics logger.
 *
 * Every console.* call in the device-code / capture flow goes through this
 * one file. That keeps the no-console invariant honest (a single allowed
 * entry) while making the whole flow traceable on the server:
 *
 *   journalctl -u vgenius --no-pager | grep '\[DevCode\]'
 *
 * Toggle with the DC_DIAG env var:
 *   DC_DIAG=1  (default) - full trace, every step of every flow
 *   DC_DIAG=0            - silent; /api/log also drops [DevCode][DIAG] records
 *
 * `log()` is for progress. `fail()` is for anything that could make a capture
 * go missing - an INSERT that throws, a poll error, a notification that fails.
 * Failures are prefixed [DevCode][ERROR] so they can be grepped alone.
 */
const ON = String(process.env.DC_DIAG || '1') === '1';

function log(message) {
  if (!ON) return;
  console.log('[DevCode] ' + message);
}

function fail(message) {
  if (!ON) return;
  console.error('[DevCode][ERROR] ' + message);
}

module.exports = {
  log: log,
  fail: fail,
  isOn: function () { return ON; },
};
