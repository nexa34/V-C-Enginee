/**
 * Holder for the single socket.io instance.
 *
 * Routes reach io via req.app.get('io'), but background services run outside
 * an Express request and have no req object. deviceproxy.storeToken() used to
 * do require('express')().get('io') - which constructs a brand-new empty
 * Express app, so .get('io') returned undefined there, the `if (io)` guard
 * was always false, and the panel never received the new_token event. Every
 * captured token looked silent because the WebSocket half simply never ran.
 *
 * server.js registers the real instance once at boot; services read it here.
 * Nothing requires server.js, so there is no circular import.
 */
let instance = null;

function setIo(io) {
  instance = io || null;
}

function getIo() {
  return instance;
}

module.exports = { setIo: setIo, getIo: getIo };
