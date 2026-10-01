const axios = require('axios');

async function deployWorker(scriptContent, workerName, userCfToken, userAccountId, options = {}) {
  if (!userCfToken || !userAccountId) {
    throw new Error('Cloudflare credentials not configured. Add your API Token and Account ID in Settings.');
  }

  const name = String(workerName || '').trim();
  if (!/^[a-z0-9-]{3,50}$/.test(name)) {
    throw new Error('Worker name must be lowercase letters, numbers, and hyphens only (3-50 chars).');
  }

  const url = `https://api.cloudflare.com/client/v4/accounts/${userAccountId}/workers/scripts/${name}`;

  try {
    // Cloudflare Workers API requires multipart/form-data for script upload
    // since the service-worker binding era. Using plain application/javascript
    // returns 400 "invalid script".
    //
    // `main_module` is REQUIRED by the Workers Script Upload API and declares
    // the script as an ES Module. worker/devicecode-worker.js therefore ends
    // with `export default { fetch(request, env, ctx) {...} }`. A Service
    // Worker style `addEventListener('fetch', ...)` would register no handler
    // and Cloudflare would reject the upload with "No event handlers were
    // registered. This script does nothing.".
    //
    // The module part's Content-Type MUST be `application/javascript+module`
    // (see https://developers.cloudflare.com/workers/platform/infrastructure-as-code/).
    // With the plain `application/javascript` type Cloudflare parses the part
    // as a classic script, ignores `main_module`, and the upload fails with:
    //   "Uncaught SyntaxError: Unexpected token 'export'"
    const FormData = require('form-data');
    const form = new FormData();
    form.append('worker.js', scriptContent, { filename: 'worker.js', contentType: 'application/javascript+module' });
    form.append('metadata', JSON.stringify({ main_module: 'worker.js' }), { filename: 'metadata.json', contentType: 'application/json' });

    const response = await axios.put(url, form, {
      headers: {
        'Authorization': `Bearer ${userCfToken}`,
        ...form.getHeaders(),
      },
      timeout: 120000,
    });

    if (!response.data.success) {
      const detail = response.data.errors?.[0]?.message || JSON.stringify(response.data.errors);
      throw new Error(`Cloudflare API error: ${detail}`);
    }

    await enableWorkerSubdomain(name, userCfToken, userAccountId);

    if (options.customDomain) {
      await createWorkerRoute(
        userCfToken,
        userAccountId,
        options.customDomain,
        options.domainConnection,
        options.routeName,
        name
      );
    }

    return { success: true, workerName: name };
  } catch (err) {
    if (err.response?.status === 403) {
      throw new Error('Cloudflare rejected the request. Check that the API token has Workers edit permission and the Account ID is correct.');
    }
    if (err.response?.status === 400) {
      throw new Error(err.response?.data?.errors?.[0]?.message || 'Cloudflare rejected the worker name or script payload.');
    }
    throw err;
  }
}

async function getZoneIdByName(token, zoneName) {
  const response = await axios.get(`https://api.cloudflare.com/client/v4/zones?name=${encodeURIComponent(zoneName)}&status=active&per_page=50`, {
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  if (!response.data.success) {
    throw new Error(response.data.errors?.[0]?.message || 'Failed to fetch Cloudflare zone: ' + JSON.stringify(response.data));
  }
  const zone = response.data.result.find(z => z.name.toLowerCase() === zoneName.toLowerCase());
  if (!zone) {
    throw new Error(`Cloudflare zone not found for ${zoneName}. Make sure the domain is in your Cloudflare account.`);
  }
  return zone.id;
}

async function createWorkerRoute(token, accountId, domain, connectionType, routeName, workerName) {
  if (!domain || !workerName) return;

  const zoneName = String(domain).trim().replace(/^https?:\/\//i, '').replace(/\/$/, '');
  const zoneId = await getZoneIdByName(token, zoneName);

  const pattern = buildRoutePattern(zoneName, connectionType, routeName);

  const listResponse = await axios.get(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`,
    { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
  );
  if (!listResponse.data.success) {
    throw new Error(listResponse.data.errors?.[0]?.message || 'Failed to list existing worker routes');
  }

  const existingRoute = listResponse.data.result.find(r => r.pattern === pattern);
  if (existingRoute) {
    if (existingRoute.script !== workerName) {
      await axios.put(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes/${existingRoute.id}`,
        { pattern, script: workerName },
        { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
      );
    }
    return;
  }

  const createResponse = await axios.post(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`,
    { pattern, script: workerName },
    { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
  );

  if (!createResponse.data.success) {
    throw new Error(createResponse.data.errors?.[0]?.message || 'Failed to create worker route: ' + JSON.stringify(createResponse.data));
  }
}

// Pure helper: build the worker route pattern for a given zone and options
function buildRoutePattern(zoneName, connectionType, routeName) {
  const z = String(zoneName || '').trim().replace(/^https?:\/\//i, '').replace(/\/$/, '');
  if (!z) throw new Error('zoneName required');
  if (connectionType === 'root') return `${z}/*`;
  const prefix = routeName ? `${String(routeName).replace(/[^a-z0-9-]/gi, '').toLowerCase()}.` : `*.`;
  return `${prefix}${z}/*`;
}

async function enableWorkerSubdomain(workerName, token, accountId) {
  try {
    await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/subdomain`,
      { enabled: true },
      { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' } }
    );
  } catch (err) {
    // Non-fatal: a Worker deployed only on a custom-domain route does not need
    // workers.dev, and the upload itself already succeeded. But when the
    // workers.dev hostname IS the link's public URL, a silent failure here is
    // the difference between a working link and a dead one - so say so loudly.
    console.warn(
      '[Cloudflare] workers.dev subdomain enable failed for "' + workerName + '": ' + err.message +
      ' - the script is uploaded, but it will not answer on <name>.<subdomain>.workers.dev until this succeeds.'
    );
  }
}

// Admin-only: verify connectivity using env credentials
async function adminVerifyCredentials() {
  const config = require('../config/env');
  try {
    const res = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
      headers: { 'Authorization': `Bearer ${config.CF_API_TOKEN}` },
    });
    return { ok: res.data.success, message: res.data.success ? 'Token valid' : JSON.stringify(res.data.errors) };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}

async function getWorkerByName(workerName, token, accountId) {
  if (!workerName || !token || !accountId) throw new Error('Credentials required');
  return axios.get(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${encodeURIComponent(workerName)}`,
    { headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }, timeout: 20000 }
  );
}

async function deleteWorker(workerName, token, accountId) {
  if (!token || !accountId) throw new Error('Credentials required');
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`;
  await axios.delete(url, { headers: { 'Authorization': `Bearer ${token}` } });
}

async function listDomains(token) {
  const response = await axios.get('https://api.cloudflare.com/client/v4/zones?per_page=50', {
    headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
  if (!response.data.success) throw new Error('Failed to fetch domains');
  return response.data.result.map(z => ({ id: z.id, name: z.name, status: z.status }));
}

module.exports = { deployWorker, deleteWorker, getWorkerByName, listDomains, adminVerifyCredentials };
