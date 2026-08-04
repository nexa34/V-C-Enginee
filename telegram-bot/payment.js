const axios = require('axios');
const config = require('../backend/config/env');

const NOW_PAYMENTS_BASE = 'https://api.nowpayments.io/v1';

function npHeaders() {
  return { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY } };
}

// Cache for currencies - fetch once and reuse
let currencyCache = null;
let cacheTimestamp = null;
const CACHE_TTL = 5 * 60 * 60 * 1000; // 5 hours

/**
 * Fetch all supported currencies from NowPayments.
 * Returns array of currency strings (e.g., ["btc", "eth", "trx", ...]).
 * Filters out underscore-format currencies (e.g., "usdt_trc20") since the invoice API
 * only accepts alphanumeric pay_currency values (underscores cause rejection).
 * Uses caching to avoid repeated API calls.
 */
async function getAllCurrencies() {
  const now = Date.now();
  if (currencyCache && cacheTimestamp && (now - cacheTimestamp) < CACHE_TTL) {
    // Ensure cached data is always an array
    return Array.isArray(currencyCache) ? currencyCache : [];
  }

  try {
    const response = await axios.get(`${NOW_PAYMENTS_BASE}/currencies`, npHeaders());
    let data = response.data;
    
    console.log('[Payment] API response type:', typeof data, 'isArray:', Array.isArray(data));
    
    // NowPayments API returns a flat array of strings: ["btc", "usdt", "usdt_trc20", ...]
    if (Array.isArray(data)) {
      // Direct array response - normalize to lowercase strings
      // Filter out underscore-format currencies (e.g., "usdt_trc20") since invoice API
      // only accepts alphanumeric pay_currency values
      currencyCache = data
        .map(c => (typeof c === 'string' ? c.toLowerCase() : c))
        .filter(c => c && !c.includes('_'))  // Remove underscore currencies
        .filter(Boolean);
      cacheTimestamp = now;
      console.log('[Payment] Fetched', currencyCache.length, 'currencies (filtered underscores)');
      return currencyCache;
    }
    
    if (data && typeof data === 'object') {
      // Handle wrapped responses
      if (Array.isArray(data.data)) {
        data = data.data;
      } else if (Array.isArray(data.currencies)) {
        data = data.currencies;
      } else {
        // Try first array value
        const values = Object.values(data);
        for (const v of values) {
          if (Array.isArray(v)) { data = v; break; }
        }
      }
    }
    
    // Ensure we always return an array of strings
    // Filter out underscore-format currencies
    currencyCache = Array.isArray         (data) 
      ? data
 .map(c => (typeof c === 'string' ? c.toLowerCase() : c))
          .filter(c => c && !c.includes('_'))
          .filter(Boolean)
      : [];
    cacheTimestamp = now;
    console.log('[Payment] Fetched', currencyCache.length, 'currencies from wrapped response (filtered underscores)');
    return currencyCache;
  } catch (err) {
    console.error('[Payment] Failed to fetch currencies:', err.message);
    if (err.response) {
      console.error('[Payment] API response status:', err.response.status);
      console.error('[Payment] API response data:', JSON.stringify(err.response.data).slice(0, 500));
    }
    // Return cached data even if stale on error
    return Array.isArray(currencyCache) ? currencyCache : [];

  }
}

/**
 * Search for a currency by name/ticker.
 * Fetches all currencies and filters client-side.
 * Returns array of matching currency strings.
 */
async function searchCurrency(query) {
  const allCurrencies = await getAllCurrencies();
  if (!allCurrencies || allCurrencies.length === 0) {
    return [];
  }

  const queryLower = query.toLowerCase().trim();
  
  // NowPayments returns flat array of lowercase strings: ["btc", "usdt", "usdt_trc20", ...]
  // Match exact ticker or anything containing the query
  const matches = allCurrencies.filter(c => {
    const coin = (c || '').toLowerCase();
    // Exact match first (e.g., "btc" matches "btc" exactly, not "usdt_btc")
    if (coin === queryLower) return true;
    // Partial match (e.g., "usdt" matches "usdt", "usdt_trc20", "usdt_erc20", etc.)
    if (coin.includes(queryLower)) return true;
    return false;
  });

  return matches;
}

/**
 * Search for provider currencies (blockchain networks) for a given token.
 * E.g., searching "usdt" returns "usdt_trc20", "usdt_erc20", "usdt_bep20"
 * Returns array of objects with { pay_currency } for compatibility with bot.js
 */
async function searchProviderCurrencies(query) {
  const allCurrencies = await getAllCurrencies();
  if (!allCurrencies || allCurrencies.length === 0) {
    return [];
  }

  const queryLower = query.toLowerCase().trim();
  
  // Find providers (networks) that match the query
  // Providers typically have format like "usdt_trc20", "usdt_erc20"
  // Only match entries that have an underscore (indicating they are network variants)
  const matches = allCurrencies.filter(c => {
    const coin = (c || '').toLowerCase();
    return coin.indexOf('_') > -1 && coin.startsWith(queryLower + '_');
  });

  // Return as array of objects with pay_currency for bot.js compatibility
  return matches.map(c => ({ pay_currency: c }));
}

/**
 * Get all available coins as a flat list with their display names.
 * @param {string} filter - Optional filter string
 * @returns {Array} Array of currency strings
 */
async function getAvailableCoins(filter) {
  const allCurrencies = await getAllCurrencies();
  if (!allCurrencies || allCurrencies.length === 0) {
    return [];
  }

  if (!filter) {
    return allCurrencies;
  }

  const filterLower = filter.toLowerCase();
  return allCurrencies.filter(c => (c || '').toLowerCase().includes(filterLower));
}

/**
 * Create a NowPayments invoice.
 * @param {number} priceUsd - Price in USD
 * @param {string} coin - Currency ticker (e.g., "usdt", "btc", "usdt_trc20")
 * @param {string} orderId - Unique order ID
 * @param {string} description - Order description
 * @returns {object} Invoice data from NowPayments
 */
async function createInvoice(priceUsd, coin, orderId, description) {
  const ipnCallback = config.APP_URL
    ? `${config.APP_URL.replace(/\/$/, '')}/api/payments/ipn`
    : 'https://your-domain.com/api/payments/ipn';

  const response = await axios.post(
    `${NOW_PAYMENTS_BASE}/invoice`,
    {
      price_amount: priceUsd,
      price_currency: 'usd',
      pay_currency: coin,
      order_id: orderId,
      order_description: description,
      ipn_callback_url: ipnCallback,
    },
    npHeaders()
  );
  return response.data;
}

/**
 * Check the status of an invoice.
 * @param {string} invoiceId - NowPayments invoice ID
 * @returns {object} Invoice status data
 */
async function checkInvoice(invoiceId) {
  const response = await axios.get(
    `${NOW_PAYMENTS_BASE}/invoice/${invoiceId}`,
    npHeaders()
  );
  return response.data;
}

/**
 * Get the full invoice details including payment info.
 * @param {string} invoiceId - NowPayments invoice ID
 * @returns {object} Full invoice details
 */
async function getInvoiceDetails(invoiceId) {
  const response = await axios.get(
    `${NOW_PAYMENTS_BASE}/invoice/${invoiceId}`,
    npHeaders()
  );
  return response.data;
}

/**
 * Clear the currency cache (for admin refresh).
 */
function clearCurrencyCache() {
  currencyCache = null;
  cacheTimestamp = null;
}

module.exports = {
  createInvoice,
  checkInvoice,
  getCurrencies: getAllCurrencies,
  searchCurrency,
  searchProviderCurrencies,
  getInvoiceDetails,
  getAvailableCoins,
  clearCurrencyCache,
};
