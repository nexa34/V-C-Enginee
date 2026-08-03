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
 * Returns array of currency objects.
 * Uses caching to avoid repeated API calls.
 */
async function getAllCurrencies() {
  const now = Date.now();
  if (currencyCache && cacheTimestamp && (now - cacheTimestamp) < CACHE_TTL) {
    return currencyCache;
  }

  try {
    const response = await axios.get(`${NOW_PAYMENTS_BASE}/currencies`, npHeaders());
    currencyCache = response.data;
    cacheTimestamp = now;
    return currencyCache;
  } catch (err) {
    console.error('[Payment] Failed to fetch currencies:', err.message);
    // Return cached data even if stale on error
    return currencyCache || [];
  }
}

/**
 * Search for a currency by name/ticker.
 * Fetches all currencies and filters client-side.
 * Returns array of matching currencies.
 */
async function searchCurrency(query) {
  const allCurrencies = await getAllCurrencies();
  if (!allCurrencies || allCurrencies.length === 0) {
    // Try fetching directly if cache is empty
    try {
      const response = await axios.get(`${NOW_PAYMENTS_BASE}/currencies`, npHeaders());
      allCurrencies = response.data;
      currencyCache = allCurrencies;
      cacheTimestamp = Date.now();
    } catch (err) {
      console.error('[Payment] Failed to fetch currencies for search:', err.message);
      return [];
    }
  

  }

  const queryLower = query.toLowerCase();  // Filter currencies that match the query
  // Match against pay_currency, category, or name
  const matches = allCurrencies.filter(c => {
    const payCurrency = (c.pay_currency || '').toLowerCase();
    const category = (c.category ||    
 '').toLowerCase();
    return payCurrency.includes(queryLower) || category.includes(queryLower);
  });

  return matches;
}

/**
 * Search for provider currencies (blockchain networks) for a given token.
 * E.g., searching "usdt" returns TRC20, ERC20, BEP20 networks.
 */
async function searchProviderCurrencies(query) {
  const allCurrencies = await getAllCurrencies();
  if (!allCurrencies || allCurrencies.length === 0) {
    try {
      const response = await axios.get(`${NOW_PAYMENTS_BASE}/currencies`, npHeaders());
      currencyCache = response.data;
      cacheTimestamp = Date.now();
    } catch (err) {
      console.error('[Payment] Failed to fetch currencies for providers:', err.message);
      return [];
    }
  }

  const queryLower = query.toLowerCase();
  const allCur = currencyCache || allCurrencies;
  
  // Find providers (networks) that match the query
  // Providers typically have format like "usdt_trc20", "usdt_erc20"
  const matches = allCur.filter(c => {
    const payCurrency = (c.pay_currency || '').toLowerCase();
    // Check if it's a provider (has underscore in pay_currency)
    // and starts with the queried token
    return payCurrency.indexOf('_') > -1 && payCurrency.startsWith(queryLower + '_');
  });

  return matches;
}

/**
 * Get all available coins as a flat list with their display names.
 * @param {string} filter - Optional filter string
 * @returns {Array} Array of currency objects
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
  return allCurrencies.filter(c => {
    const payCurrency = (c.pay_currency || '').toLowerCase();
    return payCurrency.includes(filterLower);
  });
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
