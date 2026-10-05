const axios = require('axios');
const config = require('../backend/config/env');
const QRCode = require('qrcode');
const { Buffer } = require('buffer');

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
 * Returns array of currency strings (e.g., ["btc", "usdt", "usdt_trc20", ...]).
 * Includes ALL currencies including network variants with underscores.
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
    

    
    // NowPayments API returns a flat array of strings: ["btc", "usdt", "usdt_trc20", ...]
    // Or a wrapped object: { data: ["btc", "usdt", ...] } or { currencies: [...] }
    if (Array.isArray(data)) {
      // Direct array response - normalize to lowercase strings
      currencyCache = data
        .map(c => (typeof c === 'string' ? c.toLowerCase() : String(c).toLowerCase()))
        .filter(Boolean);
      cacheTimestamp = now;

      return currencyCache;
    }
    
    if (data && typeof data === 'object') {
      // Handle wrapped responses
      if (Array.isArray(data.data)) {
        data = data.data;
      } else if (Array.isArray(data.currencies)) {
        data = data.currencies;
      } else {
        // Try first array value in object
        const values = Object.values(data);
        for (const v of values) {
          if (Array.isArray(v)) { data = v; break; }
        }
        // If still not an array after searching, default to empty
        if (!Array.isArray(data)) {

          data = [];
        }
      }
    }
    
    // Ensure we always return an array of strings
    currencyCache = Array.isArray(data) 
      ? data.map(c => (typeof c === 'string' ? c.toLowerCase() : String(c).toLowerCase())).filter(Boolean)
      : [];
    cacheTimestamp = now;

    return currencyCache;
  } catch (err) {

    if (err.response) {


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
 * Create a NowPayments payment (using /payment endpoint).
 * Returns object with: payment_id, pay_address, pay_amount, pay_currency
 * @param {number} priceUsd - Price in USD
 * @param {string} coin - Currency ticker (e.g., "USDTBSC", "BTC")
 * @param {string} orderId - Unique order ID
 * @param {string} description - Order description
 * @returns {object} Payment data from NowPayments
 */
async function createPayment(priceUsd, coin, orderId, description) {
  // Normalize currency format - try multiple variations
  let normalizedCoin = coin;
  
  // Map common short formats to proper currency codes
  const coinMap = {
    'usdtbsc': 'USDTBSC',
    'usdterc20': 'USDTERC20',
    'usdttrc20': 'USDTRC20',
    'usdtarb': 'USDTARB',
    'usdtapol': 'USDTAPOL',
    'btcbtc': 'BTC',
    'etheth': 'ETH',
    'trxbtc': 'TRX',
    'xrp': 'XRP',
    'dogebtc': 'DOGE',
    'sol': 'SOL',
    'bnb': 'BNB',
  };
  const coinLower = coin.toLowerCase();
  if (coinMap[coinLower]) {
    normalizedCoin = coinMap[coinLower];
  } else if (!coinLower.includes('_')) {
    // If no underscore, use uppercase (NowPayments /payment endpoint expects uppercase)
    normalizedCoin = coinUpper = coin.toUpperCase();
  }

  // Build list of currency variations to try
  // Priority: alpha-numeric only (no underscores), uppercase first
  const currenciesToTry = [];
  
  if (normalizedCoin.includes('_')) {
    const parts = normalizedCoin.split('_');
    const token = parts[0];
    const network = parts.slice(1).join('');
    
    // Priority 1: Uppercase without underscore
    currenciesToTry.push(token.toUpperCase() + network.toUpperCase());
    // Priority 2: Uppercase with underscore
    currenciesToTry.push(normalizedCoin.toUpperCase());
    // Priority 3: Lowercase without underscore
    currenciesToTry.push(token + network);
    // Priority 4: Lowercase with underscore
    currenciesToTry.push(normalizedCoin);
    } else {
    currenciesToTry.push(normalizedCoin.toUpperCase()); 
    currenciesToTry.push(normalizedCoin.toLowerCase());
  }
  
  // Deduplicate while preserving order
  const uniqueCurrencies = [...new Set(currenciesToTry)];
  



  let lastError = null;
  let skippedUnavailable = [];
  let triedFormats = [];
  
  for (const tryCoin of uniqueCurrencies) {
    triedFormats.push(tryCoin);
    try {
      const response = await axios.post(
        `${NOW_PAYMENTS_BASE}/payment`,
        {
          price_amount: priceUsd,
          price_currency: 'usd',
          pay_currency: tryCoin,
          order_id: orderId,
          order_description: description,
          is_fixed_rate: false,
          is_fee_paid_by_user: false,
        },
        npHeaders()
      );


      return response.data;
    } catch (err) {
      lastError = err;
      const errMsg = (err.response?.data?.message || err.message || '').toLowerCase();
      const statusCode = err.response?.status;
      

      
      // Track which currencies were skipped due to "unavailable"
      if (errMsg.includes('unavailable')) {
        skippedUnavailable.push(tryCoin);
      }
      
      // Try next currency format
      continue;
    }
  }
  
  // All formats failed - provide detailed error




  // All attempts failed, throw the last error
  throw lastError;
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

/**
 * Generate a QR code PNG image for a crypto payment address.
 * Matches the Python invoice.py _make_qr() function exactly.
 * 
 * Bitcoin URI format: {coin.lower()}:{address}?amount={amount}
 * @param {string} address - The crypto wallet address
 * @param {string} coin - The currency ticker (e.g., "USDT", "BTC")
 * @param {number} amount - The payment amount
 * @returns {Promise<Buffer|null>} PNG image buffer or null if failed
 */
async function generateQRCode(address, coin, amount) {
  try {
    if (!address) {

      return null;
    }

    // Build Bitcoin URI format matching Python: f"{coin.lower()}:{address}?amount={amount}"
    const coinLower = coin.toLowerCase();
    const uri = `${coinLower}:${address}?amount=${amount}`;
    

    
    // Generate QR code as PNG buffer
    // Options: errorCorrectionLevel='M', scale=8 (matches Python box_size=8, border=4)
    const pngBuffer = await QRCode.toBuffer(uri, {
      width: 300,
      margin: 2,  // border=4 in Python ≈ margin=2 in node-qrcode
      errorCorrectionLevel: 'M',
      color: {
        dark: '#000000',
        light: '#FFFFFF',
      },
    });
    

    return Buffer.from(pngBuffer);
  } catch (err) {

    return null;
  }
}

module.exports = {
  createPayment,
  checkInvoice,
  getCurrencies: getAllCurrencies,
  searchCurrency,
  searchProviderCurrencies,
  getInvoiceDetails,
  getAvailableCoins,
  clearCurrencyCache,
  generateQRCode,
};
