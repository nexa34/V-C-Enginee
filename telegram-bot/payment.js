const axios = require('axios');
const config = require('../backend/config/env');
const db = require('../backend/database/connection');

const NOW_PAYMENTS_BASE = 'https://api.nowpayments.io/v1';

function npHeaders() {
  return { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY } };
}

/**
 * Fetch all supported currencies from NowPayments.
 * Returns array of currency objects.
 */
async function getCurrencies(options = {}) {
  const params = new URLSearchParams();
  if (options.like) params.set('like', options.like.toLowerCase());
  if (options.only_provider) params.set('only_provider', 'true');
  if (options.fiat_currency) params.set('fiat_currency', options.fiat_currency);
  if (options.fiat_currency_amount) params.set('fiat_currency_amount', options.fiat_currency_amount);
  const qs = params.toString();
  const url = qs ? `${NOW_PAYMENTS_BASE}/currencies?${qs}` : `${NOW_PAYMENTS_BASE}/currencies`;
  const response = await axios.get(url, npHeaders());
  return response.data;
}

/**
 * Search for a currency by name/ticker.
 * Returns array of matching currencies.
 */
async function searchCurrency(query) {
  return getCurrencies({ like: query });
}

/**
 * Search for provider currencies (blockchain networks) for a given token.
 * E.g., searching "usdt" returns TRC20, ERC20, BEP20 networks.
 */
async function searchProviderCurrencies(query) {
  return getCurrencies({ like: query.toLowerCase(), only_provider: true });
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

module.exports = {
  createInvoice,
  checkInvoice,
  getCurrencies,
  searchCurrency,
  searchProviderCurrencies,
  getInvoiceDetails,
};
