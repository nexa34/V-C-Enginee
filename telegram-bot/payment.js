const axios = require('axios');
const config = require('../backend/config/env');
const db = require('../backend/database/connection');

async function createInvoice(priceUsd, coin, orderId, description) {
  const response = await axios.post(
    'https://api.nowpayments.io/v1/invoice',
    {
      price_amount: priceUsd,
      price_currency: 'usd',
      pay_currency: coin,
      order_id: orderId,
      order_description: description,
      ipn_callback_url: `${process.env.APP_URL || 'http://localhost:3000'}/api/payments/ipn`,
    },
    { headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY } }
  );
  return response.data;
}

async function checkInvoice(invoiceId) {
  const response = await axios.get(`https://api.nowpayments.io/v1/invoice/${invoiceId}`, {
    headers: { 'x-api-key': config.NOWPAYMENTS_API_KEY },
  });
  return response.data;
}

module.exports = { createInvoice, checkInvoice };