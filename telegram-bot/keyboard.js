// keyboard.js – Telegram inline keyboards (optional centralized config)
module.exports = {
    coinSelection: () => ({
        inline_keyboard: [
            [{ text: 'BTC', callback_data: 'buy_coin_BTC' }, { text: 'ETH', callback_data: 'buy_coin_ETH' }, { text: 'LTC', callback_data: 'buy_coin_LTC' }],
            [{ text: 'USDT', callback_data: 'buy_coin_USDT' }, { text: 'USDC', callback_data: 'buy_coin_USDC' }, { text: 'DOGE', callback_data: 'buy_coin_DOGE' }],
        ]
    }),
    renewCoinSelection: (key) => ({
        inline_keyboard: [
            [{ text: 'BTC', callback_data: `renew_${key}_BTC` }, { text: 'ETH', callback_data: `renew_${key}_ETH` }],
        ]
    }),
};