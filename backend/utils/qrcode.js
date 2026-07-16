const QRCode = require('qrcode');

async function generateQRCodeDataURL(text) {
  try {
    return await QRCode.toDataURL(text);
  } catch (err) {
    return '';
  }
}

module.exports = { generateQRCodeDataURL };