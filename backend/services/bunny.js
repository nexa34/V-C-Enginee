const axios = require('axios');

async function uploadToBunny(fileContent, fileName, apiKey, storageZone, storageRegion, pullZoneUrl) {
  const baseUrl = `https://${storageRegion}.storage.bunnycdn.com/${storageZone}/`;

  const response = await axios.put(`${baseUrl}${fileName}`, fileContent, {
    headers: {
      'AccessKey': apiKey,
      'Content-Type': 'text/html',
    },
  });

  if (response.status === 201 || response.status === 200) {
    const publicUrl = pullZoneUrl
      ? `https://${pullZoneUrl.replace(/^https?:\/\//, '')}/${fileName}`
      : `https://${storageZone}.b-cdn.net/${fileName}`;
    return { success: true, url: publicUrl };
  } else {
    throw new Error(`Bunny upload failed with status ${response.status}`);
  }
}

module.exports = { uploadToBunny };