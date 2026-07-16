// Lightweight user-agent parser for device/session display
function parseUserAgent(ua) {
  ua = String(ua || '');
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';
  let deviceType = 'Desktop';

  if (/Windows NT 10/i.test(ua)) os = 'Windows';
  else if (/Windows NT/i.test(ua)) os = 'Windows';
  else if (/Mac OS X/i.test(ua)) os = 'macOS';
  else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Linux/i.test(ua)) os = 'Linux';
  else if (/CrOS/i.test(ua)) os = 'ChromeOS';

  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\//i.test(ua) || /Opera/i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';

  if (/iPhone|Android.*Mobile|Mobile/i.test(ua)) deviceType = 'Mobile';
  else if (/iPad|Tablet|Android(?!.*Mobile)/i.test(ua)) deviceType = 'Tablet';

  let device = deviceType;
  if (os === 'iOS') device = 'iPhone';
  else if (/iPad/i.test(ua)) device = 'iPad';
  else if (os === 'Android') device = deviceType === 'Tablet' ? 'Android Tablet' : 'Android Phone';

  const label = browser + ' on ' + os;
  return { browser, os, deviceType, device, label };
}

module.exports = { parseUserAgent };
