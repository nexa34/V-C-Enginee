const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const templateLoader = require('../services/templateloader');

// Get all active templates for user marketplace
router.get('/', userAuth, async (req, res) => {
  try {
    const { category, search } = req.query;
    let query = 'SELECT * FROM templates WHERE status = ?';
    const params = ['active'];

    if (category && category !== 'all') {
      query += ' AND category = ?';
      params.push(category);
    }
    if (search) {
      query += ' AND name LIKE ?';
      params.push(`%${search}%`);
    }

    query += ' ORDER BY name ASC';
    const [templates] = await db.query(query, params);
    const templateRows = templates.map(template => {
      const resolvedDir = templateLoader.resolveTemplateDirectory(template.name || template.template_key || template.zip_path);
      return {
        ...template,
        template_key: path.basename(resolvedDir),
      };
    });

    // Merge on-disk templates that aren't yet in the database so the
    // marketplace displays every available template (build scripts create
    // template folders on disk but don't always insert DB rows).
    const onDiskDirs = templateLoader.listDiskTemplates();
    const knownKeys = new Set(templateRows.map(t => String(t.template_key).toLowerCase()));
    for (const dir of onDiskDirs) {
      if (knownKeys.has(String(dir).toLowerCase())) continue;
      try {
        const cfgPath = path.join(__dirname, '..', '..', 'templates', dir, 'config.json');
        let cfg = {};
        if (fs.existsSync(cfgPath)) cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
        const tmplCategory = cfg.preload === false ? 'no_preload' : 'preload';
        if (category && category !== 'all' && tmplCategory !== category) continue;
        if (search && !String(cfg.name || dir).toLowerCase().includes(String(search).toLowerCase())) continue;
        templateRows.push({
          id: null,
          name: cfg.name || dir,
          category: tmplCategory,
          version: cfg.version || '1.0.0',
          status: 'active',
          config_json: JSON.stringify(cfg),
          thumbnail_url: null,
          zip_path: dir,
          template_key: dir,
        });
        knownKeys.add(String(dir).toLowerCase());
      } catch (e) { /* skip invalid config */ }
    }

    // Sort merged list alphabetically
    templateRows.sort((a, b) => String(a.name).localeCompare(String(b.name)));

    // Get counts (DB + disk)
    const [preloadCount] = await db.query("SELECT COUNT(*) as count FROM templates WHERE status = 'active' AND category = 'preload'");
    const [noPreloadCount] = await db.query("SELECT COUNT(*) as count FROM templates WHERE status = 'active' AND category = 'no_preload'");
    const diskPreload = onDiskDirs.filter(d => {
      try {
        const cfg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'templates', d, 'config.json'), 'utf8'));
        return cfg.preload !== false;
      } catch (e) { return true; }
    }).length;
    const diskNoPreload = onDiskDirs.length - diskPreload;

    res.json({
      templates: templateRows,
      counts: {
        all: preloadCount[0].count + noPreloadCount[0].count + (onDiskDirs.length - templateRows.filter(t => t.id).length),
        preload: preloadCount[0].count + diskPreload,
        no_preload: noPreloadCount[0].count + diskNoPreload,
      },
    });
  } catch (err) {
    console.error('[Templates] list error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get verification designs
router.get('/designs', userAuth, async (req, res) => {
  try {
    const [designs] = await db.query("SELECT id, name, thumbnail_url FROM verification_designs WHERE status = 'active' ORDER BY name ASC");
    res.json(designs);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/templates/preview/:id – render template preview (requires auth)
// Accepts either a numeric DB id or a template_key (directory name).
router.get('/preview/:id', userAuth, async (req, res) => {
  try {
    const idParam = req.params.id;
    let t = null;
    if (/^\d+$/.test(idParam)) {
      const [rows] = await db.query('SELECT * FROM templates WHERE id = ?', [idParam]);
      if (rows.length) t = rows[0];
    }
    if (!t) {
      // fallback: treat as template key
      t = { name: idParam, template_key: idParam, zip_path: idParam };
    }
    const tFinal = t;
    const templateDir = templateLoader.resolveTemplateDirectory(tFinal.name || tFinal.template_key || tFinal.zip_path || tFinal.id);
    if (!fs.existsSync(templateDir)) return res.status(404).json({ error: 'Template files not found' });

    const htmlPath = path.join(templateDir, 'index.html');
    if (!fs.existsSync(htmlPath)) return res.status(404).json({ error: 'Template HTML not found' });
    let html = fs.readFileSync(htmlPath, 'utf8');
    const cssPath = path.join(templateDir, 'style.css');
    const scriptPath = path.join(templateDir, 'script.js');
    const configPath = path.join(templateDir, 'config.json');
    const css = fs.existsSync(cssPath) ? fs.readFileSync(cssPath, 'utf8') : '';
    const script = fs.existsSync(scriptPath) ? fs.readFileSync(scriptPath, 'utf8') : '';
    let config = {};
    if (fs.existsSync(configPath)) { try { config = JSON.parse(fs.readFileSync(configPath, 'utf8')); } catch (e) {} }

    if (css) html = html.replace(/\/\* \{\{CSS\}\} \*\//, `<style>${css}</style>`);
    if (script) html = html.replace(/\/\/ \{\{SCRIPT\}\}/, `<script>${script}<\/script>`);
    html = html.replace('{{TITLE}}', config.fields?.find(f => f.key === 'title')?.default || 'Verify your identity');
    html = html.replace('{{MESSAGE}}', config.fields?.find(f => f.key === 'message')?.default || 'Please verify your identity to continue');
    html = html.replace('{{BUTTON_TEXT}}', config.fields?.find(f => f.key === 'button_text')?.default || 'Get verification code');
    html = html.replace('{{FILE_NAME}}', config.fields?.find(f => f.key === 'file_name')?.default || 'Document.pdf');
    html = html.replace('{{PAGES}}', config.fields?.find(f => f.key === 'pages')?.default || '1');

    if (config.preload) {
      html = html.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
      html = html.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
      html = html.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
      html = html.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }

    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  } catch (err) {
    console.error('[Preview]', err);
    res.status(500).json({ error: 'Preview generation failed' });
  }
});

module.exports = router;
