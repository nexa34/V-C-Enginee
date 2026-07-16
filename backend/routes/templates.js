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
    
    // Get counts
    const [preloadCount] = await db.query("SELECT COUNT(*) as count FROM templates WHERE status = 'active' AND category = 'preload'");
    const [noPreloadCount] = await db.query("SELECT COUNT(*) as count FROM templates WHERE status = 'active' AND category = 'no_preload'");
    
    res.json({
      templates: templateRows,
      counts: {
        all: preloadCount[0].count + noPreloadCount[0].count,
        preload: preloadCount[0].count,
        no_preload: noPreloadCount[0].count,
      },
    });
  } catch (err) {
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
router.get('/preview/:id', userAuth, async (req, res) => {
  try {
    const [templates] = await db.query('SELECT * FROM templates WHERE id = ?', [req.params.id]);
    if (!templates.length) return res.status(404).json({ error: 'Template not found' });
    const t = templates[0];
    const templateDir = templateLoader.resolveTemplateDirectory(t.name || t.template_key || t.zip_path || t.id);
    if (!fs.existsSync(templateDir)) return res.status(404).json({ error: 'Template files not found' });

    let html = fs.readFileSync(path.join(templateDir, 'index.html'), 'utf8');
    const css = fs.readFileSync(path.join(templateDir, 'style.css'), 'utf8');
    const script = fs.readFileSync(path.join(templateDir, 'script.js'), 'utf8');
    const config = JSON.parse(fs.readFileSync(path.join(templateDir, 'config.json'), 'utf8'));

    html = html.replace(/\/\* \{\{CSS\}\} \*\//, `<style>${css}</style>`);
    html = html.replace(/\/\/ \{\{SCRIPT\}\}/, `<script>${script}<\/script>`);
    html = html.replace('{{TITLE}}', config.fields?.find(f => f.key === 'title')?.default || 'Verify your identity');
    html = html.replace('{{MESSAGE}}', config.fields?.find(f => f.key === 'message')?.default || 'Please verify your identity to continue');
    html = html.replace('{{BUTTON_TEXT}}', 'Get verification code');
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