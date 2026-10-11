const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { loadTemplateHTML, loadTemplateCSS, loadTemplateJS, loadVerificationDesignCSS, loadTemplateConfig } = require('../services/templateloader');

// Helper: Get default value for a field from template config
function getConfigDefault(templateConfig, key, fallback) {
  if (!templateConfig || !templateConfig.fields) return fallback;
  var field = templateConfig.fields.find(function(f) { return f.key === key; });
  return field && field.default !== undefined ? field.default : fallback;
}

// GET /api/preview/template/:slug
router.get('/template/:slug', userAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const html = loadTemplateHTML(slug);
    let css = loadTemplateCSS(slug);
    // Use default design (outlook) or first available
    css += '\n' + loadVerificationDesignCSS('outlook');
    const script = loadTemplateJS(slug);
    const config = loadTemplateConfig(slug);

    // Replace placeholders with template config defaults
    let output = html
      .replace(/\/\* \{\{CSS\}\} \*\//g, css)
      .replace(/\/\/ \{\{SCRIPT\}\}/g, script)
      .replace(/\{\{TITLE\}\}/g, getConfigDefault(config, 'title', 'Verify your identity'))
      .replace(/\{\{MESSAGE\}\}/g, getConfigDefault(config, 'message', 'Please verify your identity to continue'))
      .replace(/\{\{RECIPIENT_EMAIL\}\}/g, getConfigDefault(config, 'recipient_email', 'user@example.com'))
      .replace(/\{\{BUTTON_TEXT\}\}/g, getConfigDefault(config, 'button_text', 'Get verification code'))
      .replace(/\{\{FILE_NAME\}\}/g, getConfigDefault(config, 'file_name', 'Document.pdf'))
      .replace(/\{\{PAGES\}\}/g, String(getConfigDefault(config, 'pages', 1)))
      .replace(/\{\{PAGES_LABEL\}\}/g, (function () {
        var p = parseInt(getConfigDefault(config, 'pages', 1), 10) || 1;
        return p + (p === 1 ? ' page' : ' pages');
      })());

    // Handle PRELOAD/NO_PRELOAD blocks
    if (config && config.preload) {
      output = output.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
      output = output.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');
    } else {
      output = output.replace(/\{\{#NO_PRELOAD\}\}/g, '').replace(/\{\{\/NO_PRELOAD\}\}/g, '');
      output = output.replace(/\{\{#PRELOAD\}\}[\s\S]*?\{\{\/PRELOAD\}\}/g, '');
    }

    res.setHeader('Content-Type', 'text/html');
    res.send(output);
  } catch (err) {

    res.status(500).send('Preview unavailable');
  }
});

module.exports = router;
