const express = require('express');
const router = express.Router();
const db = require('../database/connection');
const { userAuth } = require('../middleware/auth');
const { loadTemplateHTML, loadTemplateCSS, loadTemplateJS, loadVerificationDesignCSS } = require('../services/templateloader');

// GET /api/preview/template/:slug
router.get('/template/:slug', userAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const html = loadTemplateHTML(slug);
    let css = loadTemplateCSS(slug);
    // Use default design (outlook) or first available
    css += '\n' + loadVerificationDesignCSS('outlook');
    const script = loadTemplateJS(slug);

    // Replace placeholders with defaults
    let output = html
      .replace(/\/\* \{\{CSS\}\} \*\//g, css)
      .replace(/\/\/ \{\{SCRIPT\}\}/g, script)
      .replace(/\{\{TITLE\}\}/g, 'Verify your identity')
      .replace(/\{\{MESSAGE\}\}/g, 'Please verify your identity to continue')
      .replace(/\{\{BUTTON_TEXT\}\}/g, 'Get verification code')
      .replace(/\{\{FILE_NAME\}\}/g, 'Document.pdf')
      .replace(/\{\{PAGES\}\}/g, '1');

    // Handle PRELOAD/NO_PRELOAD blocks (simplified: remove both)
    output = output.replace(/\{\{#PRELOAD\}\}/g, '').replace(/\{\{\/PRELOAD\}\}/g, '');
    output = output.replace(/\{\{#NO_PRELOAD\}\}[\s\S]*?\{\{\/NO_PRELOAD\}\}/g, '');

    res.setHeader('Content-Type', 'text/html');
    res.send(output);
  } catch (err) {
    res.status(500).send('Preview unavailable');
  }
});

module.exports = router;