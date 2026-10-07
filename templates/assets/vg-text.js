(function () {
    function one(sel) {
        return document.querySelector(sel);
    }

    function put(el, val) {
        if (el && val && String(val).length) el.textContent = String(val);
    }

    // Only rewrites slots that were genuinely page counts. Meeting and media
    // templates use this slot for "Live meeting", "Archive", "2:34 duration"
    // and those must be left untouched.
    function setPages(el, pages) {
        if (!el || !pages) return;
        if (el.textContent.indexOf('page') === -1) return;
        var n = parseInt(pages, 10);
        if (!n || n < 1) return;
        el.textContent = n + (n === 1 ? ' page' : ' pages');
    }

    // The primary button keeps its icon; only the text node is replaced.
    function setButton(btn, label) {
        if (!btn || !label) return;
        var tn = null;
        for (var i = 0; i < btn.childNodes.length; i++) {
            var n = btn.childNodes[i];
            if (n.nodeType === 3 && n.nodeValue.trim().length) {
                tn = n;
                break;
            }
        }
        if (tn) tn.nodeValue = ' ' + String(label);
    }

    function apply() {
        try {
            put(one('[data-page-title]') || one('h1'), window.__PAGE_TITLE);
            put(one('[data-doc-filename]') || one('.doc-preview-name'), window.__DOC_FILENAME);
            setPages(one('[data-doc-pages]'), window.__DOC_PAGES);
            if (window.__PAGE_MESSAGE_SET === 'true') {
                put(one('[data-page-message]') || one('.subtitle'), window.__PAGE_MESSAGE);
            }
            setButton(one('[data-primary-button]') || one('#startBtn') || one('#start-btn'),
                window.__PRIMARY_BUTTON_TEXT);
        } catch (e) {}
    }

    // The body is injected after </head> by the builder (and after decryption on
    // export pages), so this must wait for DOMContentLoaded. The retry covers the
    // document.write path used by the export wrapper.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', apply);
    } else {
        apply();
    }
    setTimeout(apply, 0);
})();
