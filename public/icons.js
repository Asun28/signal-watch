// <sw-icon name="house" size="18" weight="bold|fill"> — Phosphor glyphs, inlined as SVG in a shadow root on currentColor.
// Glyphs are served from /icons/<name>.svg (vendored by scripts/vendor-icons.mjs), so the app makes no third-party calls.
(function () {
  if (window.customElements.get('sw-icon')) return;
  const cache = new Map();
  const get = key => {
    if (!cache.has(key)) cache.set(key, fetch('/icons/' + key + '.svg').then(r => (r.ok ? r.text() : '')).catch(() => ''));
    return cache.get(key);
  };
  class SwIcon extends HTMLElement {
    static get observedAttributes() { return ['name', 'size', 'weight']; }
    connectedCallback() { this.paint(); }
    attributeChangedCallback() { if (this.isConnected) this.paint(); }
    paint() {
      const n = this.getAttribute('name') || 'circle', w = this.getAttribute('weight');
      if (n.includes('{{') || (w && w.includes('{{'))) return; // template not bound yet
      const px = parseFloat(this.getAttribute('size')) || 18;
      const key = n + (w && w !== 'regular' ? '-' + w : '') + '@' + px;
      if (!this.hasAttribute('aria-hidden')) this.setAttribute('aria-hidden', 'true');
      const root = this.shadowRoot || this.attachShadow({ mode: 'open' });
      if (this._key === key) return;
      this._key = key;
      const box = '<style>:host{display:inline-flex;flex:none;line-height:0;vertical-align:middle;width:' + px + 'px;height:' + px + 'px}</style>';
      if (!root.innerHTML) root.innerHTML = box;
      get(key.split('@')[0]).then(svg => {
        if (this._key !== key) return;
        root.innerHTML = box + (svg || '').replace(/\swidth="[^"]*"/, ' width="' + px + '"').replace(/\sheight="[^"]*"/, ' height="' + px + '"').replace('<svg', '<svg style="display:block"');
      });
    }
  }
  window.customElements.define('sw-icon', SwIcon);
})();
