/* BearerMail themes. Loaded in <head> so the saved theme is applied before first paint. */
(function () {
  'use strict';
  // group: 'light' | 'dark' | 'animated'. Dark themes end in "-dark" (the CSS relies on that).
  var THEMES = [
    { id: 'mint', name: 'Mint', dark: false, group: 'light', swatch: ['#f5f9f7', '#5b9a8b'] },
    { id: 'blossom', name: 'Blossom Pink', dark: false, group: 'light', swatch: ['#fff5f8', '#c2497a'] },
    { id: 'red', name: 'Red', dark: false, group: 'light', swatch: ['#fff6f6', '#c62839'] },
    { id: 'ocean', name: 'Ocean', dark: false, group: 'light', swatch: ['#f4f8ff', '#2563eb'] },
    { id: 'lavender', name: 'Lavender', dark: false, group: 'light', swatch: ['#f8f5fd', '#7c4dbd'] },
    { id: 'sunset', name: 'Sunset', dark: false, group: 'light', swatch: ['#fff8f1', '#e8590c'] },
    { id: 'slate', name: 'Slate', dark: false, group: 'light', swatch: ['#f6f7f9', '#475569'] },
    { id: 'mint-dark', name: 'Mint Dark', dark: true, group: 'dark', swatch: ['#111a18', '#5fb3a1'] },
    { id: 'blossom-dark', name: 'Blossom Pink Dark', dark: true, group: 'dark', swatch: ['#1f1419', '#c2497a'] },
    { id: 'red-dark', name: 'Red Dark', dark: true, group: 'dark', swatch: ['#1a1112', '#c62839'] },
    { id: 'ocean-dark', name: 'Ocean Dark', dark: true, group: 'dark', swatch: ['#0d1524', '#3b82f6'] },
    { id: 'lavender-dark', name: 'Lavender Dark', dark: true, group: 'dark', swatch: ['#17121f', '#9b6fe0'] },
    { id: 'forest-dark', name: 'Forest', dark: true, group: 'dark', swatch: ['#0f1610', '#4caf50'] },
    { id: 'midnight-dark', name: 'Midnight', dark: true, group: 'dark', swatch: ['#0b0d1a', '#6366f1'] },
    { id: 'graphite-dark', name: 'Graphite', dark: true, group: 'dark', swatch: ['#111317', '#5a6577'] },
    { id: 'aurora-dark', name: 'Aurora', dark: true, group: 'animated', animated: true, swatch: ['#070d14', '#2dd4bf', '#8b5cf6'] },
    { id: 'starfield-dark', name: 'Starfield', dark: true, group: 'animated', animated: true, swatch: ['#05060d', '#6d5dfc', '#cbd5ff'] },
    { id: 'synthwave-dark', name: 'Synthwave', dark: true, group: 'animated', animated: true, swatch: ['#1a0826', '#db2777', '#f59e0b'] },
    { id: 'sunrise', name: 'Sunrise', dark: false, group: 'animated', animated: true, swatch: ['#ffe4d6', '#f9a8d4', '#c4b5fd'] },
    { id: 'waves', name: 'Ocean Waves', dark: false, group: 'animated', animated: true, swatch: ['#e0f2fe', '#38bdf8', '#0369a1'] },
  ];
  var KEY = 'bearer-theme';
  function find(id) { for (var i = 0; i < THEMES.length; i++) if (THEMES[i].id === id) return THEMES[i]; return THEMES[0]; }
  function get() { try { return find(localStorage.getItem(KEY)).id; } catch (e) { return THEMES[0].id; } }
  function apply(id) {
    var t = find(id), h = document.documentElement;
    h.setAttribute('data-theme', t.id);
    h.setAttribute('data-bs-theme', t.dark ? 'dark' : 'light');
    if (t.animated) h.setAttribute('data-anim', t.id); else h.removeAttribute('data-anim');
  }
  function set(id) { try { localStorage.setItem(KEY, find(id).id); } catch (e) { /* private mode */ } apply(id); }
  apply(get());
  window.BearerTheme = { list: THEMES, get: get, set: set };
})();
