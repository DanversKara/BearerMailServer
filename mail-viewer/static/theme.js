/* BearerMail themes. Loaded in <head> so the saved theme is applied before first paint. */
(function () {
  'use strict';
  var THEMES = [
    { id: 'mint', name: 'Mint', dark: false, swatch: ['#f5f9f7', '#5b9a8b'] },
    { id: 'blossom', name: 'Blossom Pink', dark: false, swatch: ['#fff5f8', '#c2497a'] },
    { id: 'blossom-dark', name: 'Blossom Pink Dark', dark: true, swatch: ['#1f1419', '#c2497a'] },
    { id: 'red', name: 'Red', dark: false, swatch: ['#fff6f6', '#c62839'] },
    { id: 'red-dark', name: 'Red Dark', dark: true, swatch: ['#1a1112', '#c62839'] },
  ];
  var KEY = 'bearer-theme';
  function find(id) { for (var i = 0; i < THEMES.length; i++) if (THEMES[i].id === id) return THEMES[i]; return THEMES[0]; }
  function get() { try { return find(localStorage.getItem(KEY)).id; } catch (e) { return THEMES[0].id; } }
  function apply(id) {
    var t = find(id), h = document.documentElement;
    h.setAttribute('data-theme', t.id);
    h.setAttribute('data-bs-theme', t.dark ? 'dark' : 'light');
  }
  function set(id) { try { localStorage.setItem(KEY, find(id).id); } catch (e) { /* private mode */ } apply(id); }
  apply(get());
  window.BearerTheme = { list: THEMES, get: get, set: set };
})();
