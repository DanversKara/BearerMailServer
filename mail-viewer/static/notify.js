/* BearerMail new-mail alerts: a browser notification and a short chime.
   Works while BearerMail is open in a browser tab (it polls). It needs HTTPS (or localhost) and the browser's permission. */
(function () {
  'use strict';
  var K_ON = 'bearer-notify', K_SOUND = 'bearer-notify-sound', POLL_MS = 20000;
  var seen = {}, timer = null, getEmail = function () { return ''; }, ctx = null;

  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { /* private mode */ } return null; }
  function supported() { return typeof window.Notification === 'function' && window.isSecureContext !== false; }
  function permission() { return supported() ? Notification.permission : 'unsupported'; }
  function enabled() { return store(K_ON) === '1' && permission() === 'granted'; }
  function soundOn() { return store(K_SOUND) !== '0'; }

  function audio() {
    if (!ctx) { var C = window.AudioContext || window.webkitAudioContext; if (!C) return null; try { ctx = new C(); } catch (e) { return null; } }
    if (ctx.state === 'suspended') { try { ctx.resume(); } catch (e) { /* ignore */ } }
    return ctx;
  }
  // Browsers only allow sound after the person has interacted with the page once.
  document.addEventListener('click', function () { if (soundOn()) audio(); }, { once: true, capture: true });

  function chime() {
    var a = audio(); if (!a) return;
    var t0 = a.currentTime;
    [[880, 0], [1320, 0.16]].forEach(function (n) {
      var o = a.createOscillator(), g = a.createGain();
      o.type = 'sine'; o.frequency.value = n[0];
      g.gain.setValueAtTime(0.0001, t0 + n[1]);
      g.gain.exponentialRampToValueAtTime(0.25, t0 + n[1] + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + n[1] + 0.35);
      o.connect(g); g.connect(a.destination); o.start(t0 + n[1]); o.stop(t0 + n[1] + 0.4);
    });
  }

  function show(title, body) {
    if (permission() === 'granted') {
      try {
        var n = new Notification(title, { body: body, tag: 'bearermail-new', icon: '/static/favicon.svg' });
        n.onclick = function () { window.focus(); n.close(); };
      } catch (e) { /* some mobile browsers only allow service-worker notifications */ }
    }
    if (soundOn()) chime();
  }

  function check(email, msgs) {
    if (!email || !Array.isArray(msgs)) return;
    var known = seen[email], fresh = [];
    if (!known) { seen[email] = new Set(msgs.map(function (m) { return m.id; })); return; } // first look = baseline
    msgs.forEach(function (m) { if (!known.has(m.id)) { known.add(m.id); if (!m.seen) fresh.push(m); } });
    if (!fresh.length || !enabled()) return;
    var m = fresh[0], who = (m.from && (m.from.name || m.from.address)) || 'Unknown sender';
    if (fresh.length === 1) show('New mail from ' + who, m.subject || '(no subject)');
    else show(fresh.length + ' new messages', 'Latest from ' + who + ': ' + (m.subject || '(no subject)'));
  }

  function poll() {
    var email = getEmail();
    if (!enabled() || !email) return;
    fetch('/api/inbox/query', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, offset: 0, limit: 15 }) })
      .then(function (r) { return r.json(); })
      .then(function (d) { if (d && d.success) check(email, d.messages); })
      .catch(function () { /* offline: try again next time */ });
  }

  function start() { if (timer) clearInterval(timer); timer = setInterval(poll, POLL_MS); }

  window.BearerNotify = {
    init: function (opts) { if (opts && opts.getEmail) getEmail = opts.getEmail; start(); },
    check: check,
    supported: supported,
    permission: permission,
    enabled: enabled,
    soundOn: soundOn,
    setSound: function (on) { store(K_SOUND, on ? '1' : '0'); if (on) audio(); },
    async enable() {
      if (!supported()) throw new Error(window.isSecureContext === false ? 'Notifications need HTTPS. Open BearerMail through your https:// address.' : 'This browser does not support notifications.');
      var p = Notification.permission === 'granted' ? 'granted' : await Notification.requestPermission();
      if (p !== 'granted') throw new Error('Permission was not granted. Allow notifications for this site in your browser settings, then try again.');
      store(K_ON, '1'); audio(); return true;
    },
    disable: function () { store(K_ON, '0'); },
    test: function () { show('BearerMail', 'Notifications are working.'); },
  };
})();
