/* epic-status client behaviour.
 *
 * Three jobs, and deliberately nothing else:
 *
 *   1. Restore the reader's theme choice.
 *   2. Tick the relative timestamps every second, so "last seen 3m 12s ago" stays
 *      true without a request. This is also the only honest way to show a stale
 *      page: the number keeps climbing whether or not the poll is working.
 *   3. Poll the JSON API and patch the numbers in place.
 *
 * The page is rendered complete on the server. Every value below already has a
 * correct initial state in the HTML, so with JavaScript blocked or broken the board
 * is still right at the moment it was served — it simply stops updating. For a
 * status page that is not a nicety: the day it matters most is the day least suited
 * to discovering a client-side render is broken.
 *
 * Nothing here contacts a node or a relay. Timing requests from the reader's browser
 * to every listed server would put their address in every operator's logs because
 * they opened a status page, and on a privacy coin's own infrastructure page that is
 * the wrong default. Latency shown is measured server-side from one vantage point.
 */

(function () {
  'use strict';

  var POLL_MS = 5000;
  var TICK_MS = 1000;

  /* ---------------------------------------------------------------- theme */

  var STORAGE_KEY = 'epic-status-theme';

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
  }

  try {
    var stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') {
      applyTheme(stored);
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
      applyTheme('light');
    }
  } catch (e) {
    /* Private browsing can throw on localStorage access. Dark is a fine default. */
  }

  var toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', function () {
      var next =
        document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      applyTheme(next);
      try {
        localStorage.setItem(STORAGE_KEY, next);
      } catch (e) {
        /* Not worth telling the reader about. */
      }
    });
  }

  /* ------------------------------------------------------------ timestamps */

  function relative(ms) {
    var s = Math.floor((Date.now() - ms) / 1000);
    if (s < 0) s = 0;
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm ago';
    return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + 'h ago';
  }

  function tick() {
    var nodes = document.querySelectorAll('[data-age]');
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var age = parseInt(el.getAttribute('data-age'), 10);
      if (!age) continue;
      var text = relative(age);
      /* "last seen" is a prefix the server rendered; keep it rather than
         reconstructing the sentence here, so the two cannot drift apart. */
      var prefix = el.getAttribute('data-prefix') || '';
      if (!prefix && el.textContent.indexOf('last seen') === 0) {
        prefix = 'last seen ';
        el.setAttribute('data-prefix', prefix);
      }
      el.textContent = prefix + text;
    }
  }

  /* ----------------------------------------------------------------- poll */

  var failures = 0;

  function setField(slug, field, value) {
    var el = document.querySelector(
      '[data-field="' + field + '"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!el) return;
    var label = el.querySelector('em');
    el.textContent = value;
    /* Re-attach the small-screen label, which lives inside the same element and
       would otherwise be destroyed by writing textContent. */
    if (label) el.insertBefore(label, el.firstChild);
  }

  function cssEscape(value) {
    return String(value).replace(/["\\]/g, '\\$&');
  }

  function fmtMs(value) {
    if (value === null || value === undefined) return '—';
    if (value >= 10000) return (value / 1000).toFixed(1) + ' s';
    return value + ' ms';
  }

  function fmtNum(value) {
    if (value === null || value === undefined) return '—';
    return Number(value).toLocaleString('en-US');
  }

  function patchRow(row) {
    var slug = row.id;
    if (row.kind === 'node') {
      setField(slug, 'height', fmtNum(row.height));
      var lag = row.tip_lag;
      setField(slug, 'lag', lag === null || lag === undefined ? '—' : lag <= 0 ? 'at tip' : '−' + fmtNum(lag));
    } else {
      setField(slug, 'protocol', row.protocol_version || '—');
      setField(
        slug,
        'cert',
        row.cert_expires_in_days === null || row.cert_expires_in_days === undefined
          ? '—'
          : row.cert_expires_in_days + 'd'
      );
    }
    setField(slug, 'latency', fmtMs(row.latency_ms));

    var dot = document.querySelector('.row-dot[data-slug="' + cssEscape(slug) + '"]');
    if (dot) {
      dot.className =
        'row-dot dot dot-' + row.state + (row.state === 'healthy' ? ' is-live' : '');
      dot.setAttribute('aria-label', stateLabel(row.state));
    }

    var seen = document.querySelector(
      '[data-field="seen"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (seen && row.last_ok_at) {
      seen.setAttribute('data-age', String(Date.parse(row.last_ok_at)));
    }

    var container = dot ? dot.closest('.row') : null;
    if (container) {
      container.className = 'row state-' + row.state;
      var stateEl = container.querySelector('.row-state b');
      if (stateEl) stateEl.textContent = stateLabel(row.state);
    }
  }

  function stateLabel(state) {
    if (state === 'healthy') return 'Online';
    if (state === 'degraded') return 'Degraded';
    if (state === 'down') return 'Offline';
    return 'No data';
  }

  function setText(field, value) {
    var el = document.querySelector('[data-field="' + field + '"]');
    if (el) el.textContent = value;
  }

  function poll() {
    /* A status page left open in a background tab for a day would otherwise make
       17,000 requests to render something nobody is looking at. */
    if (document.hidden) return;
    fetch('/api/v1/status.json', { headers: { accept: 'application/json' } })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function (data) {
        failures = 0;
        var net = data.network || {};
        setText('tip', fmtNum(net.tip_height));
        setText('nodes', net.nodes_healthy + ' / ' + net.nodes_total);
        setText('epicbox', net.epicbox_healthy + ' / ' + net.epicbox_total);

        var generated = document.querySelector('[data-field="generated"]');
        if (generated && data.generated_at) {
          generated.setAttribute('data-age', String(Date.parse(data.generated_at)));
        }

        var rows = (data.nodes || []).concat(data.epicbox || []);
        for (var i = 0; i < rows.length; i++) patchRow(rows[i]);
        tick();
      })
      .catch(function () {
        failures += 1;
        /* Three consecutive failures means this page has lost the service, which is
           different from the network being down and must not be shown as if it were
           the same thing. The timestamps keep climbing either way, so a reader can
           see the page has gone quiet even before this says so. */
        if (failures === 3) {
          var generated = document.querySelector('[data-field="generated"]');
          if (generated) generated.removeAttribute('data-age');
          if (generated) generated.textContent = 'not updating';
        }
      });
  }

  tick();
  setInterval(tick, TICK_MS);
  setInterval(poll, POLL_MS);

  /* Catch up immediately when the tab comes back, rather than showing a minute-old
     board until the next interval fires. */
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) poll();
  });
})();
