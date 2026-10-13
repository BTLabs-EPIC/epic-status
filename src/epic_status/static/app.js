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
 * Nothing here contacts a node or a relay on its own. Timing requests from the reader's
 * browser to every listed server would put their address in every operator's logs because
 * they opened a status page, and on a privacy coin's own infrastructure page that is the
 * wrong default. The latency in each row is measured server-side from one vantage point.
 *
 * The one exception is explicit and singular: the expanded row has a button that queries
 * that one host from the reader's browser, on that press only. Never on load, never on a
 * timer, never more than the host they asked about. That is the line — a reader choosing
 * to measure a server from where they are sitting is not the same thing as a page doing it
 * to forty servers on their behalf.
 */

(function () {
  'use strict';

  var POLL_MS = 5000;
  /* Was 1000. Nothing left on the page resolves finer than the poll: the freshness
     indicator states its cadence instead of counting up to it, and the only ages still
     rendered belong to hosts that are down, where a five-second granularity is irrelevant.
     A timer that repaints text every second when no value changed is motion for its own
     sake. */
  var TICK_MS = 5000;

  /* Freshness thresholds. Below the first, the board is simply current and says so once.
     Between them something is wrong but recoverable. Past the second, the number matters
     again, so it comes back. */
  var STALE_WARN_S = 60;
  var STALE_BAD_S = 300;
  var lastOk = Date.now();

  /* The released Epicbox protocol version, read from an attribute on <html> rather
     than hardcoded here or injected as an inline script. The service sets its own CSP
     with `script-src 'self'` and no `unsafe-inline`, so a server-rendered constant in
     a <script> block would simply be dropped — a data attribute is the only channel
     that survives it. The server-rendered HTML already carries the correct marker on
     every relay row; this is only needed so a patched row keeps it. */
  var EPICBOX_PROTOCOL =
    document.documentElement.getAttribute('data-epicbox-protocol') || null;

  /* The certificate window, from config via the same channel and for the same reason.
     Parsed with a fallback rather than assumed: if the attribute is ever missing, a NaN
     comparison is false everywhere and the marker would silently stop appearing on
     patched rows while the server kept rendering it — a disagreement between the first
     paint and the second that is very hard to see. */
  var CERT_WARN_DAYS = (function () {
    var raw = parseInt(
      document.documentElement.getAttribute('data-cert-warn-days'),
      10
    );
    return isNaN(raw) ? 14 : raw;
  })();

  /* Which network this page is showing, and therefore which document to poll. Same
     data-attribute channel and the same reason: CSP forbids an inline script, so the
     server cannot simply write the URL into the page.

     Mainnet is spelled as the bare path rather than `?chain=mainnet`, matching the
     canonical URL the navbar links to, so the common case sends the request the API has
     always received. */
  var STATUS_URL = (function () {
    var chain = document.documentElement.getAttribute('data-chain');
    return chain && chain !== 'mainnet'
      ? '/api/v1/status.json?chain=' + encodeURIComponent(chain)
      : '/api/v1/status.json';
  })();

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

  function pad(n) {
    return n < 10 ? '0' + n : String(n);
  }

  /* Mirrors render._age_clock. A fixed-width clock, because the reflow of a changing
     phrase is what read as flickering — not the one-second update itself, which is the
     point of a live board and stays. */
  function clock(ms) {
    var s = Math.floor((Date.now() - ms) / 1000);
    if (s < 0) s = 0;
    if (s < 3600) return Math.floor(s / 60) + ':' + pad(s % 60);
    if (s < 86400)
      return Math.floor(s / 3600) + ':' + pad(Math.floor((s % 3600) / 60)) + ':' + pad(s % 60);
    return Math.floor(s / 86400) + 'd ' + Math.floor((s % 86400) / 3600) + ':' +
      pad(Math.floor((s % 3600) / 60));
  }

  /* `data-fmt` names the format the server rendered, so the client reproduces that one
     rather than imposing a single style on every age on the page. Without it a cell the
     server wrote as `0:04` became `4s ago` on the first tick — a layout shift one second
     after load, which is exactly the flicker this was meant to remove.

       clock  fixed-width age, no suffix      0:04
       ago    fixed-width age with a prefix   last ok 4:12
       (none) prose relative time             18m 4s ago
  */
  /* Colour and wording live here; the pulse is a class added on each successful poll and
     removed when it finishes. Text changes only at a threshold, so in the normal case this
     writes the same string it already wrote and the reader sees nothing move. */
  function freshness() {
    var stamp = document.querySelector('.hero-stamp');
    if (!stamp) return;
    var text = stamp.querySelector('[data-field="live"]');
    var sr = stamp.querySelector('[data-field="live-sr"]');
    var age = Math.floor((Date.now() - lastOk) / 1000);
    var state = age > STALE_BAD_S ? 'bad' : age > STALE_WARN_S ? 'warn' : 'ok';
    var next =
      state === 'ok'
        ? 'Updated every ' + POLL_MS / 1000 + ' sec'
        : state === 'warn'
          ? 'Catching up...'
          : 'Last updated: ' + clock(lastOk) + ' ago';
    if (stamp.getAttribute('data-live') !== state) {
      stamp.setAttribute('data-live', state);
      /* Announced once per transition, not per repaint: a live region that fires every
         five seconds is unusable with a screen reader. */
      if (sr) sr.textContent = next;
    }
    if (text && text.textContent !== next) text.textContent = next;
  }

  /* A single short pulse when an update lands. This is the only animation on the page that
     reports something: with it, a working auto-refresh is distinguishable from a frozen
     tab without any text having to move. */
  function pulse() {
    var dot = document.querySelector('.hero-stamp .live-dot');
    if (!dot) return;
    dot.classList.remove('is-pulse');
    /* Reading offsetWidth forces the class removal to take effect before it is re-added,
       without which the animation does not restart on a second poll. */
    void dot.offsetWidth;
    dot.classList.add('is-pulse');
  }

  function tick() {
    var nodes = document.querySelectorAll('[data-age]');
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var age = parseInt(el.getAttribute('data-age'), 10);
      if (!age) continue;
      var fmt = el.getAttribute('data-fmt');
      if (fmt === 'clock') {
        el.textContent = clock(age);
        continue;
      }
      if (fmt === 'ago') {
        el.textContent = 'last ok ' + clock(age);
        continue;
      }
      /* "last seen" is a prefix the server rendered; keep it rather than
         reconstructing the sentence here, so the two cannot drift apart. */
      var prefix = el.getAttribute('data-prefix') || '';
      if (!prefix && el.textContent.indexOf('last seen') === 0) {
        prefix = 'last seen ';
        el.setAttribute('data-prefix', prefix);
      }
      el.textContent = prefix + relative(age);
    }
  }

  /* ----------------------------------------------------------------- poll */

  var failures = 0;

  function setField(slug, field, value, sortValue) {
    var el = document.querySelector(
      '[data-field="' + field + '"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!el) return;
    var label = el.querySelector('em');
    el.textContent = value;
    /* Re-attach the small-screen label, which lives inside the same element and
       would otherwise be destroyed by writing textContent. */
    if (label) el.insertBefore(label, el.firstChild);
    /* Keep the sort key in step with the value on screen. Without this, a column
       sorted once keeps ordering by the numbers the page was served with while the
       visible figures move underneath it — the worst kind of wrong, because it looks
       deliberate. */
    if (sortValue !== undefined) {
      el.setAttribute(
        'data-sort',
        sortValue === null || sortValue === undefined ? '-1' : String(sortValue)
      );
    }
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

  /* Mirrors render._pct exactly, including the 99.95% rounding gate. No data is an em
     dash and never 0%: a target with no history is not a target with no uptime, and
     printing 0% for one is how a status page libels an operator. */
  function fmtPct(value) {
    if (value === null || value === undefined) return '—';
    if (value >= 0.9995) return '100%';
    return (value * 100).toFixed(2) + '%';
  }

  /* An age that ticks, rather than a value that is written once. The element
     carrying data-age is nested inside the cell so that tick() rewriting its text
     cannot destroy the cell's small-screen <em> label. */
  function setAge(slug, field, iso) {
    var cell = document.querySelector(
      '[data-field="' + field + '"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!cell) return;
    var el = cell.querySelector('[data-age]');
    if (!el) return;
    if (!iso) {
      el.removeAttribute('data-age');
      el.textContent = '—';
      return;
    }
    el.setAttribute('data-age', String(Date.parse(iso)));
  }

  /* Strictly older, not merely different — the same rule score.version_behind
     applies on the server. A relay answering 3.0.1 against a published 3.0.0 is ahead
     of the release, not behind it, and marking it taught readers to ignore the mark.
     Unparseable segments sort as 0 so "4.0.3-rc1" compares as 4.0.3. */
  function versionKey(value) {
    return String(value)
      .replace(/-/g, '.')
      .split('.')
      .map(function (chunk) {
        var n = parseInt(chunk, 10);
        return isNaN(n) ? 0 : n;
      });
  }

  function versionBehind(reported, released) {
    if (!reported || !released) return false;
    var a = versionKey(reported);
    var b = versionKey(released);
    for (var i = 0; i < Math.max(a.length, b.length); i++) {
      var x = a[i] || 0;
      var y = b[i] || 0;
      if (x !== y) return x < y;
    }
    return false;
  }

  /* Mirrors render._lat_w and render._lat_band exactly. Duplicated rather than shared
     because the server has no way to hand a function to the client, and a bar that
     disagrees with the server-rendered one after the first poll is worse than no bar. */
  var LAT_CEILING = 2000;

  function latWidth(ms) {
    if (ms === null || ms === undefined) return 0;
    var capped = Math.min(ms, LAT_CEILING);
    var step = Math.round((capped / LAT_CEILING) * 100 / 5) * 5;
    return Math.max(5, Math.min(100, step));
  }

  function latBand(ms) {
    if (ms === null || ms === undefined) return 'none';
    if (ms < 150) return 'fast';
    if (ms < 600) return 'mid';
    return 'slow';
  }

  function setLatency(slug, ms) {
    var cell = document.querySelector(
      '[data-field="latency"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!cell) return;
    cell.setAttribute('data-sort', ms === null || ms === undefined ? '-1' : String(ms));
    var n = cell.querySelector('.lat-n');
    if (n) n.textContent = fmtMs(ms);
    var fill = cell.querySelector('.lat-fill');
    if (fill) fill.className = 'lat-fill lat-' + latBand(ms) + ' lat-w' + latWidth(ms);
  }

  function setUptime(slug, value) {
    var cell = document.querySelector(
      '[data-field="up24"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!cell) return;
    cell.setAttribute(
      'data-sort',
      value === null || value === undefined ? '-1' : String(value)
    );
    setField(slug, 'up24', fmtPct(value));
  }

  /* A cell whose class carries meaning as well as its text. setField only rewrites text, so
     the `ver-old` marker is toggled separately — otherwise a node that upgraded between polls
     would keep its warning styling until a reload.
   *
   * `classList.toggle`, never `className =`. This function used to take the cell's full class
   * string and reassign it, which meant the grid slot was written here as well as in the
   * template and the stylesheet. When the relay layout changed and protocol moved from the
   * first metric slot to the third, this kept writing the old one: the server rendered the
   * table correctly, then the first poll five seconds later moved protocol into the TLS column
   * and pushed cert into Version. It looked like a CSS bug and it was a duplicated fact.
   * Toggling one class touches only what this function actually knows about. */
  function setVersion(slug, field, value, released) {
    setField(slug, field, value || '—', value || '');
    var el = document.querySelector(
      '[data-field="' + field + '"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!el) return;
    var stale = versionBehind(value, released);
    el.classList.toggle('ver-old', stale);
    if (stale) {
      el.setAttribute('title', 'Running ' + value + '; ' + released + ' is released');
    } else {
      el.removeAttribute('title');
    }
  }

  /* The certificate cell holds three things — the small-screen label, the value, and a
     marker carrying its own tooltip — so `setField` cannot be used on it. That function
     writes `textContent` and re-attaches only the <em>, which would have deleted the
     marker on the first poll five seconds after load: exactly the hazard the latency bar
     hit, and the reason that cell is patched by hand too.

     What is toggled here is one class and two attributes. The marker itself is always in
     the server-rendered markup, so crossing the threshold never has to build DOM. */
  function setCert(slug, days) {
    var cell = document.querySelector(
      '[data-field="cert"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (!cell) return;
    var known = days !== null && days !== undefined;

    var value = cell.querySelector('b');
    if (value) value.textContent = known ? days + 'd' : '—';
    /* Written here rather than via setField, for the same reason a sorted latency column
       needs it: a column sorted once must not keep ordering by the numbers the page was
       served with. */
    cell.setAttribute('data-sort', known ? String(days) : '-1');

    var why = certNote(days);
    cell.classList.toggle('cert-warn', why !== null);

    var flag = cell.querySelector('.cert-flag');
    if (!flag) return;
    if (why) {
      flag.setAttribute('role', 'img');
      flag.setAttribute('tabindex', '0');
      flag.setAttribute('title', why);
      flag.setAttribute('aria-label', why);
      flag.removeAttribute('aria-hidden');
    } else {
      /* Removed, not emptied, and the focus stop goes with them. An element keeping
         `role="img"` with no label is announced as an unlabelled image; one keeping
         `tabindex="0"` is a tab stop holding nothing. `display: none` hides it either way,
         so this only matters when the stylesheet has not loaded — which is exactly the
         moment a page should still be usable. */
      flag.removeAttribute('role');
      flag.removeAttribute('tabindex');
      flag.removeAttribute('title');
      flag.removeAttribute('aria-label');
      flag.setAttribute('aria-hidden', 'true');
    }
  }

  /* Mirrors render.cert_note, wording included. Duplicated deliberately and for the same
     reason `versionBehind` is: this page is rendered complete on the server and then
     patched in place, so any string that can change after first paint exists in both
     languages or goes stale in one of them. If the sentence changes, it changes twice. */
  function certNote(days) {
    if (days === null || days === undefined || days > CERT_WARN_DAYS) return null;
    if (days <= 0) {
      return 'TLS certificate has expired — connections will fail verification';
    }
    return (
      'TLS certificate expires in ' +
      days +
      (days === 1 ? ' day' : ' days') +
      ' — the relay is online and answering; connections are unaffected until then'
    );
  }

  function patchRow(row, network) {
    var slug = row.id;
    if (row.kind === 'node') {
      setField(slug, 'height', fmtNum(row.height), row.height);
      var lag = row.tip_lag;
      setField(slug, 'lag', lag === null || lag === undefined ? '—' : lag <= 0 ? 'at tip' : '−' + fmtNum(lag), lag);
      setVersion(
        slug,
        'version',
        row.node_version,
        network ? network.released_node_version : null
      );
    } else if (row.kind === 'pool') {
      setField(slug, 'miners', fmtNum(row.miners), row.miners);
      /* No height and no tip comparison: a pool's block height is the last block it
         won, not its chain tip. See probes/pool.py. */
      setAge(slug, 'lastblock', row.last_block_at);
    } else {
      setVersion(slug, 'protocol', row.protocol_version, EPICBOX_PROTOCOL);
      setCert(slug, row.cert_expires_in_days);
    }
    /* Latency is not a plain text cell any more: it holds a number and a bar, and
       setField rewrites textContent, which would delete the bar on the first poll. The
       number and the fill are updated separately, and `data-sort` with them — otherwise
       a column sorted by latency would keep ordering by the values the page was served
       with rather than the ones on screen. */
    setLatency(slug, row.latency_ms);
    /* 24h uptime moves slowly, but it does move, and leaving it frozen while every
       number beside it ticks is the kind of quiet staleness this page exists to not
       have. `pct` on the server renders two decimals; match it rather than inventing a
       second format for the same column. */
    if (row.uptime) setUptime(slug, row.uptime['24h']);

    var dot = document.querySelector('.row-dot[data-slug="' + cssEscape(slug) + '"]');
    if (dot) {
      dot.className =
        'row-dot dot dot-' + row.state + (row.state === 'healthy' ? ' is-live' : '');
      dot.setAttribute('aria-label', stateLabel(row.state));
    }

    /* The sub-line under the state word means different things in different states:
       30-day uptime while healthy, time since the last success otherwise. A host that
       recovers between polls has to switch, so this rewrites the cell rather than
       updating an age attribute that should no longer exist. */
    var sub = document.querySelector(
      '[data-field="sub"][data-slug="' + cssEscape(slug) + '"]'
    );
    if (sub) {
      if (row.state === 'healthy') {
        sub.removeAttribute('data-age');
        sub.removeAttribute('data-fmt');
        sub.removeAttribute('title');
        sub.className = 'row-sub';
        sub.textContent = '1h ' + fmtPct(row.uptime ? row.uptime['1h'] : null);
      } else {
        sub.className = 'row-sub row-sub-age';
        sub.setAttribute('data-fmt', 'ago');
        if (row.detail || row.last_error) sub.setAttribute('title', row.detail || row.last_error);
        if (row.last_ok_at) {
          sub.setAttribute('data-age', String(Date.parse(row.last_ok_at)));
        } else {
          sub.removeAttribute('data-age');
          sub.textContent = 'never seen';
        }
      }
    }

    var container = dot ? dot.closest('.row') : null;
    if (container) {
      /* Swap only the state class. Reassigning className here would drop anything else the
         row carries — the same mistake that moved the relay columns on the first poll. */
      container.classList.remove(
        'state-healthy', 'state-degraded', 'state-down', 'state-unknown'
      );
      container.classList.add('state-' + row.state);
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
    /* The chain this page was rendered for, not a default. Without it a floonet board
       would poll mainnet's status.json five seconds after load and patch mainnet's
       heights into floonet's rows — every number silently wrong, on a page whose
       whole purpose is to be trusted about numbers. `patchRow` matches on slug, so
       the rows themselves would not move; only their contents would become a lie. */
    fetch(STATUS_URL, { headers: { accept: 'application/json' } })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function (data) {
        /* Validate before recording success. Refuse a document that describes a
           different network than this page.

           Defence in depth behind the versioned asset URL: if the two ever disagree
           again — a stale script, a proxy rewriting the query string, a hand-edited
           URL — the page stops updating instead of filling with another chain's
           numbers. Throwing puts it through the same path as a network failure, so
           `failures` climbs and `lastOk` is left alone, which is what makes
           `freshness()` announce that the board has gone quiet. That announcement is
           the whole point: a page that visibly stops is recoverable by the reader,
           while a floonet board silently showing mainnet's tip is not detectable at
           all, and this service exists to be trusted about exactly those numbers. */
        var served = (data.network || {}).chain;
        var expected = document.documentElement.getAttribute('data-chain');
        if (served && expected && served !== expected) {
          throw new Error('chain mismatch: asked ' + expected + ', got ' + served);
        }
        failures = 0;
        var net = data.network || {};
        /* The numerator only. These used to rewrite the whole cell as "3 / 3" — spaced, where
           the server renders "3/3" unspaced — so the first poll five seconds after load widened
           every count and nudged the row. It also destroyed the span wrapping the denominator,
           which is what dims it. Writing just the number that changes cannot drift from the
           server's formatting, because it does not restate the format. */
        setText('nodes', net.nodes_healthy);
        setText('epicbox', net.epicbox_healthy);
        setText('pools', net.pools_healthy);
        setSum('nodes', net.nodes_healthy, net.nodes_total);
        setSum('epicbox', net.epicbox_healthy, net.epicbox_total);
        setSum('pools', net.pools_healthy, net.pools_total);

        lastOk = Date.now();
        pulse();
        /* The tip rolls rather than swapping. A block height only ever ticks up by one, so in
           practice one or two digits move and the rest hold still — which is the whole reason
           this is not noisy. */
        if (net.tip_height !== null && net.tip_height !== undefined) {
          roll(document.querySelector('[data-field="tip"]'), fmtNum(net.tip_height));
        }
        /* Absolute, so it does not need re-rendering on a timer — but it does move when a
           new block arrives, which is exactly when the rest of these numbers move. */
        if (net.tip_mined_at) {
          setText('mined', new Date(net.tip_mined_at).toISOString().substring(11, 19) + ' UTC');
        }

        var rows = (data.nodes || [])
          .concat(data.epicbox || [])
          .concat(data.pools || []);
        for (var i = 0; i < rows.length; i++) patchRow(rows[i], net);
        openTroubledGroups();

        /* The strip states the released version once. Its count still has to move,
           because a node upgrading is exactly the change this line exists to show. */
        if (net.released_node_version) {
          setText(
            'nodescurrent',
            net.nodes_versioned
              ? net.nodes_current + ' of ' + net.nodes_versioned + ' running it'
              : 'no node reported a version'
          );
        }
        tick();
      })
      .catch(function () {
        failures += 1;
        /* Three consecutive failures means this page has lost the service, which is
           different from the network being down and must not be shown as if it were
           the same thing. The timestamps keep climbing either way, so a reader can
           see the page has gone quiet even before this says so. */
        if (failures === 3) {
          /* `freshness()` already tells the reader the board has gone quiet, from the age
             of the last success rather than from a failure count — which is the honest
             measure, since a page left open on a laptop that slept has no failures and is
             hours stale. Nothing extra to write here. */
          freshness();
        }
      });
  }

  tick();
  freshness();
  setInterval(tick, TICK_MS);
  setInterval(freshness, TICK_MS);
  setInterval(poll, POLL_MS);


  /* ------------------------------------------------------------ rolling digits
   *
   * An odometer, at the speed of the thing it measures. A block lands about once a minute, so
   * the movement can afford to be slow — 620ms with an exponential ease-out, which settles
   * rather than snapping, and only on the characters that actually changed. A height going
   * from 3,722,051 to 3,722,052 moves one digit; the other nine hold perfectly still. Animating
   * the whole number would be the flashy version of the same information.
   *
   * Implemented with `element.animate()` rather than a class or an inline transform. The
   * service's CSP is `style-src 'self'` with no `unsafe-inline`, so a `style="transform:..."`
   * attribute is silently dropped — and the alternative, one class per digit position, is ten
   * rules to say what one scripted animation says. The Web Animations API is script, not style,
   * so it is unaffected.
   */
  var ROLL_MS = 620;
  var ROLL_EASE = 'cubic-bezier(0.16, 0.84, 0.28, 1)';

  function prefersStill() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function roll(el, next) {
    if (!el) return;
    var prev = (el.getAttribute('data-value') || el.textContent || '').trim();
    if (prev === next) return;
    el.setAttribute('data-value', next);

    /* Reduced motion, a first render, or a change of width — set the text and stop. A number
       that gained a digit has no per-position correspondence to roll against, and inventing one
       would slide every character for a carry. */
    if (prefersStill() || !prev || prev.length !== next.length || !el.animate) {
      el.textContent = next;
      return;
    }

    var chars = el.querySelectorAll('.odo-c');
    if (chars.length !== next.length) {
      el.textContent = '';
      for (var i = 0; i < next.length; i++) {
        var cell = document.createElement('span');
        cell.className = 'odo-c';
        var col = document.createElement('span');
        col.className = 'odo-col';
        var now = document.createElement('i');
        now.textContent = prev[i];
        col.appendChild(now);
        cell.appendChild(col);
        el.appendChild(cell);
      }
      chars = el.querySelectorAll('.odo-c');
    }

    for (var j = 0; j < next.length; j++) {
      var slot = chars[j];
      var column = slot.firstChild;
      var current = column.lastChild;
      if (current.textContent === next[j]) continue;

      var incoming = document.createElement('i');
      incoming.textContent = next[j];
      column.appendChild(incoming);

      /* One line up, so the outgoing character leaves through the top of the window and the
         incoming one arrives from the bottom. The window is one line tall and clipped. */
      var anim = column.animate(
        [{ transform: 'translateY(0)' }, { transform: 'translateY(-50%)' }],
        { duration: ROLL_MS, easing: ROLL_EASE, fill: 'none' }
      );
      /* Collapse to the new character when it finishes, so the column never accumulates and a
         second block arriving mid-roll starts from a clean single digit. */
      (function (colRef, value) {
        anim.onfinish = function () {
          colRef.textContent = '';
          var settled = document.createElement('i');
          settled.textContent = value;
          colRef.appendChild(settled);
        };
      })(column, next[j]);
    }
  }

  /* ----------------------------------------------------------------- sort
   *
   * Column sorting, as a progressive enhancement over the server's own ordering
   * (health, then latency). Nothing on the page depends on this having run: with
   * JavaScript off the headers are inert buttons and the served order stands.
   *
   * Sorting reads `data-sort` on each cell, never the visible text. The text is
   * formatted for a human — "at tip", "1,204", "—", "99.94%" — and comparing those
   * strings files "at tip" between "9 ms" and "90 ms" and sorts an em dash to the top.
   * The comparable value is a number, so the number is what the attribute carries.
   *
   * Missing data sorts last in both directions. A node that answered nothing is not the
   * fastest node, and it is not the slowest either; it is unknown, and unknown belongs
   * at the bottom where it cannot be mistaken for a measurement. `data-sort` renders -1
   * for an absent number precisely so this stays one comparison rather than a special
   * case scattered through the template.
   */

  var ABSENT = -1;

  function sortValue(row, key) {
    var cell =
      key === 'host'
        ? row.querySelector('.row-host b')
        : row.querySelector('.' + key.split(' ').join('.'));
    if (!cell) return null;
    if (key === 'host') return cell.textContent.trim().toLowerCase();
    var raw = cell.getAttribute('data-sort');
    if (raw === null || raw === '') return ABSENT;
    var n = Number(raw);
    return isNaN(n) ? raw.toLowerCase() : n;
  }

  function applySort(list, key, dir) {
    var rows = [].slice.call(list.querySelectorAll(':scope > .row'));
    rows.sort(function (a, b) {
      var x = sortValue(a, key);
      var y = sortValue(b, key);
      var xMissing = x === ABSENT || x === null || x === '';
      var yMissing = y === ABSENT || y === null || y === '';
      if (xMissing && yMissing) return 0;
      if (xMissing) return 1;
      if (yMissing) return -1;
      if (x === y) return 0;
      return (x < y ? -1 : 1) * (dir === 'asc' ? 1 : -1);
    });
    /* appendChild moves rather than copies, so re-appending in order is the reorder.
       The striping is `:nth-child`, so it follows automatically. The expanded panel is a
       child of its row, so it travels with it and needs nothing here — which is the
       second reason it is not a sibling list item. */
    for (var i = 0; i < rows.length; i++) list.appendChild(rows[i]);
  }

  var lists = document.querySelectorAll('.rows');
  for (var li = 0; li < lists.length; li++) {
    (function (list) {
      var head = list.querySelector('.row-head');
      if (!head) return;
      head.addEventListener('click', function (event) {
        var btn = event.target.closest('.sort');
        if (!btn) return;
        var key = btn.getAttribute('data-sort-key');
        /* First click on a measurement sorts worst-first, because the reason to sort a
           status board is to find the problem. Host is the exception: nobody looks for
           the alphabetically last hostname. */
        var next =
          btn.getAttribute('data-dir') === 'desc'
            ? 'asc'
            : btn.getAttribute('data-dir') === 'asc'
              ? 'desc'
              : key === 'host'
                ? 'asc'
                : 'desc';
        var others = head.querySelectorAll('.sort');
        for (var i = 0; i < others.length; i++) {
          others[i].removeAttribute('data-dir');
          others[i].removeAttribute('aria-label');
        }
        btn.setAttribute('data-dir', next);
        btn.setAttribute(
          'aria-label',
          btn.textContent.trim() + ', sorted ' + (next === 'asc' ? 'ascending' : 'descending')
        );
        applySort(list, key, next);
      });
    })(lists[li]);
  }

  /* Catch up immediately when the tab comes back, rather than showing a minute-old
     board until the next interval fires. */
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) poll();
  });


  /* --------------------------------------------------------------- expand
   *
   * One row open at a time, opened by clicking anywhere on it. The chevron button is the
   * real control — it carries `aria-expanded` and `aria-controls` and is what a keyboard
   * reaches — and the row-wide click handler is a convenience on top of it.
   *
   * Exclusive by design rather than by taste: two panels open at once pushes the row a
   * reader is comparing against off the screen, which is the one thing a board is for.
   */

  /* Long enough to outlast the CSS transition on `grid-template-rows`. If `--dur` in
     app.css changes, this has to change with it — the cost of not measuring layout. */
  var PANEL_MS = 240;
  var openRow = null;

  function panelOf(row) {
    return row.querySelector(':scope > .detail');
  }

  function collapse(row) {
    var panel = panelOf(row);
    if (!panel) return;
    var btn = row.querySelector('.row-toggle');
    row.classList.remove('is-open');
    if (btn) btn.setAttribute('aria-expanded', 'false');
    panel.classList.remove('is-open');
    /* `hidden` is `display: none`, which cannot be animated, so it goes on after the
       collapse has run. A timer rather than `transitionend`: under
       prefers-reduced-motion the stylesheet kills every transition and the event never
       fires, which would leave a collapsed panel in the tab order forever. */
    window.clearTimeout(panel.closeTimer);
    panel.closeTimer = window.setTimeout(function () {
      panel.hidden = true;
    }, PANEL_MS);
  }

  function expand(row) {
    var panel = panelOf(row);
    if (!panel) return;
    var btn = row.querySelector('.row-toggle');
    window.clearTimeout(panel.closeTimer);
    panel.hidden = false;
    row.classList.add('is-open');
    if (btn) btn.setAttribute('aria-expanded', 'true');
    /* Two frames. The panel has to have been laid out at 0fr before the class that takes
       it to 1fr, or there is nothing to transition from and it appears instantly. */
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        panel.classList.add('is-open');
      });
    });
  }

  function toggleRow(row) {
    var wasOpen = row.classList.contains('is-open');
    if (openRow && openRow !== row) collapse(openRow);
    if (wasOpen) {
      collapse(row);
      openRow = null;
      return;
    }
    expand(row);
    openRow = row;
  }

  document.addEventListener('click', function (event) {
    /* Inside an open panel is not a click on the row. Without this the Query button
       closes the panel it lives in. */
    if (event.target.closest('.detail')) return;

    var row = event.target.closest('.rows > .row');
    if (!row) return;

    /* Anything that already does something keeps doing it: a link, a sort header, a
       sparkline bar that shows its own timestamp on focus. The chevron is the exception,
       because opening the row is exactly what it is for. */
    if (
      event.target.closest('a, input, select, [tabindex], button') &&
      !event.target.closest('.row-toggle')
    ) {
      return;
    }

    /* Selecting a hostname to copy it ends in a click. Dragging across text should not
       also fold the row away underneath the selection. */
    var selection = window.getSelection();
    if (selection && String(selection).length > 2) return;

    toggleRow(row);
  });

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Escape' || !openRow) return;
    var row = openRow;
    collapse(row);
    openRow = null;
    var btn = row.querySelector('.row-toggle');
    if (btn) btn.focus();
  });


  /* ---------------------------------------------------------------- probe
   *
   * The only place this page talks to a listed host, and only when asked. The request goes
   * from the reader's browser straight to the server — nothing is proxied — so the figure
   * it produces answers a different question from the one in the row: not "is this host
   * up" but "how far is it from me".
   *
   * It is allowed to work at all because the board's `connect-src` names these origins,
   * and because an Epic node's foreign API answers with `access-control-allow-origin: *`.
   * A host that does not is reported as unreachable, which is the honest reading: from
   * this reader's browser, it is.
   */

  var PROBE_MS = 8000;

  function paint(el, parts, cls) {
    el.textContent = '';
    for (var i = 0; i < parts.length; i++) {
      if (i) {
        var sep = document.createElement('i');
        sep.textContent = '·';
        el.appendChild(sep);
      }
      var span = document.createElement(i === 0 ? 'b' : 'span');
      if (i === 0 && cls) span.className = cls;
      span.textContent = parts[i];
      el.appendChild(span);
    }
  }

  function probeNode(url, done) {
    var started = performance.now();
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = window.setTimeout(function () {
      if (controller) controller.abort();
    }, PROBE_MS);

    fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"jsonrpc":"2.0","id":1,"method":"get_tip","params":[]}',
      mode: 'cors',
      cache: 'no-store',
      /* The reader's address is unavoidable — it is their request. Which page they came
         from is not, so it is not sent. */
      referrer: '',
      referrerPolicy: 'no-referrer',
      signal: controller ? controller.signal : undefined
    })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function (data) {
        var ms = Math.round(performance.now() - started);
        var tip = data && data.result && data.result.Ok;
        if (!tip || tip.height === undefined) throw new Error('unexpected answer');
        window.clearTimeout(timer);
        done(null, [
          'Reachable',
          'answered in ' + fmtMs(ms),
          'at tip height ' + fmtNum(tip.height)
        ]);
      })
      .catch(function (error) {
        window.clearTimeout(timer);
        done(error);
      });
  }

  function probeRelay(url, done) {
    var started = performance.now();
    var socket;
    try {
      socket = new WebSocket(url);
    } catch (error) {
      done(error);
      return;
    }
    var settled = false;
    var opened = null;

    function finish(error, parts) {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      try {
        socket.close();
      } catch (ignored) {
        /* Already closing. */
      }
      done(error, parts);
    }

    var timer = window.setTimeout(function () {
      /* A relay that completed the handshake and then said nothing is a different fact
         from one that never answered, and the handshake time is still a real measurement. */
      if (opened !== null) {
        finish(null, [
          'Port open',
          'connected in ' + fmtMs(opened),
          'but sent no challenge'
        ]);
      } else finish(new Error('timeout'));
    }, PROBE_MS);

    socket.onopen = function () {
      opened = Math.round(performance.now() - started);
    };

    /* The first frame a relay sends is its challenge, so one message is proof the
       protocol is alive rather than just the port being open. */
    socket.onmessage = function (event) {
      var ms = Math.round(performance.now() - started);
      var type = '';
      try {
        type = String((JSON.parse(event.data) || {}).type || '').toLowerCase();
      } catch (ignored) {
        /* A frame this page cannot parse is still a frame. */
      }
      finish(null, [
        'Relay alive',
        'handshake in ' + fmtMs(ms),
        type ? 'sent its ' + type + ' frame' : 'sent a frame'
      ]);
    };

    socket.onerror = function () {
      finish(new Error('refused'));
    };
  }

  function probePool(url, done) {
    var started = performance.now();
    var controller = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = window.setTimeout(function () {
      if (controller) controller.abort();
    }, PROBE_MS);

    /* Latency only. Reading miners out of the payload would mean shipping every pool's
       envelope shape to the browser, and the row already carries that number from a
       prober that knows which shape to expect. */
    fetch(url, {
      mode: 'cors',
      cache: 'no-store',
      referrer: '',
      referrerPolicy: 'no-referrer',
      signal: controller ? controller.signal : undefined
    })
      .then(function (response) {
        window.clearTimeout(timer);
        var ms = Math.round(performance.now() - started);
        if (!response.ok) throw new Error('HTTP ' + response.status);
        done(null, [
          'Reachable',
          'answered in ' + fmtMs(ms),
          'stats endpoint served'
        ]);
      })
      .catch(function (error) {
        window.clearTimeout(timer);
        done(error);
      });
  }

  /* Each message leads with a verdict and then says why, because the reader clicked a
     button labelled "Check connection" and the first thing they want is the answer to
     that question. The detail after it is what makes the verdict checkable. */
  function reason(error) {
    var name = error && error.name;
    var message = error && error.message;
    if (name === 'AbortError' || message === 'timeout') {
      return 'No answer — gave up after ' + Math.round(PROBE_MS / 1000) + ' s';
    }
    if (message && message.indexOf('HTTP ') === 0) {
      return 'Reachable, but refused the request with ' + message.toLowerCase();
    }
    if (message === 'unexpected answer') return 'Answered, but not with a chain tip';
    /* A cross-origin block and a dead host are the same TypeError by design — the browser
       will not say which, so neither will this. Both are true from here, which is what the
       reader asked about. */
    return 'No answer — blocked or unreachable from your network';
  }

  document.addEventListener('click', function (event) {
    var button = event.target.closest('.d-go');
    if (!button) return;
    var box = button.closest('.d-probe');
    var out = box.querySelector('.d-out');
    var url = box.getAttribute('data-probe');
    var kind = box.getAttribute('data-kind');

    button.disabled = true;
    paint(out, ['Checking…'], null);

    var probe = kind === 'epicbox' ? probeRelay : kind === 'pool' ? probePool : probeNode;
    probe(url, function (error, parts) {
      button.disabled = false;
      button.textContent = 'Check again';
      if (error) paint(out, [reason(error)], 'd-bad');
      else paint(out, parts, 'd-ok');
    });
  });


  /* ---------------------------------------------------------- group folds
   *
   * Relays and pools fold on a phone, and only when there is nothing in them to see: every
   * host online. The heading becomes a button here rather than in the template so that a
   * desktop, and a phone with JavaScript off, get a plain heading over an open group —
   * the correct page, with nothing inert in it pretending to be a control.
   *
   * A fault opens its group: the poll re-checks after every update. A reader who opened a
   * group by hand is never folded back on them; folding only happens on load and on
   * narrowing the window.
   */
  var NARROW = window.matchMedia ? window.matchMedia('(max-width: 899px)') : null;
  var CHEV =
    '<svg class="chev" width="11" height="7" viewBox="0 0 11 7" aria-hidden="true" fill="none"' +
    ' stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M1.2 1.6 5.5 5.5 9.8 1.6" /></svg>';
  var foldGroups = [].slice.call(document.querySelectorAll('.group[data-fold]'));

  function isNarrow() {
    return !!(NARROW && NARROW.matches);
  }

  function groupCalm(group) {
    return !!group.querySelector('.row') && !group.querySelector('.row:not(.state-healthy)');
  }

  function foldButton(group) {
    var h2 = group.querySelector('.group-head h2');
    var body = group.querySelector('.group-body');
    if (!h2 || !body) return null;
    var btn = h2.querySelector('.group-fold');
    if (btn) return btn;
    btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'group-fold';
    btn.setAttribute('aria-expanded', 'true');
    btn.setAttribute('aria-controls', body.id);
    while (h2.firstChild) btn.appendChild(h2.firstChild);
    /* A constant, not data: the only markup this file ever builds from a string. */
    btn.insertAdjacentHTML('beforeend', CHEV);
    h2.appendChild(btn);
    btn.addEventListener('click', function () {
      setFold(group, btn.getAttribute('aria-expanded') === 'true');
    });
    return btn;
  }

  function unwrapFold(group) {
    var btn = group.querySelector('.group-fold');
    if (!btn) return;
    var h2 = btn.parentNode;
    var chev = btn.querySelector('.chev');
    if (chev) btn.removeChild(chev);
    while (btn.firstChild) h2.insertBefore(btn.firstChild, btn);
    h2.removeChild(btn);
  }

  function setFold(group, folded) {
    var btn = foldButton(group);
    var body = group.querySelector('.group-body');
    if (!btn || !body) return;
    btn.setAttribute('aria-expanded', folded ? 'false' : 'true');
    body.hidden = folded;
    group.classList.toggle('is-folded', folded);
    if (folded && openRow && group.contains(openRow)) {
      collapse(openRow);
      openRow = null;
    }
  }

  function arrangeFolds() {
    for (var i = 0; i < foldGroups.length; i++) {
      var group = foldGroups[i];
      if (isNarrow()) {
        foldButton(group);
        setFold(group, groupCalm(group));
      } else {
        setFold(group, false);
        unwrapFold(group);
        group.classList.remove('is-folded');
      }
    }
  }

  /* After every poll: a group with a fault in it opens. Never the other way. */
  function openTroubledGroups() {
    for (var i = 0; i < foldGroups.length; i++) {
      var group = foldGroups[i];
      if (group.classList.contains('is-folded') && !groupCalm(group)) setFold(group, false);
    }
  }

  /* Tapping anywhere on a folded heading line is a tap on its button — the count beside
     the title is part of the same target on a phone. Links keep being links. */
  document.addEventListener('click', function (event) {
    if (!isNarrow()) return;
    var head = event.target.closest('.group[data-fold] .group-head');
    if (!head || event.target.closest('a, button')) return;
    var btn = head.querySelector('.group-fold');
    if (btn) btn.click();
  });

  arrangeFolds();
  if (NARROW) {
    var onWidth = function () {
      arrangeFolds();
    };
    if (NARROW.addEventListener) NARROW.addEventListener('change', onWidth);
    else if (NARROW.addListener) NARROW.addListener(onWidth);
  }

  /* The count in each group's heading, kept in step with the rows under it. */
  function setSum(key, healthy, total) {
    var el = document.querySelector('[data-sum="' + key + '"]');
    if (!el || healthy === null || healthy === undefined) return;
    var b = el.querySelector('b');
    if (b) b.textContent = String(healthy);
    var known = parseInt(el.getAttribute('data-total'), 10);
    var of = total !== null && total !== undefined ? total : known;
    el.classList.toggle('is-short', healthy < of);
  }


  /* ---------------------------------------------------------- quick check
   *
   * The form posts to /check and works without any of this: the server renders the whole
   * board again with the box open. Here the same post asks for only the result fragment,
   * which the server renders from the same template, and the box opens around it. Nothing
   * is formatted twice, and nothing from the response is built into markup here — the
   * fragment arrives already escaped by the template engine that wrote the page.
   *
   * Escape closes the result and keeps the address, so it can be corrected and checked
   * again; the × closes it and clears the address. Neither reaches the row-panel handler
   * further up, which would otherwise fold a row away under the same key press.
   */
  var QC_MS = 260;

  (function (box) {
    if (!box) return;
    var form = box.querySelector('.qc-form');
    var input = box.querySelector('.qc-input');
    var go = box.querySelector('.qc-go');
    var result = box.querySelector('.qc-result');
    var inner = box.querySelector('.qc-result-in');
    var close = box.querySelector('.qc-close');
    if (!form || !input || !result || !inner) return;
    var busy = false;
    var timer = 0;

    function reveal() {
      window.clearTimeout(timer);
      result.hidden = false;
      box.classList.add('is-open');
      if (close) close.hidden = false;
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          result.classList.add('is-open');
          /* On a phone the result can open below the fold. Bring its top edge into view,
             no further — the field the reader typed into should stay on screen too. */
          var rect = result.getBoundingClientRect();
          if (rect.bottom > window.innerHeight) {
            result.scrollIntoView({ block: 'nearest', behavior: prefersStill() ? 'auto' : 'smooth' });
          }
        });
      });
    }

    function shut(clear) {
      result.classList.remove('is-open');
      box.classList.remove('is-open');
      if (close) close.hidden = true;
      window.clearTimeout(timer);
      timer = window.setTimeout(function () {
        result.hidden = true;
        inner.textContent = '';
      }, QC_MS);
      if (clear) {
        input.value = '';
        input.removeAttribute('aria-invalid');
      }
      input.focus();
    }

    /* Only for failures that never reached the server, so there is no fragment to show.
       Built with textContent, like every other message this file writes. */
    function localMessage(tone, text) {
      var out = document.createElement('div');
      out.className = 'qc-out tone-' + tone;
      var p = document.createElement('p');
      p.className = 'qc-verdict';
      var dot = document.createElement('span');
      dot.className = 'dot qc-dot';
      dot.setAttribute('aria-hidden', 'true');
      var line = document.createElement('b');
      line.className = 'qc-headline';
      line.textContent = text;
      p.appendChild(dot);
      p.appendChild(line);
      out.appendChild(p);
      return out;
    }

    function show(content) {
      inner.textContent = '';
      if (typeof content === 'string') inner.innerHTML = content;
      else inner.appendChild(content);
      var out = inner.querySelector('.qc-out');
      if (out && out.getAttribute('data-error') === 'input') input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
      reveal();
    }

    function setBusy(on) {
      busy = on;
      box.classList.toggle('is-busy', on);
      if (on) box.setAttribute('aria-busy', 'true');
      else box.removeAttribute('aria-busy');
      /* aria-disabled, not disabled: disabling the button that has focus throws focus to
         the document body, and a keyboard user would land at the top of the page. */
      if (go) go.setAttribute('aria-disabled', on ? 'true' : 'false');
    }

    function run(address, defaults) {
      if (busy) return;
      address = (address || '').trim();
      if (!address) {
        show(localMessage('info', 'Paste a node address first — a hostname or an IP, with or without a port.'));
        input.setAttribute('aria-invalid', 'true');
        input.focus();
        return;
      }
      var body = new URLSearchParams();
      body.set('address', address);
      if (defaults) body.set('defaults', '1');
      var chainField = form.querySelector('input[name="chain"]');
      if (chainField) body.set('chain', chainField.value);
      setBusy(true);
      fetch('/check', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
          accept: 'text/html',
          'x-quickcheck': 'fragment'
        },
        body: body.toString()
      })
        .then(function (response) {
          /* 429 carries a rendered result too: the rate-limit message is an answer. */
          if (!response.ok && response.status !== 429) throw new Error('HTTP ' + response.status);
          return response.text();
        })
        .then(function (html) {
          setBusy(false);
          show(html);
        })
        .catch(function () {
          setBusy(false);
          show(localMessage('info', 'This page could not reach its own server. Check your connection and try again.'));
        });
    }

    box.addEventListener('submit', function (event) {
      event.preventDefault();
      var target = event.target;
      if (target.classList.contains('qc-retry')) {
        var hidden = target.querySelector('input[name="address"]');
        run(hidden ? hidden.value : input.value, true);
        return;
      }
      run(input.value, false);
    });

    if (close) {
      close.addEventListener('click', function (event) {
        event.preventDefault();
        shut(true);
      });
    }

    input.addEventListener('input', function () {
      input.removeAttribute('aria-invalid');
    });

    box.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') return;
      event.stopPropagation();
      if (box.classList.contains('is-open')) shut(false);
      else if (input.value) input.value = '';
    });

    /* "On this board": go to the row and open it, unfolding its group first. */
    box.addEventListener('click', function (event) {
      var link = event.target.closest('[data-qc-listed]');
      if (!link) return;
      var row = document.getElementById('row-' + link.getAttribute('data-qc-listed'));
      if (!row) return;
      event.preventDefault();
      var group = row.closest('.group[data-fold]');
      if (group && group.classList.contains('is-folded')) setFold(group, false);
      if (!row.classList.contains('is-open')) toggleRow(row);
      row.scrollIntoView({ block: 'start', behavior: prefersStill() ? 'auto' : 'smooth' });
      var toggle = row.querySelector('.row-toggle');
      if (toggle) toggle.focus({ preventScroll: true });
    });

    /* The server rendered a result into the page (the no-JavaScript path, or a reload of
       one): its region is already open; the close control just needs wiring, done above. */
  })(document.querySelector('[data-qc]'));
})();
