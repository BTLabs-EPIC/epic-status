/* The review dashboard, without page reloads.
 *
 * Every control here writes one field and reports back in place. The form POSTs it replaces
 * are still in the markup and still work, so with JavaScript off the page degrades to
 * ordinary forms — worth the duplication on the one surface that edits the board.
 *
 * When to save, per control, following the pattern the field actually is:
 *
 *   checkbox, tag      immediately on click. There is no half-ticked state to debounce.
 *   text field         on blur, on Enter, or 900ms after typing stops — whichever comes
 *                      first. Escape reverts to the last saved value.
 *   remove             two-step in place. No modal: a dialog here would trap focus and
 *                      move the page, which is what this rewrite exists to stop.
 *
 * The text rule is the one worth defending. Saving on every keystroke writes a row per
 * character; saving only on blur loses work when a tab is closed mid-edit; so both, which is
 * what GitLab's design spec and the autosave literature converge on. 900ms is long enough
 * that a two-finger typist is not saving between words and short enough that the save has
 * landed before attention moves.
 *
 * One toast, ever. Rapid changes replace its text rather than stacking, because a column of
 * five "Saved" cards is noise about something that went right.
 */
(function () {
  'use strict';

  var root = document.querySelector('[data-admin]');
  if (!root) return;

  var CSRF = root.getAttribute('data-csrf');
  var SAVE_DELAY_MS = 900;

  /* ------------------------------------------------------------------ toast */

  var toast = document.getElementById('toast');
  var toastTimer = null;

  function notify(message, tone) {
    if (!toast) return;
    toast.textContent = message;
    toast.setAttribute('data-tone', tone || 'ok');
    toast.setAttribute('data-open', '1');
    /* Restarting the timer rather than queueing: the newest outcome is the one worth
       showing, and a queue would keep announcing saves the user has moved on from. */
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () {
      toast.removeAttribute('data-open');
    }, tone === 'bad' ? 6000 : 2400);
  }

  /* ------------------------------------------------------------------- post */

  function post(url, body) {
    var data = new URLSearchParams(body);
    data.set('csrf', CSRF);
    return fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: data.toString(),
      /* The session cookie is Path=/admin and SameSite=Strict; same-origin is what it
         needs and nothing wider. */
      credentials: 'same-origin',
    })
      .then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok || !j.ok) throw new Error(j.error || 'HTTP ' + r.status);
          return j;
        });
      });
  }

  /* --------------------------------------------------------------- field save */

  function flash(el, state) {
    el.setAttribute('data-state', state);
    if (state === 'saved') {
      setTimeout(function () {
        if (el.getAttribute('data-state') === 'saved') el.removeAttribute('data-state');
      }, 1200);
    }
  }

  function saveField(input) {
    var rec = input.closest('[data-target-id]');
    if (!rec) return Promise.resolve();
    var field = input.getAttribute('data-field-name');
    var value = input.type === 'checkbox' ? (input.checked ? '1' : '0') : input.value;
    if (input.getAttribute('data-last') === value) return Promise.resolve();

    flash(input, 'saving');
    return post('/admin/api/patch', {
      target_id: rec.getAttribute('data-target-id'),
      field: field,
      value: value,
    })
      .then(function (j) {
        /* Show what was stored, not what was typed: the server trims, and uppercases a
           country code. Writing the response back means the field cannot disagree with the
           database. */
        if (input.type !== 'checkbox' && typeof j.value === 'string') input.value = j.value;
        input.setAttribute('data-last', input.type === 'checkbox' ? value : input.value);
        flash(input, 'saved');
        syncTags(rec, j);
        notify(j.host + ' · ' + label(field) + ' saved');
      })
      .catch(function (e) {
        flash(input, 'failed');
        notify('Not saved: ' + e.message, 'bad');
      });
  }

  function label(field) {
    return {
      operator: 'operator',
      label: 'label',
      notes: 'notes',
      country: 'country',
      provider: 'hosting',
      city: 'city',
      verified: 'listing',
      enabled: 'checking',
    }[field] || field;
  }

  /* Keep the tags beside the hostname agreeing with the checkboxes, whichever one was used
     to make the change. They are two views of the same two booleans. */
  function syncTags(rec, j) {
    var listing = rec.querySelector('[data-tag="verified"]');
    if (listing && typeof j.listing === 'string') {
      listing.textContent = j.listing;
      listing.setAttribute('aria-pressed', j.verified ? 'true' : 'false');
      listing.className = 'badge badge-tag' + (j.verified ? ' badge-accepted' : '');
    }
    var checking = rec.querySelector('[data-tag="enabled"]');
    if (checking && typeof j.enabled === 'boolean') {
      checking.textContent = j.enabled ? 'checked' : 'not checked';
      checking.setAttribute('aria-pressed', j.enabled ? 'true' : 'false');
      checking.className = 'badge badge-tag' + (j.enabled ? '' : ' badge-rejected');
      rec.classList.toggle('rec-off', !j.enabled);
    }
    /* There are no checkboxes to mirror any more: the tags are the control. Kept as one
       function because the tag text, its pressed state and the row's dimming all follow from
       the same two booleans. */
  }

  /* ------------------------------------------------------------------ wiring */

  var timers = new WeakMap();

  root.addEventListener('input', function (e) {
    var input = e.target.closest('input[data-field-name]');
    if (!input || input.type === 'checkbox') return;
    flash(input, 'dirty');
    if (timers.get(input)) clearTimeout(timers.get(input));
    timers.set(input, setTimeout(function () {
      saveField(input);
    }, SAVE_DELAY_MS));
  });

  root.addEventListener('change', function (e) {
    var input = e.target.closest('input[data-field-name], select[data-field-name]');
    if (!input) return;
    /* Checkboxes and selects have no intermediate state: a change is a decision. */
    if (input.type === 'checkbox' || input.tagName === 'SELECT') {
      if (timers.get(input)) clearTimeout(timers.get(input));
      saveField(input);
    }
  });

  root.addEventListener('focusout', function (e) {
    var input = e.target.closest('input[data-field-name]');
    if (!input || input.type === 'checkbox') return;
    if (timers.get(input)) clearTimeout(timers.get(input));
    saveField(input);
  });

  root.addEventListener('keydown', function (e) {
    var input = e.target.closest('input[data-field-name]');
    if (!input) return;
    if (e.key === 'Enter') {
      e.preventDefault();
      if (timers.get(input)) clearTimeout(timers.get(input));
      saveField(input).then(function () {
        input.blur();
      });
    }
    if (e.key === 'Escape') {
      /* Back to the last value the server confirmed, which is the only value worth
         reverting to — the initial render is stale the moment anything else saved. */
      input.value = input.getAttribute('data-last') || '';
      if (timers.get(input)) clearTimeout(timers.get(input));
      input.removeAttribute('data-state');
      input.blur();
    }
  });

  /* Tags beside the hostname toggle the thing they name. Before this they were decoration
     that looked interactive. */
  root.addEventListener('click', function (e) {
    var tag = e.target.closest('[data-tag]');
    if (tag) {
      /* The tags are submit buttons so they work without JavaScript. With it, the click is
         handled here and the form submit is cancelled. */
      e.preventDefault();
      var rec = tag.closest('[data-target-id]');
      var name = tag.getAttribute('data-tag');
      var now = tag.getAttribute('aria-pressed') === 'true';
      tag.setAttribute('aria-busy', 'true');
      post('/admin/api/patch', {
        target_id: rec.getAttribute('data-target-id'),
        field: name,
        value: now ? '0' : '1',
      })
        .then(function (j) {
          syncTags(rec, j);
          notify(j.host + ' · ' + label(name) + ' saved');
        })
        .catch(function (err) {
          notify('Not saved: ' + err.message, 'bad');
        })
        .finally(function () {
          tag.removeAttribute('aria-busy');
        });
      return;
    }

    /* ---- removal: two steps, in place ---- */
    var ask = e.target.closest('[data-remove]');
    if (ask) {
      e.preventDefault();
      var row = ask.closest('[data-target-id]');
      row.setAttribute('data-confirming', '1');
      return;
    }
    var cancel = e.target.closest('[data-remove-cancel]');
    if (cancel) {
      e.preventDefault();
      cancel.closest('[data-target-id]').removeAttribute('data-confirming');
      return;
    }
    var go = e.target.closest('[data-remove-confirm]');
    if (go) {
      e.preventDefault();
      var target = go.closest('[data-target-id]');
      go.disabled = true;
      post('/admin/api/remove', { target_id: target.getAttribute('data-target-id') })
        .then(function (j) {
          /* Collapse the row where it sits rather than re-rendering the page, so the
             scroll position and every other open field survive. */
          target.setAttribute('data-removed', '1');
          setTimeout(function () {
            target.remove();
          }, 260);
          notify(
            j.returns_on_restart
              ? j.host + ' removed — a seed target, so it returns on restart unless deleted from targets.toml'
              : j.host + ' removed',
            j.returns_on_restart ? 'warn' : 'ok'
          );
        })
        .catch(function (err) {
          go.disabled = false;
          notify('Not removed: ' + err.message, 'bad');
        });
    }
  });

  /* ---- deleting a request ---- */
  root.addEventListener('click', function (e) {
    var del = e.target.closest('[data-req-remove]');
    if (!del) return;
    e.preventDefault();
    var req = del.closest('[data-submission-id]');
    del.disabled = true;
    post('/admin/api/request/remove', {
      submission_id: req.getAttribute('data-submission-id'),
    })
      .then(function (j) {
        req.setAttribute('data-removed', '1');
        setTimeout(function () {
          req.remove();
        }, 260);
        notify('Request for ' + j.host + ' deleted');
      })
      .catch(function (err) {
        del.disabled = false;
        notify('Not deleted: ' + err.message, 'bad');
      });
  });

  /* ---- the request queue, same treatment ---- */
  root.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-decide]');
    if (!btn) return;
    e.preventDefault();
    var req = btn.closest('[data-submission-id]');
    var decision = btn.getAttribute('data-decide');
    btn.disabled = true;
    post('/admin/review/json', {
      submission_id: req.getAttribute('data-submission-id'),
      decision: decision,
    })
      .then(function (j) {
        var badge = req.querySelector('[data-req-status]');
        if (badge) {
          badge.textContent = j.status;
          badge.className = 'badge badge-' + j.status;
        }
        var actions = req.querySelector('.req-act');
        if (actions) actions.remove();
        req.className = 'req req-' + j.status;
        notify(
          j.host + (j.status === 'accepted' ? ' added to the board' : ' rejected')
        );
      })
      .catch(function (err) {
        btn.disabled = false;
        notify('Failed: ' + err.message, 'bad');
      });
  });

  /* Record each field's starting value, so a save is skipped when nothing changed and
     Escape has somewhere to go back to. */
  var fields = root.querySelectorAll('input[data-field-name], select[data-field-name]');
  for (var i = 0; i < fields.length; i++) {
    var f = fields[i];
    f.setAttribute('data-last', f.type === 'checkbox' ? (f.checked ? '1' : '0') : f.value);
  }

  /* The Save buttons are the no-JavaScript path. With JavaScript they are a promise the
     page no longer keeps, so they go — leaving them would imply changes are unsaved until
     clicked, which is the opposite of what now happens. */
  var saves = root.querySelectorAll('[data-save-fallback]');
  for (var k = 0; k < saves.length; k++) saves[k].remove();
})();
