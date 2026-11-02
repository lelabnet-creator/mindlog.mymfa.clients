/*
 * Vue « Tableau de bord » de l'app (#/dashboard).
 *  - Chiffres : comptes 2FA, mots de passe, passkeys, note de santé des mots de passe.
 *  - Usage : activité des 30 derniers jours, tirée de l'historique.
 *  - Santé : mots de passe hors politique, réutilisés, à renouveler, compromis.
 *  - Fuites : Have I Been Pwned (k-anonymat, sur demande) ; Mozilla Monitor et Google Password
 *    Checkup en liens, faute d'API publique.
 *  - Pilotage : politique de complexité et de renouvellement.
 * Politique et résultats de fuite sont des réglages du coffre (Store.setting) : chiffrés, sauvegardés
 * sur Drive et partagés avec l'extension comme le reste.
 * Dépend de : I18n, Store, Vault, Lock, Audit.
 */
(function () {
  'use strict';

  const { t } = I18n;
  const $ = (id) => document.getElementById(id);
  const MONITOR_URL = 'https://monitor.mozilla.org/';
  const CHECKUP_URL = 'https://passwords.google.com/checkup';
  const CONCURRENCY = 4;

  let ctx = null; // { store, toast, errorMessage }
  const state = { checking: false, progress: 0, total: 0, open: null };

  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'value') node.value = value;
      else if (key === 'checked') node.checked = Boolean(value);
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function icon(d) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    for (const part of [].concat(d)) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', part);
      svg.append(path);
    }
    return svg;
  }

  const ICONS = {
    weak: 'M12 9v4M12 17h.01M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
    reused: ['M17 2l4 4-4 4', 'M3 11V9a3 3 0 0 1 3-3h15', 'M7 22l-4-4 4-4', 'M21 13v2a3 3 0 0 1-3 3H3'],
    expired: ['M12 7v5l3 2', 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z'],
    pwned: ['M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6z', 'M12 8v4M12 16h.01'],
    open: 'M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
    chevron: 'm9 6 6 6-6 6',
  };

  const policy = () => Audit.normalizePolicy(ctx.store.setting('policy'));
  const savedBreaches = () => ctx.store.setting('breaches') || null;
  const number = (n) => new Intl.NumberFormat(I18n.getLocale()).format(n);

  function analysis() {
    const store = ctx.store;
    const unlocked = Lock.status() === 'unlocked';
    const logins = unlocked ? store.logins() : [];
    return Audit.analyze(
      {
        accounts: store.list(),
        logins,
        passkeys: unlocked ? store.passkeys() : [],
        history: store.history(),
      },
      policy(),
      { strength: Vault.passwordStrength, matchesHost: Store.accountMatchesHost, hostOf: Store.hostOf, breaches: Audit.savedBreaches(savedBreaches(), logins) }
    );
  }

  /* ───────────── Rendu ───────────── */

  function render() {
    const root = $('dashboard');
    if (!ctx || !root || Lock.isLocked()) return;
    const a = analysis();
    const unlocked = Lock.status() === 'unlocked';
    root.replaceChildren(
      tiles(a),
      usagePanel(a.usage),
      unlocked ? healthPanel(a) : h('section', { class: 'dash-section' }, [
        h('h2', { class: 'section-label', text: t('dashboard.health') }),
        h('div', { class: 'panel dash-panel' }, [
          h('p', { class: 'panel-hint', text: t('dashboard.plainHint') }),
          h('button', { type: 'button', class: 'btn btn-primary btn-sm', onclick: () => Lock.openEnable(), text: t('dashboard.enable') }),
        ]),
      ]),
      unlocked ? breachPanel(a) : null,
      policyPanel()
    );
  }

  function tile(label, value, sub, tone) {
    return h('div', { class: `panel dash-tile${tone ? ` tone-${tone}` : ''}` }, [
      h('span', { class: 'dash-tile-label', text: label }),
      h('span', { class: 'dash-tile-value', text: value }),
      sub ? h('span', { class: 'dash-tile-sub', text: sub }) : null,
    ]);
  }

  function tiles(a) {
    const scoreTone = a.score === null ? '' : a.score >= 80 ? 'good' : a.score >= 50 ? 'warn' : 'bad';
    return h('div', { class: 'dash-tiles' }, [
      tile(t('dashboard.tiles.accounts'), number(a.counts.accounts), t('dashboard.tiles.tags', { count: a.counts.tags })),
      tile(t('dashboard.tiles.logins'), number(a.counts.logins), a.counts.logins ? t('dashboard.tiles.with2fa', { count: a.counts.with2fa, total: a.counts.logins }) : null),
      tile(t('dashboard.tiles.passkeys'), number(a.counts.passkeys)),
      tile(t('dashboard.tiles.score'), a.score === null ? '—' : `${a.score}`, a.score === null ? t('dashboard.tiles.scoreNone') : t('dashboard.tiles.scoreSub', { count: a.atRisk.length }), scoreTone),
    ]);
  }

  /** Une barre par jour ; survol ou focus : le jour et son nombre d'événements. */
  function usagePanel(u) {
    const max = Math.max(1, ...u.perDay.map((d) => d.count));
    const dayFormat = new Intl.DateTimeFormat(I18n.getLocale(), { day: 'numeric', month: 'short' });
    const bars = u.perDay.map((d) => {
      const label = t('dashboard.usage.day', { date: dayFormat.format(d.date), count: d.count });
      const bar = h('span', { class: 'dash-bar', role: 'listitem', tabindex: '0', title: label, 'aria-label': label }, [h('span', { class: 'dash-bar-fill' })]);
      // CSSOM, pas d'attribut style : la CSP (style-src 'self') bloque les styles en ligne.
      bar.firstChild.style.setProperty('--h', String(d.count / max));
      if (!d.count) bar.classList.add('is-empty');
      return bar;
    });
    const actions = Object.entries(u.byAction).sort((x, y) => y[1] - x[1]);
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('dashboard.usage.title') }),
      h('div', { class: 'panel dash-panel' }, [
        h('div', { class: 'dash-usage-head' }, [
          h('span', { class: 'dash-usage-total', text: t('dashboard.usage.total', { count: u.total }) }),
          h('span', { class: 'panel-hint', text: t('dashboard.usage.copies', { count: u.copies }) }),
        ]),
        u.total
          ? h('div', { class: 'dash-chart' }, [
              h('div', { class: 'dash-bars', role: 'list', 'aria-label': t('dashboard.usage.chart') }, bars),
              h('div', { class: 'dash-axis', 'aria-hidden': 'true' }, [
                h('span', { text: dayFormat.format(u.perDay[0].date) }),
                h('span', { text: t('dashboard.usage.today') }),
              ]),
            ])
          : h('p', { class: 'panel-hint', text: t('dashboard.usage.empty') }),
        actions.length
          ? h('ul', { class: 'dash-actions' }, actions.map(([action, count]) => h('li', {}, [h('span', { text: t(`activity.verb.${action}`) }), h('b', { text: number(count) })])))
          : null,
      ]),
    ]);
  }

  /** Une ligne par problème ; dépliée, la liste des sites concernés, vers leur fiche. */
  function healthPanel(a) {
    const p = policy();
    const rows = [
      { key: 'weak', items: a.weak, detail: (i) => i.issues.map((r) => t(`dashboard.rule.${r}`, { min: p.minLength, level: t(`security.strength.${p.minStrength}`) })).join(' · ') },
      { key: 'reused', items: a.reused, detail: () => t('dashboard.reusedDetail') },
      { key: 'expired', items: a.expired, detail: (i) => t('dashboard.age', { count: i.age }), off: p.maxAgeDays === 0 },
      { key: 'pwned', items: a.pwned, detail: (i) => t('dashboard.pwnedDetail', { count: number(i.pwned) }), pending: a.checked < a.counts.logins },
    ];
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('dashboard.health') }),
      h('div', { class: 'panel panel-list' }, rows.map((row) => healthRow(row))),
      a.counts.logins ? null : h('p', { class: 'panel-hint', text: t('dashboard.noLogins') }),
    ]);
  }

  function healthRow({ key, items, detail, off, pending }) {
    const count = items.length;
    const status = off ? t('dashboard.off') : count ? number(count) : pending && key === 'pwned' ? t('dashboard.unchecked') : t('dashboard.none');
    const open = state.open === key && count > 0;
    const head = h('button', {
      type: 'button',
      class: `row dash-row${count ? ' has-issues' : ''}`,
      'aria-expanded': count ? String(open) : null,
      disabled: !count,
      onclick: () => {
        state.open = open ? null : key;
        render();
      },
    }, [
      h('span', { class: `dash-row-icon kind-${count ? (key === 'pwned' || key === 'weak' ? 'delete' : 'update') : 'create'}` }, [icon(ICONS[key])]),
      h('span', { class: 'row-main' }, [h('span', { text: t(`dashboard.issue.${key}`) }), h('small', { text: t(`dashboard.issue.${key}Text`) })]),
      h('span', { class: 'dash-row-count', text: status }),
      count ? icon(ICONS.chevron) : null,
    ]);
    if (!open) return head;
    const list = h('ul', { class: 'dash-sites' }, items.map((i) =>
      h('li', {}, [
        h('a', { href: `#/passwords/${i.login.id}` }, [
          h('span', { class: 'dash-site-name', text: i.login.title || Store.siteOf(i.host) }),
          h('span', { class: 'dash-site-sub', text: [i.login.username, detail(i)].filter(Boolean).join(' — ') }),
        ]),
      ])
    ));
    return h('div', { class: 'dash-row-wrap' }, [head, list]);
  }

  function breachPanel(a) {
    const logins = a.counts.logins;
    const button = h('button', {
      type: 'button',
      class: 'btn btn-primary btn-sm',
      disabled: state.checking || !logins,
      onclick: checkBreaches,
      text: state.checking ? t('dashboard.breach.checking', { done: state.progress, total: state.total }) : t('dashboard.breach.check'),
    });
    const progress = state.checking ? h('progress', { max: String(state.total), value: String(state.progress), class: 'dash-progress' }) : null;
    const timeFormat = new Intl.DateTimeFormat(I18n.getLocale(), { dateStyle: 'medium', timeStyle: 'short' });
    const saved = savedBreaches();
    const status = saved && saved.checkedAt && !state.checking
      ? t('dashboard.breach.done', { time: timeFormat.format(new Date(saved.checkedAt)), count: a.pwned.length })
      : t('dashboard.breach.never');
    const external = (url, nameKey, textKey) =>
      h('a', { class: 'row dash-ext', href: url, target: '_blank', rel: 'noopener noreferrer' }, [
        h('span', { class: 'row-main' }, [h('span', { text: t(nameKey) }), h('small', { text: t(textKey) })]),
        icon(ICONS.open),
      ]);
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('dashboard.breach.title') }),
      h('div', { class: 'panel dash-panel' }, [
        h('div', { class: 'dash-breach-head' }, [
          h('span', { class: 'row-main' }, [h('b', { text: 'Have I Been Pwned' }), h('small', { class: 'panel-hint', text: t('dashboard.breach.hibpText') })]),
          button,
        ]),
        progress,
        h('p', { class: 'panel-hint', role: 'status', text: status }),
      ]),
      h('div', { class: 'panel panel-list' }, [
        external(MONITOR_URL, 'dashboard.breach.monitor', 'dashboard.breach.monitorText'),
        external(CHECKUP_URL, 'dashboard.breach.checkup', 'dashboard.breach.checkupText'),
      ]),
    ]);
  }

  function policyPanel() {
    const p = policy();
    const save = (patch) => {
      try {
        ctx.store.setSetting('policy', Audit.normalizePolicy({ ...p, ...patch }));
      } catch (err) {
        ctx.toast(ctx.errorMessage(err));
      }
      render();
    };
    const toggle = (key) =>
      h('label', { class: 'gen-chip' }, [
        h('input', { type: 'checkbox', checked: p[key], onchange: (event) => save({ [key]: event.target.checked }) }),
        h('span', { text: t(`dashboard.policy.${key}`) }),
      ]);
    const lengthValue = h('span', { class: 'gen-value', text: String(p.minLength) });
    const range = h('input', { type: 'range', class: 'gen-range', min: '8', max: '32', value: String(p.minLength), 'aria-label': t('dashboard.policy.minLength') });
    range.addEventListener('input', () => (lengthValue.textContent = range.value));
    range.addEventListener('change', () => save({ minLength: Number(range.value) }));
    const select = (labelKey, value, options, key) =>
      h('label', { class: 'row' }, [
        h('span', { class: 'row-main', text: t(labelKey) }),
        h('select', { class: 'row-select', onchange: (event) => save({ [key]: Number(event.target.value) }) },
          options.map(([v, label]) => {
            const option = h('option', { value: String(v), text: label });
            option.selected = v === value;
            return option;
          })),
        icon(ICONS.chevron),
      ]);
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('dashboard.policy.title') }),
      h('div', { class: 'panel dash-panel' }, [
        h('label', { class: 'gen-length' }, [h('span', { class: 'gen-label', text: t('dashboard.policy.minLength') }), range, lengthValue]),
        h('div', { class: 'gen-options' }, [toggle('upper'), toggle('digits'), toggle('symbols')]),
      ]),
      h('div', { class: 'panel panel-list' }, [
        select('dashboard.policy.minStrength', p.minStrength, [1, 2, 3, 4].map((n) => [n, t(`security.strength.${n}`)]), 'minStrength'),
        select('dashboard.policy.maxAge', p.maxAgeDays, Audit.MAX_AGES.map((n) => [n, n ? t('dashboard.policy.days', { count: n }) : t('dashboard.policy.never')]), 'maxAgeDays'),
      ]),
      h('p', { class: 'panel-hint', text: t('dashboard.policy.hint') }),
    ]);
  }

  /* ───────────── Fuites ───────────── */

  /** Chaque mot de passe distinct est vérifié une fois ; seul le préfixe de son empreinte part. */
  async function checkBreaches() {
    if (state.checking || Lock.status() !== 'unlocked') return;
    const logins = ctx.store.logins();
    const groups = new Map();
    for (const login of logins) {
      const ids = groups.get(login.password) || [];
      ids.push(login.id);
      groups.set(login.password, ids);
    }
    const queue = [...groups.entries()];
    state.checking = true;
    state.progress = 0;
    state.total = queue.length;
    render();
    const results = new Map();
    let failed = null;
    const worker = async () => {
      while (queue.length && !failed) {
        const [password, ids] = queue.shift();
        try {
          const count = await Audit.pwnedCount(password, fetch.bind(window));
          for (const id of ids) results.set(id, count);
        } catch (err) {
          failed = err;
        }
        state.progress += 1;
        if (state.checking) render();
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    if (!state.checking) return; // verrouillé entre-temps : rien ne reste
    state.checking = false;
    if (failed) {
      ctx.toast(t('error.pwnedUnavailable'));
    } else {
      ctx.store.setSetting('breaches', Audit.breachRecord(results, logins, new Date().toISOString()));
      ctx.store.log('security', null, { event: 'breachCheck' });
      const pwned = [...results.values()].filter((n) => n > 0).length;
      ctx.toast(pwned ? t('dashboard.breach.found', { count: pwned }) : t('dashboard.breach.clean'));
      if (pwned) state.open = 'pwned';
    }
    render();
  }

  /* ───────────── Cycle de vie ───────────── */

  function init(options) {
    ctx = options;
    I18n.onChange(render);
  }

  /** Verrouillage : plus rien à l'écran ; une vérification en cours s'arrête là. */
  function reset() {
    state.checking = false;
    state.open = null;
    if ($('dashboard')) $('dashboard').replaceChildren();
  }

  window.Dashboard = { init, render, reset };
})();
