/*
 * Mots de passe des sites (script de contenu, cadre principal).
 *  1. Formulaire de connexion et identifiants connus pour ce site : toast « Se connecter en tant que… »,
 *     un clic remplit identifiant et mot de passe.
 *  2. Connexion ou inscription envoyée : le mot de passe saisi part au service d'arrière-plan (en mémoire),
 *     puis toast « Enregistrer le mot de passe ? », sur la page suivante ou quand le formulaire disparaît.
 *  3. Inscription (ou changement de mot de passe) : toast « Mot de passe fort », généré selon la politique
 *     du site (passwordrules, minlength / maxlength / pattern, texte d'aide du champ — voir Passgen) ;
 *     un clic remplit le mot de passe et sa confirmation. Il est proposé à l'enregistrement à l'envoi (2).
 * Un mot de passe enregistré n'arrive ici qu'au moment de le remplir, sur un vrai clic. Rien sur l'app myMFA
 * elle-même (son mot de passe maître ne doit jamais être capturé).
 */
(() => {
  'use strict';
  if (window.__mymfaPasswords || window.top !== window) return;
  window.__mymfaPasswords = true;

  const { t } = I18n;
  const Ui = MyMfaUi;
  const { el, icon, ICON } = Ui;
  const send = (message) => chrome.runtime.sendMessage(message).catch(() => null);
  if (Ui.isApp()) return;

  /* ═════════════ Champs ═════════════ */

  const ownNode = (node) => {
    const host = Ui.toast.host();
    return Boolean(host && host.contains(node));
  };
  const usable = (input) => Ui.visible(input) && !input.disabled && !ownNode(input);
  const passwordFields = (scope = document) => [...scope.querySelectorAll('input[type="password"]')].filter(usable);
  const USERNAME_HINT = /user|login|email|e-mail|mail|identifi|account|compte|pseudo|nom/i;

  /** Champ identifiant d'un mot de passe : dans le même formulaire, celui qui le précède. */
  function usernameField(password) {
    const scope = password.form || document;
    const inputs = [...scope.querySelectorAll('input')].filter(
      (i) => usable(i) && ['text', 'email', 'tel', ''].includes(i.type) && i.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    const score = (i) =>
      (/username|email/.test(i.autocomplete) ? 10 : 0) + (i.type === 'email' ? 5 : 0) + (USERNAME_HINT.test([i.name, i.id, i.placeholder, i.getAttribute('aria-label')].join(' ')) ? 3 : 0);
    const ranked = inputs.map((i, index) => [i, score(i), index]).sort((a, b) => b[1] - a[1] || b[2] - a[2]);
    return ranked.length ? ranked[0][0] : null;
  }

  /** Mot de passe à retenir dans une zone : le nouveau (inscription, changement) plutôt que l'actuel. */
  function chosenPassword(fields) {
    const filled = fields.filter((f) => f.value);
    if (!filled.length) return null;
    const fresh = filled.filter((f) => f.autocomplete === 'new-password');
    if (fresh.length) return fresh[0];
    // Changement de mot de passe : actuel, nouveau, confirmation → le dernier.
    return filled[filled.length - 1];
  }

  /* ═════════════ Capture ═════════════ */

  let lastSent = '';
  let watching = null;

  function capture(scope) {
    const fields = passwordFields(scope);
    const password = chosenPassword(fields.length ? fields : passwordFields());
    if (!password) {
      // Connexion en deux temps : l'identifiant d'abord, le mot de passe sur l'écran suivant.
      const user = [...(scope.querySelectorAll ? scope.querySelectorAll('input') : [])].find(
        (i) => usable(i) && i.value && (/username|email/.test(i.autocomplete) || i.type === 'email' || USERNAME_HINT.test(`${i.name} ${i.id}`))
      );
      if (user) send({ type: 'content:capture', username: user.value, password: '' });
      return;
    }
    const user = usernameField(password);
    const username = user ? user.value : '';
    const key = `${username}\u0000${password.value}`;
    if (key === lastSent) return;
    lastSent = key;
    send({ type: 'content:capture', username, password: password.value }).then((res) => {
      if (res && (res.action === 'save' || res.action === 'update')) watchDeparture(password);
    });
  }

  /** Page qui ne change pas (application monopage) : on propose quand le formulaire disparaît. */
  function watchDeparture(field) {
    clearInterval(watching);
    const started = Date.now();
    watching = setInterval(() => {
      if (!document.contains(field) || !Ui.visible(field)) {
        clearInterval(watching);
        checkPending();
      } else if (Date.now() - started > 15000) clearInterval(watching);
    }, 500);
  }

  document.addEventListener('submit', (event) => capture(event.target), true);
  document.addEventListener('click', (event) => {
    const button = event.target.closest && event.target.closest('button, input[type="submit"], input[type="button"], [role="button"]');
    if (!button || ownNode(button)) return;
    capture(button.form || button.closest('form') || document);
  }, true);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && event.target instanceof HTMLInputElement && !ownNode(event.target)) {
      capture(event.target.form || document);
    }
  }, true);

  /* ═════════════ Enregistrer ═════════════ */

  const save = { pending: null, status: null, state: 'ask', username: '' };

  async function checkPending() {
    const res = await send({ type: 'content:pendingLogin' });
    if (!res || !res.pending) return;
    save.pending = res.pending;
    save.status = res.status;
    save.username = res.pending.username;
    save.state = res.pending.requested ? stateFor(res.status) : 'ask';
    Ui.toast.open('save', { priority: 30, render: saveView, onClose: (byUser) => byUser && save.state === 'ask' && send({ type: 'content:dismissLogin' }) });
  }

  const stateFor = (status) => (status === 'locked' ? 'locked' : status === 'unlocked' ? 'saved' : 'vault');

  function saveView() {
    const p = save.pending;
    const who = el('div', { class: 'who' }, [
      Ui.tile(p.host),
      el('div', { class: 'who-text' }, [el('span', { class: 'issuer', text: p.host }), el('span', { class: 'account', text: save.username || t('ext.toast.noUsername') })]),
    ]);
    if (save.state === 'saved') {
      setTimeout(() => Ui.toast.close('save'), 2200);
      return { body: el('div', { class: 'body' }, [who, el('p', { class: 'success' }, [icon(ICON.check), document.createTextNode(t('ext.toast.passwordSaved'))])]) };
    }
    if (save.state === 'locked' || save.state === 'vault') {
      const intent = save.state === 'locked' ? 'unlock' : 'create';
      const note = el('p', { class: 'note', text: t(intent === 'unlock' ? 'ext.toast.saveLockedText' : 'ext.toast.saveVaultText') });
      return {
        badge: el('span', { class: 'badge warn', text: t(intent === 'unlock' ? 'ext.card.badgeLocked' : 'ext.toast.badgeProtect') }),
        body: el('div', { class: 'body' }, [who, note, el('div', { class: 'actions one' }, [openPopupButton(intent, note)])]),
      };
    }
    const username = el('input', { value: save.username, 'aria-label': t('ext.toast.username'), autocomplete: 'off', oninput: (e) => (save.username = e.target.value) });
    const error = el('p', { class: 'error', hidden: true });
    const saveButton = el('button', {
      class: 'btn primary',
      type: 'button',
      onclick: Ui.trusted(async () => {
        saveButton.disabled = true;
        const res = await send({ type: 'content:saveLogin', username: save.username });
        saveButton.disabled = false;
        if (!res || res.error) {
          error.textContent = res ? t(`error.${res.error.code}`, res.error.params) : t('ext.error.noExtension');
          error.hidden = false;
          return;
        }
        save.state = res.saved ? 'saved' : stateFor(res.status);
        Ui.toast.refresh('save', { force: true });
      }),
    }, [icon(ICON.key), document.createTextNode(t(p.action === 'update' ? 'ext.toast.update' : 'ext.toast.save'))]);
    return {
      badge: el('span', { class: 'badge', text: t(p.action === 'update' ? 'ext.toast.badgeChanged' : 'ext.toast.badgeNew') }),
      label: t(p.action === 'update' ? 'ext.toast.updateTitle' : 'ext.toast.saveTitle'),
      body: el('div', { class: 'body' }, [
        el('p', { class: 'title', text: t(p.action === 'update' ? 'ext.toast.updateTitle' : 'ext.toast.saveTitle') }),
        el('div', { class: 'group' }, [
          el('label', {}, [document.createTextNode(t('ext.toast.username')), username]),
          el('label', {}, [document.createTextNode(t('ext.toast.password')), el('span', { class: 'dots', text: '•'.repeat(Math.min(p.length, 16)) })]),
        ]),
        error,
        el('div', { class: 'actions wide' }, [
          saveButton,
          el('button', { class: 'btn', type: 'button', text: t('ext.toast.notNow'), onclick: () => Ui.toast.close('save', true) }),
        ]),
        el('button', {
          class: 'link',
          type: 'button',
          text: t('ext.toast.never', { site: p.host }),
          onclick: () => {
            send({ type: 'content:dismissLogin', never: true });
            save.state = 'never';
            Ui.toast.close('save');
          },
        }),
      ]),
    };
  }

  function openPopupButton(intent, note) {
    return el('button', {
      class: 'btn primary',
      type: 'button',
      onclick: async () => {
        const res = await send({ type: 'content:openPopup', intent });
        if ((!res || !res.opened) && note) note.textContent = t('ext.card.lockedHint');
      },
    }, [icon(ICON.lock), document.createTextNode(t(intent === 'create' ? 'ext.toast.createVault' : 'ext.card.unlock'))]);
  }

  /* ═════════════ Remplir ═════════════ */

  const login = { list: [], status: null, known: false, dismissed: false, filled: null };

  async function checkLogins() {
    if (login.dismissed || Ui.toast.has('save') || !passwordFields().length) return;
    const res = await send({ type: 'content:logins' });
    if (!res || res.error) return;
    login.status = res.status;
    login.known = Boolean(res.known);
    login.list = res.logins || [];
    if (login.list.length || (res.status === 'locked' && res.known)) {
      // Écarté ou déjà rempli : plus rien à proposer sur cette page. Sans cela, la fermeture du
      // message « Rempli » relancerait l'observateur du DOM, qui rouvrirait le toast, en boucle.
      Ui.toast.open('fill', { priority: 15, render: fillView, onClose: (byUser) => (byUser || login.filled) && (login.dismissed = true) });
    } else Ui.toast.close('fill');
  }

  function fillFields(username, password) {
    const field = passwordFields()[0];
    if (!field) return false;
    const user = usernameField(field);
    if (user && username) Ui.setValue(user, username);
    field.focus();
    Ui.setValue(field, password);
    lastSent = `${username}\u0000${password}`; // déjà connu : rien à proposer à l'envoi
    return true;
  }

  function fillView() {
    if (login.status === 'locked') {
      const note = el('p', { class: 'note', text: t('ext.toast.fillLockedText') });
      return {
        badge: el('span', { class: 'badge warn', text: t('ext.card.badgeLocked') }),
        body: el('div', { class: 'body' }, [el('p', { class: 'title', text: t('ext.toast.fillTitle', { site: location.hostname.replace(/^www\./, '') }) }), note, el('div', { class: 'actions one' }, [openPopupButton('unlock', note)])]),
      };
    }
    if (login.filled) {
      setTimeout(() => Ui.toast.close('fill'), 1500);
      return { body: el('div', { class: 'body' }, [el('p', { class: 'success' }, [icon(ICON.check), document.createTextNode(t('ext.toast.filledAs', { name: login.filled }))])]) };
    }
    const error = el('p', { class: 'error', hidden: true });
    const rows = login.list.map((item) =>
      el('button', {
        class: 'row',
        type: 'button',
        onclick: Ui.trusted(async () => {
          const res = await send({ type: 'content:fillLogin', id: item.id });
          if (!res || res.error || !fillFields(res.username, res.password)) {
            error.textContent = res && res.error ? t(`error.${res.error.code}`, res.error.params) : t('ext.card.noField');
            error.hidden = false;
            return;
          }
          login.filled = item.username || item.host;
          Ui.toast.refresh('fill', { force: true });
        }),
      }, [
        Ui.tile(item.username || item.host, true),
        el('span', { class: 'who-text' }, [
          el('span', { class: 'issuer', text: item.username || t('ext.toast.noUsername') }),
          el('span', { class: 'account', text: [item.title || item.host, item.hasOtp ? t('ext.toast.otpReady') : ''].filter(Boolean).join(' · ') }),
        ]),
        el('span', { class: 'row-go' }, icon(ICON.fill)),
      ])
    );
    return {
      badge: el('span', { class: 'badge', text: t('ext.toast.fillBadge', { count: login.list.length }) }),
      body: el('div', { class: 'body' }, [el('p', { class: 'title', text: t('ext.toast.fillTitle', { site: location.hostname.replace(/^www\./, '') }) }), el('div', { class: 'rows' }, rows), error]),
    };
  }

  /* ═════════════ Générer (inscription) ═════════════ */

  const SIGNUP_HINT = /regist|sign.?up|inscri|cr[eé]er|create|join|new.?account|nouveau compte|enrol/i;
  const LOGIN_HINT = /log.?in|sign.?in|connexion|se connecter/i;
  let settings = {};
  const gen = { fields: null, policy: null, value: '', dismissed: false, filled: false };

  function formHints(form) {
    const buttons = [...form.querySelectorAll('button, input[type="submit"]')].map((b) => b.textContent || b.value || '');
    return [form.id, form.className, form.getAttribute('action'), form.getAttribute('name'), ...buttons].join(' ');
  }

  /** Champs d'un nouveau mot de passe (inscription, changement), ou null. */
  function signupFields() {
    const all = passwordFields();
    if (!all.length) return null;
    const fresh = all.filter((f) => f.autocomplete === 'new-password');
    if (fresh.length) return fresh;
    if (all.some((f) => f.autocomplete === 'current-password')) return null;
    const form = all[0].form;
    const group = all.filter((f) => f.form === form);
    if (group.length === 2) return group; // mot de passe et confirmation
    if (group.length === 3) return group.slice(1); // actuel, nouveau, confirmation
    if (group.length === 1 && form) {
      const hints = formHints(form);
      if (SIGNUP_HINT.test(hints) && !LOGIN_HINT.test(hints)) return group;
    }
    return null;
  }

  /** Politique du site pour ce champ : attributs, puis texte d'aide (le sien, pas celui de tout le formulaire). */
  function policyFor(field) {
    const texts = [field.title, field.placeholder];
    const add = (node) => node && texts.push(node.textContent || '');
    for (const id of (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean)) add(document.getElementById(id));
    for (const label of field.labels || []) add(label);
    // Bloc du champ : on remonte tant qu'il ne contient pas d'autre champ (identifiant, e-mail…).
    let block = null;
    for (let node = field.parentElement, depth = 0; node && node !== document.body && depth < 4; node = node.parentElement, depth++) {
      const others = [...node.querySelectorAll('input, select, textarea')].some((i) => !['password', 'hidden', 'checkbox', 'submit', 'button'].includes(i.type));
      if (others) break;
      block = node;
    }
    add(block);
    return Passgen.merge(
      Passgen.fromPasswordRules(field.getAttribute('passwordrules')),
      Passgen.fromAttributes({ minLength: field.getAttribute('minlength'), maxLength: field.getAttribute('maxlength'), pattern: field.getAttribute('pattern') }),
      Passgen.fromText(texts.join('\n'))
    );
  }

  function checkSignup() {
    if (settings.generate === false || gen.dismissed || gen.filled) return;
    const fields = signupFields();
    // Rien à proposer, ou l'utilisateur tape déjà le sien.
    if (!fields || fields.some((f) => f.value)) {
      Ui.toast.close('generate');
      return;
    }
    gen.fields = fields;
    if (Ui.toast.has('generate')) return;
    gen.policy = policyFor(fields[0]);
    gen.value = Passgen.generate(gen.policy);
    Ui.toast.open('generate', { priority: 20, render: generateView, onClose: (byUser) => byUser && (gen.dismissed = true) });
  }

  function useGenerated() {
    const fields = signupFields() || gen.fields || [];
    if (!fields.length) return;
    for (const field of fields) Ui.setValue(field, gen.value);
    fields[0].focus();
    gen.filled = true;
    Ui.toast.refresh('generate', { force: true });
  }

  function rulesText(policy) {
    const info = Passgen.describe(policy);
    const rules = [];
    if (info.min && info.max) rules.push(t('ext.gen.lengthRange', { min: info.min, max: info.max }));
    else if (info.min) rules.push(t('ext.gen.lengthMin', { min: info.min }));
    else if (info.max) rules.push(t('ext.gen.lengthMax', { max: info.max }));
    if (!info.symbols) rules.push(t('ext.gen.noSymbols'));
    else if (info.symbols !== Passgen.DEFAULT_SYMBOLS) rules.push(t('ext.gen.symbolsOnly', { symbols: info.symbols }));
    if (policy.pattern) rules.push(t('ext.gen.pattern'));
    return rules.length ? t('ext.gen.rules', { rules: rules.join(' · ') }) : t('ext.gen.noRules');
  }

  function generateView() {
    if (gen.filled) {
      setTimeout(() => Ui.toast.close('generate'), 4000);
      return {
        body: el('div', { class: 'body' }, [
          el('p', { class: 'success' }, [icon(ICON.check), document.createTextNode(t('ext.gen.filled'))]),
          el('p', { class: 'note', text: t('ext.gen.filledNote') }),
        ]),
      };
    }
    return {
      badge: el('span', { class: 'badge', text: t('ext.gen.badge', { count: gen.value.length }) }),
      body: el('div', { class: 'body' }, [
        el('p', { class: 'title', text: t('ext.gen.title', { site: location.hostname.replace(/^www\./, '') }) }),
        el('p', { class: 'secret', text: gen.value }),
        el('p', { class: 'note', text: rulesText(gen.policy) }),
        el('div', { class: 'actions wide' }, [
          el('button', { class: 'btn primary', type: 'button', onclick: Ui.trusted(useGenerated) }, [icon(ICON.fill), el('span', { text: t('ext.gen.use') })]),
          el('button', {
            class: 'btn',
            type: 'button',
            text: t('ext.gen.another'),
            onclick: Ui.trusted(() => {
              gen.value = Passgen.generate(gen.policy);
              Ui.toast.refresh('generate', { force: true });
            }),
          }),
        ]),
      ]),
    };
  }

  /* ═════════════ Messages et démarrage ═════════════ */

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message) return false;
    if (message.type === 'mymfa:fillLogin') {
      sendResponse({ filled: fillFields(message.username, message.password) });
      return false;
    }
    if (message.type === 'mymfa:loginSaved' && Ui.toast.has('save')) {
      save.state = 'saved';
      Ui.toast.refresh('save', { force: true });
    }
    if (message.type === 'mymfa:state') {
      if (Ui.toast.has('save')) checkPending();
      checkLogins();
    }
    return false;
  });

  async function start() {
    const state = await send({ type: 'content:state' });
    if (!state || !state.settings) return;
    I18n.init(state.settings.lang, { stored: false });
    Ui.setSettings(state.settings);
    settings = state.settings;
    // Formulaire encore là sur la page suivante : connexion sans doute refusée, on attend qu'il disparaisse.
    const field = passwordFields()[0];
    if (field) watchDeparture(field);
    else await checkPending();
    let timer = null;
    new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        checkLogins();
        checkSignup();
      }, 400);
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['type', 'hidden', 'style', 'class'] });
    // Saisie de son propre mot de passe : la proposition se retire.
    document.addEventListener('input', (event) => event.target.type === 'password' && event.isTrusted && checkSignup(), true);
    checkLogins();
    checkSignup();
  }

  start();
})();
