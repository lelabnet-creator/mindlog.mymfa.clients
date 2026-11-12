/*
 * Vue « Synchronisation » de l'app (#/sync) — APP-08.
 *  - État : dernière synchro, modifications en attente, fichier Drive, heure de référence,
 *    prochaine synchro automatique (extension) ; « Synchroniser maintenant ».
 *  - Appareils : le registre v2 du coffre (SYN-09) — type de client, nom, dernière activité,
 *    couverture, nombre d'éléments dont l'appareil a fait la dernière modification.
 *  - Chronologie : l'historique (ajouts, modifications, suppressions) avec l'appareil source,
 *    filtrable par action, type d'élément, appareil et période.
 *  - Journal : les cycles de synchro de cet appareil (et de l'arrière-plan de l'extension) —
 *    changements reçus et envoyés avec leur auteur, conflits, doublons, horloges suspectes.
 * Rien n'est lu hors du coffre ouvert ; les valeurs sensibles des conflits ne sont jamais
 * journalisées (js/drivesync.js).
 * Dépend de : I18n, Sync2, Store, Lock.
 */
(function () {
  'use strict';

  const { t } = I18n;
  const $ = (id) => document.getElementById(id);
  const TYPES = ['web', 'extension', 'linux', 'android'];
  const ACTIONS = ['create', 'update', 'delete'];
  const KINDS = ['account', 'login', 'passkey'];
  const PERIODES = ['7', '30', 'all'];
  const JOURNAL_VISIBLE = 30;

  let ctx = null;
  const state = { action: '', kind: '', appareil: '', periode: '30', journal: null, appareilHote: null, plus: false, enCours: false };

  /* ───── Utilitaires DOM ───── */

  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'value') node.value = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of [].concat(children)) if (child !== null && child !== undefined && child !== false) node.append(child);
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
    web: ['M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z', 'M3 12h18', 'M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18'],
    extension: 'M10 3h4v3a2 2 0 1 0 4 0V3h3v7h-3a2 2 0 1 0 0 4h3v7h-7v-3a2 2 0 1 0-4 0v3H3v-7h3a2 2 0 1 0 0-4H3V3z',
    linux: ['M3 5h18v11H3z', 'M8 20h8M12 16v4', 'M7 9l2 2-2 2M11 13h4'],
    android: ['M7 3h10a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z', 'M11 18h2'],
    other: ['M4 6h16v10H4z', 'M2 20h20'],
    legacy: ['M12 7v5l3 2', 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z'],
    create: 'M12 5v14M5 12h14',
    update: 'M4 20h4L18.5 9.5a2.1 2.1 0 0 0-4-4L4 16v4z',
    delete: 'M4 7h16M6 7l1 13h10l1-13M9 7V4h6v3',
    sync: ['M20 11a8 8 0 0 0-14.9-3.5M4 4v4h4', 'M4 13a8 8 0 0 0 14.9 3.5M20 20v-4h-4'],
    conflict: 'M12 9v4M12 17h.01M10.3 3.9 2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  };

  const dateHeure = (value) => (value ? I18n.formatDateTime(value) : '—');

  /* ───── Données ───── */

  const liste = (map, cle) => {
    try {
      const v = JSON.parse((map || {})[cle] || '[]');
      return Array.isArray(v) ? v : [];
    } catch {
      return [];
    }
  };

  function registre(donnees) {
    return Sync2.lireMarqueur(donnees || {}).appareils;
  }

  /** Nom lisible d'un appareil : type de client (dans la langue de chacun) et nom qu'il s'est donné. */
  function libelleAppareil(id, appareils) {
    if (!id) return t('sync.device.unknown');
    if (id === Sync2.APPAREIL_HERITAGE) return t('sync.device.legacy');
    const e = appareils[id];
    const type = e && e.type ? t(`sync.type.${TYPES.includes(e.type) ? e.type : 'other'}`) : t('sync.type.other');
    return e && e.nom ? `${type} · ${e.nom}` : `${type} ${id.slice(0, 8)}`;
  }

  function iconeAppareil(id, appareils) {
    if (id === Sync2.APPAREIL_HERITAGE) return ICONS.legacy;
    const type = appareils[id] && appareils[id].type;
    return ICONS[TYPES.includes(type) ? type : 'other'];
  }

  /** Éléments vivants dont chaque appareil a fait la dernière modification (tampons v2). */
  function auteurs(donnees) {
    const compte = {};
    for (const collection of Sync2.COLLECTIONS) {
      for (const item of liste(donnees, collection.cle)) {
        if (!item || !Sync2.estVivant(item)) continue;
        const sommet = Sync2.plusGrandTampon(item);
        if (!sommet) continue;
        const id = Sync2.decoderAppareil(sommet);
        compte[id] = (compte[id] || 0) + 1;
      }
    }
    return compte;
  }

  async function chargerJournal() {
    const local = (await Lock.lireJournal()).map((e) => ({ ...e, source: e.source || 'app' }));
    let hote = [];
    if (ctx.host && ctx.host.syncJournal) {
      try {
        const res = await ctx.host.syncJournal();
        hote = (res.entrees || []).map((e) => ({ ...e, source: 'extension' }));
        state.appareilHote = res.appareil || null;
      } catch {
        /* extension verrouillée ou indisponible : son journal attendra */
      }
    }
    state.journal = [...local, ...hote].sort((a, b) => (b.at || '').localeCompare(a.at || ''));
  }

  /* ───── Sections ───── */

  function ligneDl(label, valeur) {
    return [h('dt', { text: label }), h('dd', {}, [valeur])];
  }

  function sectionEtat(donnees) {
    const drive = ctx.etatDrive();
    const statut = Lock.status();
    let titre;
    let ton = '';
    let indication = null;
    let action = null;
    if (!drive.configure) {
      titre = t('sync.state.notConfigured');
      indication = t('sync.state.notConfiguredHint');
      action = h('a', { class: 'btn btn-ghost', href: '#/settings', text: t('sync.state.configure') });
    } else if (statut === 'plain') {
      titre = t('sync.state.needsPassword');
      indication = t('drive.privacy');
      action = h('button', { type: 'button', class: 'btn btn-primary', text: t('drive.enablePassword'), onclick: () => Lock.openEnable() });
    } else if (statut === 'locked') {
      titre = t('sync.state.locked');
    } else if (!drive.derniere) {
      titre = t('sync.state.never');
      indication = t('drive.suggest');
      ton = 'is-pending';
    } else if (drive.enAttente) {
      titre = t('sync.state.pending');
      ton = 'is-pending';
    } else {
      titre = t('sync.state.upToDate');
      ton = 'is-ok';
    }
    const dernierCycle = (state.journal || [])[0];
    if (dernierCycle && (dernierCycle.resultat === 'erreur' || dernierCycle.resultat === 'autreCoffre') && statut === 'unlocked') {
      ton = 'is-error';
      indication = ctx.errorMessage({ code: dernierCycle.code || 'driveOtherVault' });
    }
    const peutSynchroniser = drive.configure && statut === 'unlocked';
    if (peutSynchroniser) {
      action = h('button', {
        type: 'button',
        class: `btn btn-primary${state.enCours ? ' is-busy' : ''}`,
        id: 'btn-sync-now',
        disabled: state.enCours,
        onclick: synchroniser,
      }, [icon(ICONS.sync), h('span', { text: t('sync.now') })]);
    }

    const heure = Lock.heure.etat();
    const details = [];
    if (drive.configure) {
      details.push(...ligneDl(t('sync.state.last'), dateHeure(drive.derniere)));
      details.push(...ligneDl(t('drive.file'), h('code', { text: `Google Drive/${Drive.FOLDER}/${(drive.fichier && drive.fichier.name) || Drive.FILE_NAME}` })));
      if (drive.fichier && drive.fichier.modifiedTime) details.push(...ligneDl(t('sync.state.driveModified'), dateHeure(drive.fichier.modifiedTime)));
      if (drive.prochaine !== undefined) details.push(...ligneDl(t('sync.state.next'), drive.prochaine ? dateHeure(drive.prochaine) : t('drive.everyOff')));
    }
    details.push(
      ...ligneDl(
        t('sync.state.clock'),
        heure.verifiee
          ? t('sync.state.clockChecked', { secondes: Math.round(Math.abs(heure.decalageMs || 0) / 1000) })
          : t('sync.state.clockUnchecked')
      )
    );
    const appareils = registre(donnees);
    details.push(...ligneDl(t('sync.state.thisDevice'), libelleAppareil(Lock.temps.appareil, { ...appareils, [Lock.temps.appareil]: { ...Lock.temps.etat, ...(appareils[Lock.temps.appareil] || {}) } })));

    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('sync.state.title') }),
      h('div', { class: `panel sync-state ${ton}` }, [
        h('div', { class: 'sync-state-head' }, [
          h('span', { class: 'row-icon accent', 'aria-hidden': 'true' }, [icon(ICONS.sync)]),
          h('div', { class: 'sync-state-text' }, [
            h('p', { class: 'sync-state-title', id: 'sync-status', text: titre }),
            indication ? h('p', { class: 'panel-hint', text: indication }) : null,
          ]),
          action ? h('div', { class: 'sync-state-action' }, [action]) : null,
        ]),
        h('dl', { class: 'sync-dl' }, details),
      ]),
    ]);
  }

  function sectionAppareils(donnees) {
    const appareils = registre(donnees);
    const ids = Object.keys(appareils);
    const parAuteur = auteurs(donnees);
    // Les tampons hérités de la v1 (migration) : une source à part entière.
    if (parAuteur[Sync2.APPAREIL_HERITAGE] && !ids.includes(Sync2.APPAREIL_HERITAGE)) ids.push(Sync2.APPAREIL_HERITAGE);
    const ici = Lock.temps.appareil;
    ids.sort((a, b) => (a === ici ? -1 : b === ici ? 1 : (appareils[b]?.actifLe || 0) - (appareils[a]?.actifLe || 0)));
    const items = ids.map((id) => {
      const e = appareils[id] || {};
      const badges = [];
      if (id === ici) badges.push(h('span', { class: 'tag sync-here', text: t('sync.devices.here') }));
      if (state.appareilHote && id === state.appareilHote) badges.push(h('span', { class: 'tag', text: t('sync.devices.hostHere') }));
      const lignes = [];
      if (id === Sync2.APPAREIL_HERITAGE) lignes.push(t('sync.devices.legacyHint'));
      else {
        lignes.push(e.actifLe ? t('sync.devices.active', { date: dateHeure(e.actifLe) }) : t('sync.devices.neverActive'));
        if (e.vu && Sync2.decoderL(e.vu) > 0) lignes.push(t('sync.devices.seen', { date: dateHeure(Sync2.isoDepuisTampon(e.vu)) }));
      }
      const n = parAuteur[id] || 0;
      return h('li', { class: 'sync-device' }, [
        h('span', { class: 'activity-icon kind-transfer' }, [icon(iconeAppareil(id, appareils))]),
        h('div', { class: 'activity-body' }, [
          h('div', { class: 'activity-top' }, [h('span', { class: 'activity-subject sync-device-name', text: libelleAppareil(id, appareils) })]),
          badges.length ? h('div', { class: 'activity-line' }, badges) : null,
          h('span', { class: 'activity-line sync-count', text: t('sync.devices.authored', { count: n }) }),
          ...lignes.map((l) => h('span', { class: 'activity-detail', text: l })),
          id !== Sync2.APPAREIL_HERITAGE ? h('span', { class: 'activity-detail sync-id', text: t('sync.devices.id', { id }) }) : null,
        ]),
      ]);
    });
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('sync.devices.title') }),
      ids.length
        ? h('ol', { class: 'panel activity-list', id: 'sync-devices' }, items)
        : h('p', { class: 'panel panel-hint sync-empty', text: t('sync.devices.empty') }),
    ]);
  }

  function chip(valeur, courant, texte, surChoix) {
    return h('button', {
      type: 'button',
      class: 'chip',
      'aria-pressed': String(courant === valeur),
      text: texte,
      onclick: () => surChoix(valeur),
    });
  }

  function genreDe(entree) {
    const kind = entree.details && entree.details.kind;
    return KINDS.includes(kind) ? kind : 'account';
  }

  function champsModifies(entree) {
    const d = entree.details || {};
    const champs = Array.isArray(d.changes) ? d.changes.map((c) => c.field) : Array.isArray(d.fields) ? d.fields : [];
    return champs.map(nomChamp).join(', ');
  }

  function nomChamp(champ) {
    const texte = t(`sync.field.${champ}`);
    return texte === `sync.field.${champ}` ? champ : texte;
  }

  function sectionChronologie(donnees) {
    const appareils = registre(donnees);
    const depuis = state.periode === 'all' ? 0 : Date.now() - Number(state.periode) * 86400000;
    const entrees = ctx.store
      .history()
      .filter((e) => ACTIONS.includes(e.action))
      .filter((e) => !state.action || e.action === state.action)
      .filter((e) => !state.kind || genreDe(e) === state.kind)
      .filter((e) => !state.appareil || (state.appareil === '?' ? !e.appareil : e.appareil === state.appareil))
      .filter((e) => !depuis || Date.parse(e.at) >= depuis);

    const choixAppareils = [...new Set(ctx.store.history().map((e) => e.appareil || '?'))];
    const select = h(
      'select',
      {
        class: 'select-inline',
        id: 'sync-filter-device',
        'aria-label': t('sync.timeline.device'),
        onchange: (ev) => {
          state.appareil = ev.target.value;
          render();
        },
      },
      [
        h('option', { value: '', text: t('sync.timeline.allDevices') }),
        ...choixAppareils.map((id) => h('option', { value: id, text: id === '?' ? t('sync.device.unknown') : libelleAppareil(id, appareils) })),
      ]
    );
    select.value = state.appareil;

    const filtres = h('div', { class: 'sync-filters' }, [
      h('div', { class: 'chips chips-wrap', role: 'group', 'aria-label': t('sync.timeline.byAction') }, [
        chip('', state.action, t('sync.timeline.all'), (v) => ((state.action = v), render())),
        ...ACTIONS.map((a) => chip(a, state.action, t(`sync.action.${a}`), (v) => ((state.action = v), render()))),
      ]),
      h('div', { class: 'chips chips-wrap', role: 'group', 'aria-label': t('sync.timeline.byKind') }, [
        chip('', state.kind, t('sync.timeline.allKinds'), (v) => ((state.kind = v), render())),
        ...KINDS.map((k) => chip(k, state.kind, t(`sync.kind.${k}`), (v) => ((state.kind = v), render()))),
      ]),
      h('div', { class: 'sync-filters-row' }, [
        select,
        h('div', { class: 'chips chips-wrap', role: 'group', 'aria-label': t('sync.timeline.period') }, PERIODES.map((p) => chip(p, state.periode, t(`sync.period.${p}`), (v) => ((state.periode = v), render())))),
      ]),
    ]);

    const lignes = entrees.slice(0, 200).map((e) => {
      const champs = e.action === 'update' ? champsModifies(e) : '';
      return h('li', { class: 'activity-item' }, [
        h('span', { class: `activity-icon kind-${e.action}` }, [icon(ICONS[e.action])]),
        h('div', { class: 'activity-body' }, [
          h('div', { class: 'activity-top' }, [
            h('span', { class: 'activity-subject', text: e.label || t('list.noName') }),
            h('time', { datetime: e.at, text: dateHeure(e.at) }),
          ]),
          h('div', { class: 'activity-line' }, [
            h('span', { text: t(`sync.action.${e.action}`) }),
            h('span', { class: 'tag', text: t(`sync.kind.${genreDe(e)}`) }),
            h('span', { class: 'sync-source' }, [icon(iconeAppareil(e.appareil, appareils)), h('span', { text: e.appareil ? libelleAppareil(e.appareil, appareils) : t('sync.device.unknown') })]),
          ]),
          champs ? h('span', { class: 'activity-detail', text: t('sync.timeline.fields', { list: champs }) }) : null,
        ]),
      ]);
    });

    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('sync.timeline.title') }),
      filtres,
      lignes.length
        ? h('ol', { class: 'panel activity-list', id: 'sync-timeline' }, lignes)
        : h('p', { class: 'panel panel-hint sync-empty', text: t('sync.timeline.empty') }),
    ]);
  }

  function ligneChangement(c, appareils) {
    const auteur = c.appareil ? libelleAppareil(c.appareil, appareils) : t('sync.device.unknown');
    const action = { ajout: 'create', modification: 'update', suppression: 'delete' }[c.action] || 'update';
    const champs = c.champs && c.champs.length ? ` (${c.champs.map(nomChamp).join(', ')})` : '';
    return h('li', { class: 'sync-change' }, [
      h('span', { class: `sync-dot kind-${action}` }, [icon(ICONS[action])]),
      h('span', { class: 'sync-change-text' }, [
        h('strong', { text: c.libelle || t('list.noName') }),
        ` — ${t(`sync.action.${action}`)}${champs} · ${t(`sync.kind.${{ accounts: 'account', logins: 'login', passkeys: 'passkey' }[c.collection] || 'account'}`)}`,
        h('span', { class: 'sync-change-meta', text: `${auteur}${c.at ? ` · ${dateHeure(c.at)}` : ''}` }),
      ]),
    ]);
  }

  function valeurConflit(v) {
    if (!v) return '—';
    return v.masque ? t('sync.journal.masked') : v.valeur === null || v.valeur === undefined || v.valeur === '' ? '∅' : v.valeur;
  }

  function blocCycle(e, appareils) {
    const somme = (x) => (x ? x.ajout + x.modification + x.suppression : 0);
    const recus = somme(e.totaux && e.totaux.recus);
    const envoyes = somme(e.totaux && e.totaux.envoyes);
    const conflits = e.conflits || [];
    const autres = e.autres || [];
    const erreur = e.resultat === 'erreur' || e.resultat === 'autreCoffre';
    const resume = erreur
      ? ctx.errorMessage({ code: e.code || 'driveOtherVault' })
      : t('sync.journal.summary', { recus, envoyes }) + (conflits.length ? ` · ${t('sync.journal.conflicts', { count: conflits.length })}` : '');
    const detail = [];
    if ((e.recus || []).length) {
      detail.push(h('p', { class: 'sync-sub', text: t('sync.journal.received', { count: recus }) }), h('ul', { class: 'sync-changes' }, e.recus.map((c) => ligneChangement(c, appareils))));
    }
    if ((e.envoyes || []).length) {
      detail.push(h('p', { class: 'sync-sub', text: t('sync.journal.sent', { count: envoyes }) }), h('ul', { class: 'sync-changes' }, e.envoyes.map((c) => ligneChangement(c, appareils))));
    }
    if (conflits.length) {
      detail.push(
        h('p', { class: 'sync-sub', text: t('sync.journal.conflictsTitle') }),
        h(
          'ul',
          { class: 'sync-changes' },
          conflits.map((c) =>
            h('li', { class: 'sync-change' }, [
              h('span', { class: 'sync-dot kind-delete' }, [icon(ICONS.conflict)]),
              h('span', { class: 'sync-change-text' }, [
                h('strong', { text: c.libelle || t('list.noName') }),
                ` — ${nomChamp(c.champ)} : ${
                  c.gagnant && c.gagnant.masque
                    ? t('sync.journal.maskedConflict')
                    : `${t('sync.journal.kept', { valeur: valeurConflit(c.gagnant) })}, ${t('sync.journal.dropped', { valeur: valeurConflit(c.perdant) })}`
                }`,
                h('span', {
                  class: 'sync-change-meta',
                  text: `${t('sync.journal.winner')} ${c.gagnant && c.gagnant.appareil ? libelleAppareil(c.gagnant.appareil, appareils) : t('sync.device.unknown')}${c.gagnant && c.gagnant.at ? ` · ${dateHeure(c.gagnant.at)}` : ''}`,
                }),
              ]),
            ])
          )
        )
      );
    }
    if (autres.length) {
      detail.push(
        h('p', { class: 'sync-sub', text: t('sync.journal.notes') }),
        h('ul', { class: 'sync-changes' }, autres.map((a) => h('li', { class: 'sync-change' }, [h('span', { class: 'sync-change-text', text: `${t(`sync.genre.${a.genre}`)}${a.libelle ? ` — ${a.libelle}` : ''}` })])))
      );
    }
    const tete = [
      h('span', { class: `activity-icon kind-${erreur ? 'delete' : recus + envoyes ? 'transfer' : 'copy'}` }, [icon(ICONS.sync)]),
      h('div', { class: 'activity-body' }, [
        h('div', { class: 'activity-top' }, [
          h('span', { class: 'activity-subject', text: t(`sync.result.${e.resultat}`) }),
          h('time', { datetime: e.at, text: dateHeure(e.at) }),
        ]),
        h('div', { class: 'activity-line' }, [
          h('span', { class: 'tag', text: t(`sync.journal.source.${e.source === 'extension' ? 'extension' : 'app'}`) }),
          h('span', { text: resume }),
        ]),
      ]),
    ];
    if (!detail.length) return h('li', { class: 'activity-item' }, tete);
    return h('li', { class: 'sync-cycle' }, [
      h('details', {}, [h('summary', { class: 'activity-item' }, tete), h('div', { class: 'sync-detail' }, detail)]),
    ]);
  }

  function sectionJournal(donnees) {
    const appareils = registre(donnees);
    let contenu;
    if (Lock.status() !== 'unlocked') contenu = h('p', { class: 'panel panel-hint sync-empty', text: t('sync.journal.locked') });
    else if (state.journal === null) contenu = h('p', { class: 'panel panel-hint sync-empty', text: t('sync.journal.loading') });
    else if (!state.journal.length) contenu = h('p', { class: 'panel panel-hint sync-empty', text: t('sync.journal.empty') });
    else {
      const visibles = state.plus ? state.journal : state.journal.slice(0, JOURNAL_VISIBLE);
      contenu = h('div', {}, [
        h('ol', { class: 'panel activity-list', id: 'sync-journal' }, visibles.map((e) => blocCycle(e, appareils))),
        state.journal.length > visibles.length
          ? h('button', { type: 'button', class: 'btn btn-ghost sync-more', text: t('sync.journal.more'), onclick: () => ((state.plus = true), render()) })
          : null,
      ]);
    }
    return h('section', { class: 'dash-section' }, [
      h('h2', { class: 'section-label', text: t('sync.journal.title') }),
      h('p', { class: 'panel-hint sync-section-hint', text: t('sync.journal.hint') }),
      contenu,
    ]);
  }

  /* ───── Rendu et actions ───── */

  function render() {
    const root = $('sync');
    if (!root || !ctx) return;
    const donnees = ctx.donnees();
    root.replaceChildren(sectionEtat(donnees), sectionAppareils(donnees), sectionChronologie(donnees), sectionJournal(donnees));
  }

  /** Vue ouverte : rendu immédiat, puis journal (déchiffré) et rendu complet. */
  function show() {
    render();
    if (Lock.status() !== 'unlocked') return;
    chargerJournal()
      .then(render)
      .catch(() => {});
  }

  async function synchroniser() {
    if (state.enCours) return;
    state.enCours = true;
    render();
    try {
      const entree = await ctx.synchroniser();
      ctx.toast(ctx.messageSynchro(entree));
    } catch (err) {
      ctx.toast(ctx.errorMessage(err));
    } finally {
      state.enCours = false;
      ctx.renderAll();
      await chargerJournal().catch(() => {});
      render();
    }
  }

  function reset() {
    state.journal = null;
    state.appareilHote = null;
    state.plus = false;
    const root = $('sync');
    if (root) root.replaceChildren();
  }

  function init(options) {
    ctx = options;
    I18n.onChange(() => {
      if (!$('sync') || $('sync').closest('[hidden]')) return;
      render();
    });
  }

  window.SyncView = { init, render, show, reset };
})();
