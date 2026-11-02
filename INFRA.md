# mindlog.mymfa.clients — contrat avec LeLab-infra

> **Fichier généré. Ne pas l'éditer ici.** Il est écrit par
> `stacks/contrat-depot.py` du dépôt d'infrastructure, et réécrit à
> chaque passe : une correction faite dans ce fichier-ci serait perdue.
> Ce qu'il faut corriger est dans `LeLab-infra`.

Ce dépôt ne se déploie pas lui-même : il **construit des images** que
`LeLab-infra` transporte et lance. Les règles ci-dessous ne sont donc pas
des conventions de style, ce sont les conditions auxquelles ce qui sort
d'ici peut être déployé.

## Le dépôt qui fait foi

    /home/jacques/Documents/DEV/Perso/LeLab-infra

| Fichier | Ce qu'il tranche |
|---|---|
| `regles.md` | **Les règles, et rien d'autre ne les énonce.** Vingt-deux en vigueur, quatre proposées, rangées de la plus coûteuse à enfreindre à la moins. |
| `nommage.md` | Le détail des conventions de noms, avec leurs exceptions motivées. |
| `ARCHITECTURE.md` | La forme du parc : façade SNI, terminaison par pile, sauvegardes. |
| `ports.tsv` | Le registre des ports — machine, port, pile, projet compose, rôle. |

Les énoncés repris plus bas sont **abrégés**, et pris dans l'ordre de
`regles.md` : la première engage plus que la dernière. En cas de doute ou
de désaccord, c'est `regles.md` qui tranche, jamais ce fichier.

## Comment ce dépôt est déployé

### Pile `mymfa.mindlog.today.app` — trigramme `mfa`

    ./stacks/deploy.sh mymfa.mindlog.today.app <env>

| Env | Projet Compose | Domaine | Port TLS |
|---|---|---|---|
| `dev` | `mfa-app-dev` | `app.mymfa.mindlog.today.localhost` | `8126` |

**Images construites depuis cet arbre.** Le nom est celui
qu'impose R6 ; les chemins sont relatifs à la racine de CE dépôt,
donc utilisables tels quels :

| Image | Contexte | Dockerfile | Cible |
|---|---|---|---|
| `mfa-web` | `.` | `web/Dockerfile` | — |

Renommer une image, déplacer son contexte ou retirer une cible
d'un Dockerfile casse le déploiement **côté infrastructure**, où
ces valeurs sont écrites : `stacks/mymfa.mindlog.today.app/`.

## Les règles qui engagent ce dépôt

Sept des dix-sept. Les autres portent sur ce que `LeLab-infra` écrit
(R1, R3, R4) ou sur ce qui tourne sur les machines (R10, R11, R14, R15) :
les rappeler ici ferait du bruit sans destinataire.

### R7 — Tout fichier compose déclare son `name:`

Y compris les composes de développement de ce dépôt. Sans lui, Compose dérive le projet du répertoire et l'assainit EN SILENCE — un répertoire `crisis-lab.eu.app` donne le projet `crisis-labeuapp`, donc des volumes NEUFS et les anciens orphelins sans un mot.

### R9 — Aucun tag mobile. Ni `latest`, nulle part

Un `up -d` qui résout `api:latest` sur une image locale plus ancienne rétrograde la production en silence : arrivé le 2026-08-01, symptôme une route absente rendant 401 au lieu de 404. Quand l'amont ne publie que `latest`, on résout son digest et on épingle le tag qui porte le même.

### R13 — Les trois plafonds sont obligatoires : `cpus`, `memory`, `pids`

Aucun service n'y échappe. `cpus` est un quota, jamais une réservation ; la mémoire, elle, ne se partage pas — un conteneur qui touche son plafond est tué, ce qui vaut mieux qu'une machine qui s'effondre.

### R12 — Tout conteneur expose une sonde effective

« Effective » est le mot : la sonde peut venir du compose OU du `HEALTHCHECK` de l'image — donc de ce dépôt-ci. La moitié des vitrines du parc n'en déclarent aucune dans leur compose et héritent celle de leur image. Retirer un `HEALTHCHECK` ici casse les `depends_on: service_healthy` de là-bas.

### R5 — Neuf noms de services réservés à neuf rôles

`site`, `web`, `api`, `db`, `redis`, `s3`, `mail`, `migrate`, `tls` désignent CES rôles et rien d'autre. C'est une réservation, pas une clôture : un rôle hors liste prend un nom parlant (`contact`, `mailer`, `worker`). Un `db` qui ne serait pas la base serait la faute.

### R6 — Une image construite ici s'appelle `<trigramme>-<service>`

Le trigramme est celui du tableau ci-dessus. Une image sans clé `image:` dans un compose est nommée par Docker `<projet>-<service>` et sans tag : elle manque R6 et R9 d'un coup.

### R21 — Alpine par défaut : on ne garde en mémoire que le nécessaire

À service égal, la variante `alpine` — c'est le `FROM` des Dockerfiles de ce dépôt. Préférence et non obligation : une image tierce sans variante alpine se prend telle quelle. Ce que la règle refuse, c'est la variante lourde QUAND la légère existe et fait le travail.

## Ce qui ne se fait pas depuis ce dépôt

**R8, la règle d'or : on ne déploie que des images.** Aucun code source,
aucune chaîne de compilation, aucun secret en clair ne va sur une machine.
`deploy.sh` construit sur le poste, transfère l'image, et pose le compose
et le `.env`. C'est ce qui garantit que la production fait tourner
exactement ce que la qualification a validé — et un `docker compose up`
lancé en SSH depuis ce dépôt-ci annule cette garantie sans laisser de trace.

**R16, tout est rejouable en script.** Aucune action manuelle en SSH. Un
geste qu'on ne sait pas rejouer est un geste qu'on ne saura pas défaire.

Le compose présent dans ce dépôt, s'il y en a un, est un compose de
**développement local**. Il ne décrit pas le déploiement : celui-ci vit
dans `LeLab-infra/stacks/<pile>/compose.yaml`. Les deux se ressemblent
volontairement, ils ne sont pas interchangeables.

## Régénérer ce fichier

    cd /home/jacques/Documents/DEV/Perso/LeLab-infra
    ./stacks/contrat-depot.py              # réécrit les huit dépôts
    ./stacks/contrat-depot.py --verifie    # sort 1 si une copie a dérivé

