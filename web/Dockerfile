# syntax=docker/dockerfile:1

# myMFA — l'application, en image. Ce dépôt construit l'image, il ne la déploie
# pas : c'est la pile `mymfa.mindlog.today.app` de LeLab-infra qui la transporte
# et la lance, sous le nom `mfa-web` (R5 : `web` est le rôle d'un client servi
# au navigateur ; R6 : `<trigramme>-<service>`).
#
# L'app n'a pas de serveur : c'est un site statique. L'image n'est donc qu'un
# nginx qui sert des fichiers — aucun secret, aucun compte n'y transite, tout
# vit dans le navigateur.
#
# Contexte de construction : la RACINE du dépôt, et non `web/`. L'image sert
# aussi l'archive de l'extension, qui est un client à part (`extension/`) :
#     docker build -f web/Dockerfile .
# La pile le sait par son `images.tsv` ; les exclusions sont dans le
# `.dockerignore` de la racine.

# --- Étage de build ----------------------------------------------------------
# Deux choses à produire qui ne sont pas versionnées : les fichiers tiers de
# `web/vendor/` (jsQR, police Manrope), copiés depuis node_modules, et l'archive
# de l'extension que propose `extension.html`, construite par son propre client.
FROM node:22-alpine AS build
WORKDIR /src

# `zip` : sans lui, extension/scripts/build.mjs construit l'extension mais saute
# l'archive, et le bouton de téléchargement d'extension.html tombe en 404.
RUN apk add --no-cache zip

COPY web/package.json web/package-lock.json web/
COPY extension/package.json extension/package-lock.json extension/
# `playwright-core` est une dépendance de dev pure JS : il ne télécharge aucun
# navigateur à l'installation.
RUN cd web && npm ci --no-audit --no-fund \
 && cd ../extension && npm ci --no-audit --no-fund

# L'extension copie ses modules partagés depuis web/js : les deux arbres.
COPY web web
COPY extension extension
RUN cd web && npm run vendor \
 && cd ../extension && npm run build

# Ce qui est servi, et rien d'autre : ni les tests, ni les scripts, ni le
# dossier source de l'extension (son archive suffit).
RUN mkdir /out \
 && cd web && cp -r index.html extension.html css js vendor /out/ \
 && mkdir /out/dist && cp ../extension/dist/mymfa-extension.zip /out/dist/

# --- Étage d'exécution -------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY --from=build /out /usr/share/nginx/html
COPY web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
# Sonde sur 127.0.0.1 et non `localhost` : dans le conteneur, `localhost`
# résout d'abord en IPv6, où nginx n'écoute pas (même piège que les vitrines).
# R12 : c'est cette sonde que la pile attend dans son `depends_on`.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1/ >/dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
