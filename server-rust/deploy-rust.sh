#!/usr/bin/env bash
#
# Déploiement clé en main du serveur Brocolis 🥦 (Vitesse + Memoire + Active)
# sur Heroku. Idempotent : crée l'app si elle manque, (re)configure l'APNs si
# fourni, puis build/release le conteneur et affiche les logs de boot.
# Aucun add-on : ni Postgres ni Redis, les données sont en mémoire.
#
# Usage :
#   ./server-rust/deploy-rust.sh [nom-app]     # défaut : brocolis-serveur
#   APP=brocolis-serveur ./server-rust/deploy-rust.sh
#
# APNs (optionnel — sans ça, /push/live-activity/update répond 503) :
#   APNS_KEY_ID=... APNS_TEAM_ID=... APNS_BUNDLE_ID=rs.brocolis.messagerie \
#   APNS_ENV=sandbox APNS_KEY_P8_FILE=./AuthKey_XXXX.p8 ./server-rust/deploy-rust.sh
#
# Réglages facultatifs (env) :
#   MESSAGE_RETENTION_DAYS, MAX_PEERS, MEMORY_BUDGET_MB
#   SKIP_LOGS=1  pour ne pas suivre les logs à la fin.

set -euo pipefail

APP="${1:-${APP:-brocolis-serveur}}"

# Le Dockerfile est à la racine du dépôt (il construit le site et le serveur).
cd "$(dirname "$0")/.."

say()  { printf '\n\033[1;32m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── Prérequis ────────────────────────────────────────────────────────────────
command -v heroku >/dev/null 2>&1 || die "CLI Heroku introuvable (https://devcenter.heroku.com/articles/heroku-cli)."
command -v docker >/dev/null 2>&1 || die "Docker introuvable (nécessaire pour container:push)."
heroku whoami >/dev/null 2>&1 || die "Pas connecté à Heroku : lance 'heroku login'."
docker info >/dev/null 2>&1 || die "Le démon Docker ne tourne pas."

say "App cible : $APP"

# ── App (stack conteneur) ────────────────────────────────────────────────────
if heroku apps:info -a "$APP" >/dev/null 2>&1; then
  say "App déjà existante — on la réutilise."
  heroku stack:set container -a "$APP" >/dev/null 2>&1 || true
else
  say "Création de l'app (stack conteneur)…"
  heroku create "$APP" --stack container
fi

# Plus besoin de Postgres ni de Redis : on le signale s'il en reste.
addons="$(heroku addons -a "$APP" 2>/dev/null || true)"
if grep -qE "heroku-postgresql|heroku-redis|heroku-key-value" <<<"$addons"; then
  warn "Des add-ons Postgres/Redis sont encore attachés : le serveur ne s'en sert plus (heroku addons:destroy …)."
fi

# ── Variables de config ──────────────────────────────────────────────────────
[ -n "${MESSAGE_RETENTION_DAYS:-}" ] && heroku config:set -a "$APP" "MESSAGE_RETENTION_DAYS=$MESSAGE_RETENTION_DAYS" >/dev/null
[ -n "${MAX_PEERS:-}" ] && heroku config:set -a "$APP" "MAX_PEERS=$MAX_PEERS" >/dev/null
[ -n "${MEMORY_BUDGET_MB:-}" ] && heroku config:set -a "$APP" "MEMORY_BUDGET_MB=$MEMORY_BUDGET_MB" >/dev/null

# APNs : uniquement si les 3 identifiants + la clé .p8 sont fournis.
if [ -n "${APNS_KEY_ID:-}" ] && [ -n "${APNS_TEAM_ID:-}" ] && [ -n "${APNS_BUNDLE_ID:-}" ] && [ -n "${APNS_KEY_P8_FILE:-}" ]; then
  [ -f "$APNS_KEY_P8_FILE" ] || die "APNS_KEY_P8_FILE introuvable : $APNS_KEY_P8_FILE"
  say "Configuration APNs…"
  heroku config:set -a "$APP" \
    "APNS_KEY_ID=$APNS_KEY_ID" \
    "APNS_TEAM_ID=$APNS_TEAM_ID" \
    "APNS_BUNDLE_ID=$APNS_BUNDLE_ID" \
    "APNS_ENV=${APNS_ENV:-sandbox}" >/dev/null
  # La clé .p8 est multi-lignes : on préserve les retours à la ligne.
  heroku config:set -a "$APP" "APNS_KEY_P8=$(cat "$APNS_KEY_P8_FILE")" >/dev/null
else
  warn "APNs non configuré (variables/fichier .p8 manquants) → /push/live-activity/update répondra 503."
fi

# ── Build + release ──────────────────────────────────────────────────────────
say "Build & push du conteneur (peut prendre quelques minutes la 1ʳᵉ fois)…"
heroku container:push web -a "$APP"
say "Release…"
heroku container:release web -a "$APP"

# ── Vérification ─────────────────────────────────────────────────────────────
URL="https://$APP.herokuapp.com"
say "Vérification de /health à $URL …"
sleep 5
if curl -fsS "$URL/health" >/dev/null 2>&1; then
  printf '\033[1;32m✓ /health répond « ok »\033[0m\n'
else
  warn "/health n'a pas encore répondu — regarde les logs ci-dessous."
fi

say "Déployé : $URL"
echo "   Attendu dans les logs : « Données en mémoire », « APNs configuré » (si APNs), « à l'écoute »."

if [ "${SKIP_LOGS:-}" != "1" ]; then
  say "Logs (Ctrl-C pour quitter) :"
  heroku logs -a "$APP" --tail
fi
