#!/usr/bin/env bash
#
# Déploiement clé en main du service messagerie Rust sur une app Heroku DÉDIÉE.
# Idempotent : crée l'app + les add-ons s'ils manquent, (re)configure l'APNs si
# fourni, puis build/release le conteneur et affiche les logs de boot.
#
# ⚠️ NE PAS viser l'app de PROD (serveur Node). Utilise une app séparée.
#
# Usage :
#   ./deploy-rust.sh [nom-app]                 # défaut : brocolis-rust
#   APP=brocolis-rust ./deploy-rust.sh
#
# APNs (optionnel — sans ça, /push/live-activity/update répond 503) :
#   APNS_KEY_ID=... APNS_TEAM_ID=... APNS_BUNDLE_ID=rs.brocolis.messagerie \
#   APNS_ENV=sandbox APNS_KEY_P8_FILE=./AuthKey_XXXX.p8 ./deploy-rust.sh
#
# Réglages facultatifs (env) :
#   PG_PLAN (défaut heroku-postgresql:essential-0)
#   REDIS_PLAN (défaut heroku-redis:mini)
#   MESSAGE_RETENTION_DAYS, MAX_PEERS
#   SKIP_LOGS=1  pour ne pas suivre les logs à la fin.

set -euo pipefail

APP="${1:-${APP:-brocolis-rust}}"
PG_PLAN="${PG_PLAN:-heroku-postgresql:essential-0}"
REDIS_PLAN="${REDIS_PLAN:-heroku-redis:mini}"

# Ce script doit tourner depuis server-rust/ (là où est le Dockerfile).
cd "$(dirname "$0")"

say()  { printf '\n\033[1;32m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── Prérequis ────────────────────────────────────────────────────────────────
command -v heroku >/dev/null 2>&1 || die "CLI Heroku introuvable (https://devcenter.heroku.com/articles/heroku-cli)."
command -v docker >/dev/null 2>&1 || die "Docker introuvable (nécessaire pour container:push)."
heroku whoami >/dev/null 2>&1 || die "Pas connecté à Heroku : lance 'heroku login'."
docker info >/dev/null 2>&1 || die "Le démon Docker ne tourne pas."

say "App cible : $APP"
warn "Assure-toi que ce N'EST PAS l'app de prod (serveur Node)."

# ── App (stack conteneur) ────────────────────────────────────────────────────
if heroku apps:info -a "$APP" >/dev/null 2>&1; then
  say "App déjà existante — on la réutilise."
  heroku stack:set container -a "$APP" >/dev/null 2>&1 || true
else
  say "Création de l'app (stack conteneur)…"
  heroku create "$APP" --stack container
fi

# ── Add-ons (idempotents) ────────────────────────────────────────────────────
addons="$(heroku addons -a "$APP" 2>/dev/null || true)"

if grep -q "heroku-postgresql" <<<"$addons"; then
  say "Postgres déjà présent."
else
  say "Ajout de Postgres ($PG_PLAN)…"
  heroku addons:create "$PG_PLAN" -a "$APP"
fi

if grep -qE "heroku-redis|heroku-key-value" <<<"$addons"; then
  say "Redis / Key-Value déjà présent."
else
  say "Ajout de Redis ($REDIS_PLAN)…"
  heroku addons:create "$REDIS_PLAN" -a "$APP"
fi

# ── Variables de config ──────────────────────────────────────────────────────
[ -n "${MESSAGE_RETENTION_DAYS:-}" ] && heroku config:set -a "$APP" "MESSAGE_RETENTION_DAYS=$MESSAGE_RETENTION_DAYS" >/dev/null
[ -n "${MAX_PEERS:-}" ] && heroku config:set -a "$APP" "MAX_PEERS=$MAX_PEERS" >/dev/null

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
echo "   Attendu dans les logs : « à l'écoute », « APNs configuré » (si APNs), « Redis branché » (si REDIS_URL)."

if [ "${SKIP_LOGS:-}" != "1" ]; then
  say "Logs (Ctrl-C pour quitter) :"
  heroku logs -a "$APP" --tail
fi
