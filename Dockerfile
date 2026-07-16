# Déploiement Heroku EN CONTENEUR du serveur de rendez-vous, depuis la racine
# du dépôt. Référencé par heroku.yml. Ne copie que le serveur (server/), pas
# l'app iOS ni le site.
FROM node:22-alpine

WORKDIR /app

# Dépendances (pg + redis) pour la persistance durable Postgres et le temps réel
# Redis. Installées AVANT de copier les sources pour profiter du cache Docker.
# Sans DATABASE_URL / REDIS_URL, ces modules ne sont pas sollicités (repli local).
COPY server/package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Sources du serveur + vitrine pré-construite (servie sur /site/). index.js fait
# require des modules ci-dessous au démarrage : SANS ces fichiers, le conteneur
# plante au boot (exit 1 / H10). Toujours tous les copier.
COPY server/index.js ./
COPY server/apns.js ./
COPY server/messages-store.js ./
COPY server/durable-snapshot.js ./
COPY server/realtime.js ./
COPY server/public ./public

ENV NODE_ENV=production
# Fichier SQLite runtime (rapide, synchrone). /tmp est inscriptible sur Heroku.
# ⚠️ Le disque d'un dyno Heroku est ÉPHÉMÈRE : ce fichier est effacé à chaque
# déploiement / recyclage. La DURABILITÉ 7 jours est assurée par les snapshots
# Postgres (durable-snapshot.js) : restaurés au boot, ré-enregistrés en continu.
ENV DB_PATH=/tmp/brocolis-messages.db
EXPOSE 8788

USER node

CMD ["node", "index.js"]
