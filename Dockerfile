# Déploiement Heroku EN CONTENEUR du serveur de rendez-vous, depuis la racine
# du dépôt. Référencé par heroku.yml. Ne copie que le serveur (server/), pas
# l'app iOS ni le site.
FROM node:22-alpine

WORKDIR /app

# Le serveur n'a aucune dépendance externe : on copie ses sources + la vitrine
# pré-construite (servie sur /site/). index.js fait require('./apns.js') et
# require('./messages-store.js') au démarrage : SANS ces fichiers, le conteneur
# plante au boot (exit 1 / H10). Toujours les copier tous les deux.
COPY server/package.json ./
COPY server/index.js ./
COPY server/apns.js ./
COPY server/messages-store.js ./
COPY server/public ./public

ENV NODE_ENV=production
# Persistance SQLite. /tmp est inscriptible sur Heroku. ⚠️ Le disque d'un dyno
# Heroku est ÉPHÉMÈRE : ce fichier survit aux redémarrages du process mais est
# effacé à chaque déploiement / recyclage de dyno. Pour une persistance DURABLE
# sur Heroku, utiliser une base gérée (Postgres) plutôt qu'un fichier.
ENV DB_PATH=/tmp/brocolis-messages.db
EXPOSE 8788

USER node

CMD ["node", "index.js"]
