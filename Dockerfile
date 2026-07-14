# Déploiement Heroku EN CONTENEUR du serveur de rendez-vous, depuis la racine
# du dépôt. Référencé par heroku.yml. Ne copie que le serveur (server/), pas
# l'app iOS ni le site.
FROM node:22-alpine

WORKDIR /app

# Le serveur n'a aucune dépendance externe : on copie ses sources + la vitrine
# pré-construite (servie sur /site/). index.js fait require('./apns.js') au
# démarrage : SANS ce fichier, le conteneur plante au boot (exit 1 / H10).
COPY server/package.json ./
COPY server/index.js ./
COPY server/apns.js ./
COPY server/public ./public

ENV NODE_ENV=production
EXPOSE 8788

USER node

CMD ["node", "index.js"]
