# Déploiement Heroku EN CONTENEUR du serveur de rendez-vous, depuis la racine
# du dépôt. Référencé par heroku.yml. Ne copie que le serveur (server/), pas
# l'app iOS ni le site.
FROM node:22-alpine

WORKDIR /app

# Le serveur n'a aucune dépendance externe : on copie juste ses sources.
COPY server/package.json ./
COPY server/index.js ./

ENV NODE_ENV=production
EXPOSE 8788

USER node

CMD ["node", "index.js"]
