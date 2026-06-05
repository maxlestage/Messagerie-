# Relais de rendez-vous brocolis 🥦 — image minimale (Node, sans dépendances).
FROM node:22-alpine

WORKDIR /app

# Pas de dépendances externes : on copie juste les sources.
COPY package.json ./
COPY index.js ./

ENV NODE_ENV=production
ENV PORT=8788
EXPOSE 8788

# N'exécute pas en root.
USER node

# Vérifie que le serveur répond sur /health.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- "http://127.0.0.1:${PORT:-8788}/health" || exit 1

CMD ["node", "index.js"]
