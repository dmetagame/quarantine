FROM node:22.22.0-bookworm-slim

WORKDIR /app

COPY --chown=node:node index.html package.json package-lock.json ./
COPY --chown=node:node public ./public
COPY --chown=node:node src ./src
COPY --chown=node:node scripts/demo-server.mjs ./scripts/demo-server.mjs

ENV NODE_ENV=production \
    QUARANTINE_DEMO_HOST=0.0.0.0 \
    QUARANTINE_DEMO_PORT=4173

USER node
EXPOSE 4173

HEALTHCHECK --interval=10s --timeout=5s --start-period=120s --retries=12 \
  CMD node -e "fetch('http://127.0.0.1:4173/api/health').then((response) => process.exit(response.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "scripts/demo-server.mjs"]
