# Multi-stage production build for AegisID Decentralized Identity Wallet
FROM node:22-alpine AS builder

WORKDIR /app

# Build Frontend
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci

COPY frontend ./frontend
RUN cd frontend && npm run build

# Production Runtime
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5000
ENV DATA_DIR=/app/backend/data
ENV NODE_OPTIONS=--disable-warning=ExperimentalWarning

# Install Backend Dependencies
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --omit=dev

# Copy backend source & built frontend dist
COPY backend ./backend
COPY --from=builder /app/frontend/dist ./frontend/dist

# Run as the unprivileged "node" user; it only needs to write backend/data
RUN mkdir -p backend/data && chown -R node:node backend/data
USER node

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||5000)+'/api/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "backend/server.js"]
