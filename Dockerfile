# Stage 1: Build TypeScript
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

# Stage 2: Production Image with Full Networking Tools
FROM node:22-alpine AS runner

# Install essential network reconnaissance & diagnostic utilities
RUN apk add --no-cache \
    bind-tools \
    curl \
    whois \
    openssl \
    ca-certificates \
    tini \
    bash

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000
ENV RUNNING_IN_DOCKER=true

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY public ./public

EXPOSE 3000
VOLUME [ "/app/data" ]

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/server.js"]
