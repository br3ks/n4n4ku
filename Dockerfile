# Stage 1: Build TypeScript
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src ./src
RUN npm run build

# Stage 2: Download pre-compiled security tools & wordlists
FROM alpine:3.20 AS tools

RUN apk add --no-cache curl unzip tar git

WORKDIR /tools/bin

# ProjectDiscovery suite (latest releases)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip -o nuclei.zip \
    && unzip -o nuclei.zip nuclei -d . && rm nuclei.zip \
    && curl -sSL https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip -o katana.zip \
    && unzip -o katana.zip katana -d . && rm katana.zip \
    && curl -sSL https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_amd64.zip -o subfinder.zip \
    && unzip -o subfinder.zip subfinder -d . && rm subfinder.zip \
    && curl -sSL https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip -o httpx.zip \
    && unzip -o httpx.zip httpx -d . && rm httpx.zip \
    && curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz | tar xzf - ffuf \
    && chmod +x nuclei katana subfinder httpx ffuf

# SecLists (sparse checkout: only Discovery/Web-Content and Discovery/DNS)
RUN git clone --no-checkout --depth 1 https://github.com/danielmiessler/SecLists.git /tools/seclists \
    && cd /tools/seclists \
    && git sparse-checkout init --cone \
    && git sparse-checkout set Discovery/Web-Content Discovery/DNS \
    && git checkout \
    && rm -rf .git

# Stage 3: Production Image
FROM node:22-alpine AS runner

# Network recon utilities + Go binary runtime deps
RUN apk add --no-cache \
    bind-tools \
    curl \
    whois \
    openssl \
    ca-certificates \
    tini \
    bash \
    libstdc++ \
    libgcc

# Copy tool binaries and wordlists from tools stage
COPY --from=tools /tools/bin/* /usr/local/bin/
COPY --from=tools /tools/seclists/Discovery /usr/share/seclists/Discovery

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
