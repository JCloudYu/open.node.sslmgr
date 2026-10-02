FROM node:23-bookworm-slim AS deps

WORKDIR /app
ENV NODE_ENV=production

RUN npm install -g pnpm@10

COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod


FROM node:23-bookworm-slim

WORKDIR /app
ENV NODE_ENV=production

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	&& npm install -g pnpm@10 tsx

COPY --from=deps /app/node_modules ./node_modules
COPY . .

EXPOSE 63039

# /app/storage   : 憑證目錄（STORAGE_DIR），server 與 cron 共用
# /var/log/sslmgr: cron 執行結果 log
VOLUME ["/app/storage", "/var/log/sslmgr"]

CMD ["sh", "-c", "mkdir -p \"${STORAGE_DIR:-./storage}\" && BIND_HOST=\"${BIND_HOST:-0.0.0.0}\" BIND_PORT=\"${BIND_PORT:-${PORT:-63039}}\" pnpm start"]