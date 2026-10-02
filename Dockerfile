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

EXPOSE 3000

CMD ["sh", "-c", "mkdir -p \"${STORAGE_DIR:-./storage}\" && BIND_HOST=\"${BIND_HOST:-0.0.0.0}\" BIND_PORT=\"${BIND_PORT:-${PORT:-3000}}\" pnpm start"]