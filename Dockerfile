FROM jcloudyu/node-cron:23-bookworm
COPY . .
RUN pnpm install