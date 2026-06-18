FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libcurl4 libssl3 libstdc++6 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY src ./src

RUN mkdir -p /opt/bedrock-seed

ENV NODE_ENV=production
ENV SERVER_DIR=/data/servers/principal
ENV SERVERS_DIR=/data/servers
ENV BACKUP_ROOT=/data/backups
ENV SEED_DIR=/opt/bedrock-seed
ENV AUTO_START=true

EXPOSE 3000/tcp
EXPOSE 19132/udp
EXPOSE 19133/udp

CMD ["npm", "start"]
