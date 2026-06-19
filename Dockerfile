FROM node:20-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl libcurl4 libssl3 libstdc++6 \
  && rm -rf /var/lib/apt/lists/*

ARG PLAYIT_VERSION=0.17.1
RUN curl -fsSL "https://github.com/playit-cloud/playit-agent/releases/download/v${PLAYIT_VERSION}/playit-linux-amd64" -o /usr/local/bin/playit \
  && echo "e78d463d93aa1e3ec36a06ded5a1f4fe879905fdceb865df8f4cef6124f8a555  /usr/local/bin/playit" | sha256sum -c - \
  && chmod 0755 /usr/local/bin/playit

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
