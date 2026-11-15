FROM eclipse-temurin:17-jre-jammy

RUN apt-get update \
 && apt-get install -y curl ca-certificates \
 && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y nodejs \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY vineflower.jar ./

ENV PORT=8787
EXPOSE 8787
CMD ["node", "server.js"]
