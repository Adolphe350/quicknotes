FROM node:20-alpine

WORKDIR /app

# Install build deps for better-sqlite3
RUN apk add --no-cache python3 make g++ sqlite

COPY package*.json ./
RUN npm install

COPY . .

# Data directory will be mounted as volume
RUN mkdir -p /app/data

EXPOSE 3000

ENV NODE_ENV=production

CMD ["node", "server.js"]
