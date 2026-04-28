FROM node:20-alpine

WORKDIR /app

# Install build deps for better-sqlite3
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm install --production

COPY . .

# Create data dir for SQLite
RUN mkdir -p /app/data

EXPOSE 3000

ENV NODE_ENV=production
ENV JWT_SECRET=quicknotes-prod-secret-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

CMD ["node", "server.js"]
