FROM node:20-alpine
WORKDIR /app
COPY package*.json .npmrc ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 3939
CMD ["node", "server.js"]
