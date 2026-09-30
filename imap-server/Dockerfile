FROM node:20-alpine
WORKDIR /app
COPY package*.json .npmrc ./
RUN npm ci --omit=dev
COPY . .
EXPOSE 993
CMD ["node", "src/index.js"]
