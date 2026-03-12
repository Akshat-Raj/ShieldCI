FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm ci --omit=dev
COPY src/ src/
USER 1000
EXPOSE 3002
CMD ["node", "src/index.js"]
