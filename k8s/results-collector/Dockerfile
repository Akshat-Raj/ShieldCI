FROM node:18-alpine
WORKDIR /app
COPY package.json ./
RUN npm ci --omit=dev
COPY src/ src/
USER 1000
EXPOSE 8080 8443
CMD ["node", "src/index.js"]
