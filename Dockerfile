FROM node:22-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src/ src/
RUN npx tsc

FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/dist/ dist/
COPY web/ web/
RUN mkdir -p /app/data /app/config
VOLUME ["/app/data", "/app/config"]
EXPOSE 3001
CMD ["node", "dist/index.js"]
