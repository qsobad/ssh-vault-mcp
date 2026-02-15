FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY tsconfig.json ./
COPY src ./src
COPY web ./web

RUN npm run build

# Production image
FROM node:20-alpine

WORKDIR /app

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/web ./web
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./

# Create data directory
RUN mkdir -p /app/data

# Set environment
ENV NODE_ENV=production
ENV SSH_VAULT_CONFIG=/app/config.yml

# Expose ports
EXPOSE 3000 3001

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

# Run
CMD ["node", "dist/index.js"]
