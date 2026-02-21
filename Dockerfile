# ─── Stage 1: Build ──────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files first for better layer caching
COPY package.json package-lock.json ./

# Install production dependencies only
RUN npm ci --omit=dev

# ─── Stage 2: Production ─────────────────────────────────────────────
FROM node:20-alpine

# Security: run as non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy deps from builder stage
COPY --from=builder /app/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY server.js ./
COPY config/ ./config/
COPY models/ ./models/
COPY routes/ ./routes/
COPY middleware/ ./middleware/
COPY scripts/ ./scripts/
COPY public/ ./public/

# Create uploads directory with correct ownership
RUN mkdir -p /app/uploads && chown -R appuser:appgroup /app

# Environment variables (defaults, override at runtime)
ENV NODE_ENV=production
ENV PORT=3000

# Expose the application port
EXPOSE 3000

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Start the application
CMD ["node", "server.js"]
