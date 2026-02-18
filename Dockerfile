# ----------------------------
# 1️⃣ Build React frontend
# ----------------------------
# FROM node:20-alpine AS frontend-build
FROM oven/bun:latest AS client-build
WORKDIR /client

# Copy frontend package.json and install dependencies
COPY client/package*.json ./
RUN bun install

# Copy all frontend files and build
COPY client ./
RUN bun run build

# ----------------------------
# 2️⃣ Build backend
# ----------------------------
# FROM node:20-alpine
FROM oven/bun:latest
WORKDIR /app

# Copy backend package.json and install production dependencies
COPY server/package*.json ./
RUN bun install --production

# Copy backend source code
COPY server ./

# Copy built frontend from previous stage
COPY --from=client-build /client/dist ./client/dist

# Set production environment
ENV NODE_ENV=production
EXPOSE 3004

# Start server
CMD ["node", "server.js"]
