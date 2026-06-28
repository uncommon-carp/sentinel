FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
RUN useradd --uid 1001 --no-create-home sentinel && \
    mkdir -p /app/sentinel-out && \
    chown sentinel:sentinel /app/sentinel-out
USER sentinel
ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["scan"]
