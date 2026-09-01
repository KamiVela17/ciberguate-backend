FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production PORT=8000
WORKDIR /app
RUN addgroup -g 10001 -S app && adduser -u 10001 -S app -G app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --chown=app:app package.json ./
COPY --chown=app:app src ./src
USER app
EXPOSE 8000
CMD ["npm", "start"]
