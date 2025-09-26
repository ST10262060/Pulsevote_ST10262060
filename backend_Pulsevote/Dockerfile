FROM node:22-alpine3.20 AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM node:22-alpine3.20 AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5000
EXPOSE 5000

HEALTHCHECK CMD node -e "require('http').get('http://localhost:'+ (process.env.PORT||5000) +'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

RUN addgroup -S nodegrp && adduser -S nodeuser -G nodegrp
USER nodeuser

COPY --from=deps /app/node_modules ./node_modules
COPY . .
CMD ["npm","start"]