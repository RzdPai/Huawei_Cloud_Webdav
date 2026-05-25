FROM node:24-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY docker.js ./

EXPOSE 1900

ENV PORT=1900

CMD ["node", "docker.js"]