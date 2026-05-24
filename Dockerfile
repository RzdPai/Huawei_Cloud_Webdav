FROM node:24-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY webdav.js ./

EXPOSE 1900

ENV DAEMON=1
ENV PORT=1900

CMD ["node", "webdav.js"]