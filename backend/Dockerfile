FROM node:18-alpine3.17
USER root

RUN apk update && apk upgrade && apk add g++ make py3-pip

WORKDIR /app
COPY ./package* ./

RUN npm install -g npm@9
RUN npm ci

COPY . .

ENV IS_OFFLINE "true"

CMD ["npx", "ts-node-dev", "src/api-dev.ts"]
