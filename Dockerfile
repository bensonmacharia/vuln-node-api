# FROM node:14
FROM --platform=linux/amd64 node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE ${PORT}

CMD ["node", "app.js"]
