# Local development image.
FROM node:22-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build
USER node
CMD ["npx", "next", "start", "--hostname", "0.0.0.0", "--port", "3000"]
