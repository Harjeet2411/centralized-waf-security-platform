# Console image for the local docker-compose stack: build the Vite SPA, serve it with nginx, and proxy /api and /ws
# to the FastAPI service so the browser stays same-origin (HttpOnly SameSite=Strict session cookie).
# Production serves the same dist/ from S3 + CloudFront (infra/central_account/app.yaml).
FROM node:22-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 80
