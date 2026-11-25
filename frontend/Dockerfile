# Static SecurCode web console served by nginx, proxying /api/v1 to the API
# so the session cookie stays first-party.
FROM node:22-alpine AS build
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
ENV VITE_SAME_ORIGIN_API=true
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
USER 101
COPY frontend/deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
