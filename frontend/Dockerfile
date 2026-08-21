# OutPost frontend — build once with Vite, serve the static bundle with nginx.
#
# VITE_API_URL is baked in at build time: it's where the *browser* reaches the
# backend. Local docker run → http://localhost:8001 (compose passes it); a
# remote server → http://<server>:8001 via --build-arg.
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ARG VITE_API_URL=http://localhost:8001
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
