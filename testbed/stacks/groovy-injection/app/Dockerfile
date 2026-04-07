FROM groovy:4-jdk21-alpine
USER root
RUN apk add --no-cache curl
USER groovy
COPY server.groovy /app/server.groovy
WORKDIR /app
EXPOSE 8080
CMD ["groovy", "server.groovy"]
