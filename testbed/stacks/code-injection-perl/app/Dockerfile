FROM perl:5-slim
RUN cpanm Mojolicious YAML
WORKDIR /app
COPY server.pl .
EXPOSE 8080
CMD ["perl", "server.pl", "daemon", "-l", "http://0.0.0.0:8080"]
