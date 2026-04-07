FROM ruby:3.3-alpine
WORKDIR /app
RUN apk add --no-cache build-base && gem install sinatra puma rackup base64 oj --no-doc && apk del build-base
COPY server.rb .
EXPOSE 8080
CMD ["ruby", "server.rb"]
