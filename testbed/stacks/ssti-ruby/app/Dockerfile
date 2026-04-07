FROM ruby:3.3-alpine
WORKDIR /app
RUN apk add --no-cache build-base && gem install sinatra rackup puma slim haml --no-doc
COPY server.rb .
EXPOSE 8080
CMD ["ruby", "server.rb"]
