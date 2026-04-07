FROM php:8.3-cli-alpine

RUN apk add --no-cache curl unzip \
    && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

WORKDIR /app

RUN composer require twig/twig smarty/smarty --no-interaction --prefer-dist

COPY index.php /app/index.php

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080", "index.php"]
