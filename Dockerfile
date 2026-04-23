ARG PHP_VERSION=8.2
FROM darrenedale/equit:php-${PHP_VERSION}-cli
RUN printf "totp\ntotp\n" | adduser -u 1000 -h /php-totp totp
