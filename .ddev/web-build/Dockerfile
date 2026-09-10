# Adds PCOV so local coverage runs use the same driver as the PHP 8.4 CI job
# (Xdebug and PCOV instrument differently, so their figures drift by a fraction).
# DDEV passes the project's PHP version in as a build argument; the sury
# repository the web image already uses ships php<version>-pcov.
ARG DDEV_PHP_VERSION
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "php${DDEV_PHP_VERSION}-pcov" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
