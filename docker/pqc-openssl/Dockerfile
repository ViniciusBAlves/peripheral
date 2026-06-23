FROM debian:trixie-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        mosquitto \
        mosquitto-clients \
        openssl \
    && rm -rf /var/lib/apt/lists/*

RUN openssl version | grep -E '^OpenSSL 3\.[5-9]\.' \
    && openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256s'

CMD ["sleep", "infinity"]
