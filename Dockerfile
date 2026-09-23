# syntax=docker/dockerfile:1
FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c AS lego-download
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
      amd64) checksum=ebb33f1bead5a7c99dd46f1c5734b44cf1eab5b5c12faf397cd14d50a5916419 ;; \
      arm64) checksum=8494c06bde449ac4d65c726b7ea50d67ac61f422e698c9b78b47778445b098f2 ;; \
      *) echo 'Unsupported architecture' >&2; exit 1 ;; esac; \
    curl --fail --location --retry 3 "https://github.com/go-acme/lego/releases/download/v5.4.1/lego_v5.4.1_linux_${arch}.tar.gz" -o /tmp/lego.tar.gz; \
    echo "$checksum  /tmp/lego.tar.gz" | sha256sum -c -; \
    mkdir /lego && tar -xzf /tmp/lego.tar.gz -C /lego lego LICENSE

FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c
LABEL org.opencontainers.image.title="VCF Certificate Renewer" \
      org.opencontainers.image.version="1.3.1" \
      org.opencontainers.image.source="https://github.com/kiefer413/vcf-cert-renewer"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OUTPUT_DIR=/data
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 renewer \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data renewer \
    && mkdir /app /data && chown 10001:10001 /data
WORKDIR /app
COPY packaging/requirements-container.txt /app/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY --from=lego-download /lego/lego /usr/local/bin/lego
COPY --from=lego-download /lego/LICENSE /usr/local/share/lego-LICENSE
COPY vcf_cert_renewer /app/vcf_cert_renewer
COPY packaging/container-entrypoint.sh /usr/local/bin/vcf-cert-renewer
RUN chmod 0755 /usr/local/bin/vcf-cert-renewer
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/vcf-cert-renewer"]
CMD ["--help"]
