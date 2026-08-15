FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
RUN cp /root/.opengrep/cli/latest/opengrep /usr/local/bin/opengrep \
    && chmod 0755 /usr/local/bin/opengrep

RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /src

CMD ["opengrep", "--help"]
