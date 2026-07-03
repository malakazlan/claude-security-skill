# Zero-install runner: all scanners preloaded.
#   docker build -t claude-security .
#   docker run --rm -v "$PWD":/repo -e ANTHROPIC_API_KEY \
#       claude-security python3 scripts/scan.py /repo
FROM python:3.12-slim

ENV PATH="/root/.local/bin:${PATH}"
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

# Copy the tool first so install.sh is available
COPY . /app

# install.sh pins versions and degrades gracefully if any single tool fails
RUN chmod +x install.sh && ./install.sh || true

# Sanity: the orchestrator must import and show help even if some tools missing
RUN python3 scripts/scan.py --help >/dev/null

ENTRYPOINT []
CMD ["python3", "scripts/scan.py", "--help"]
