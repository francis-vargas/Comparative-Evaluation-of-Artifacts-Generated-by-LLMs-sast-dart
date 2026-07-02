# dart_sast - containerized distribution
#
# Build:  docker build -t dart_sast:latest .
# Run:    docker run --rm -v "$(pwd)":/src dart_sast:latest /src --format json
#
# Using a slim Python base keeps the image small; dart_sast has zero
# third-party runtime dependencies, so no extra layers are needed for
# package installation beyond the tool itself.

FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="dart_sast"
LABEL org.opencontainers.image.description="Static Application Security Testing (SAST) for Dart/Flutter code"
LABEL org.opencontainers.image.source="https://github.com/example/dart_sast"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src/ /app/src/

RUN pip install --no-cache-dir .

# The tool scans whatever directory is mounted at /src by default.
WORKDIR /src
ENTRYPOINT ["dart_sast"]
CMD ["--help"]
