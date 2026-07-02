FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY dart_sast ./dart_sast
RUN pip install --no-cache-dir .
ENTRYPOINT ["dart_sast"]
