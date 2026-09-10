FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency management
RUN pip install --no-cache-dir uv

COPY . .

# Fail closed if the tracked local OAuth template ever enters the image.
RUN test ! -e /app/.env.oauth21 && test ! -L /app/.env.oauth21

# Install Python dependencies using uv sync
RUN uv sync --frozen --no-dev --extra disk

# COPY and dependency installation run as root. Keep the runtime immutable to
# the service user so privileged maintenance can safely trust these paths.
RUN useradd --create-home --shell /bin/bash app \
    && chmod -R go-w /app

# Only data is application-owned. Home-based credentials, logs, attachments,
# and OAuth storage remain writable under /home/app. Mounted volumes must be
# provisioned separately; never recursively chown a live data volume at startup.
RUN install -d -o app -g app -m 700 /app/store_creds

USER app

# Expose port (use default of 8000 if PORT not set)
EXPOSE 8000
# Expose additional port if PORT environment variable is set to a different value
ARG PORT
EXPOSE ${PORT:-8000}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD sh -c 'curl -f http://localhost:${PORT:-8000}/health || exit 1'

# Set environment variables for Python startup args
ENV TOOL_TIER=""
ENV TOOLS=""

# Use entrypoint for the base command and CMD for args
ENTRYPOINT ["/bin/sh", "-c"]
# Dependencies are synchronized at build time only. Do not rewrite the protected
# environment or bytecode at startup; exec also forwards signals to Python.
CMD ["exec /app/.venv/bin/python -B main.py --transport streamable-http ${TOOL_TIER:+--tool-tier \"$TOOL_TIER\"} ${TOOLS:+--tools $TOOLS}"]
