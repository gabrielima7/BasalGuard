# ── Build stage ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

# Avoid interactive prompts and bytecode clutter
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install Poetry (pinned version for reproducibility)
RUN pip install --no-cache-dir poetry==2.3.2 && \
    poetry config virtualenvs.create false

# Copy dependency files first (layer caching)
COPY pyproject.toml poetry.lock ./

# Install runtime dependencies only (no dev)
RUN poetry install --only main --no-interaction --no-ansi

# ── Runtime stage ────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create non-root user for security
RUN groupadd --gid 1000 basaluser && \
    useradd --uid 1000 --gid basaluser --create-home basaluser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src/ ./src/
COPY interactive_agent.py ./
COPY pyproject.toml ./

# Create workspace directory owned by basaluser
RUN mkdir -p /app/safe_workspace && \
    chown -R basaluser:basaluser /app

# Switch to non-root user
USER basaluser

# Ensure src is in PYTHONPATH
ENV PYTHONPATH="/app/src:/app/src/taipanstack_repo/src:${PYTHONPATH}"

# Default env vars (overridden at runtime)
ENV GROQ_API_KEY="" \
    OPENAI_API_KEY="" \
    OPENAI_BASE_URL="https://api.groq.com/openai/v1" \
    OPENAI_MODEL="llama-3.3-70b-versatile"

ENTRYPOINT ["python", "interactive_agent.py"]
