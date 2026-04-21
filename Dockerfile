FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy metadata first to leverage layer caching.
COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY examples ./examples

# cel-python 0.4.0 is the last release without a hard google-re2 native
# dependency; we pin it deliberately so the container builds on any host.
RUN pip install --upgrade pip && \
    pip install --no-deps cel-python==0.4.0 pendulum lark tomli jmespath python-dateutil && \
    pip install . && \
    pip install 'uvicorn[standard]' fakeredis

EXPOSE 8080

CMD ["uvicorn", "agentguard.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]
