# Local development image. dev_stack.py seeds synthetic data, so this is not a production image.
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml alembic.ini ./
COPY src ./src
COPY migrations ./migrations
COPY scripts ./scripts
RUN pip install --no-cache-dir -e . httpx
RUN useradd --create-home aegis && mkdir -p /app/.dev && chown aegis /app/.dev
USER aegis
CMD ["python", "scripts/dev_stack.py"]
