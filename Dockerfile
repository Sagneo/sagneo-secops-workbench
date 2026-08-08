FROM python:3.12.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends --yes openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --no-create-home app
COPY requirements.txt /app/
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY pyproject.toml /app/
COPY app /app/app
COPY fixtures /app/fixtures
COPY rules /app/rules
COPY alembic.ini /app/
COPY alembic /app/alembic
RUN mkdir /data && chown 10001:10001 /data

USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
