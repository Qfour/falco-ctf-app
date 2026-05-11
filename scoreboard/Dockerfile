FROM python:3.12-alpine

WORKDIR /app

RUN apk add --no-cache --virtual .build curl \
 && adduser -D -u 1000 app \
 && apk del .build

# Build context is the repo root (so we can COPY challenges/ alongside scoreboard/app/).
COPY scoreboard/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=1000:1000 scoreboard/app /app/app
# Challenge catalog is baked in by default; can be overridden with a
# CHALLENGES_DIR env var or a volume mount at /app/challenges.
COPY --chown=1000:1000 challenges /app/challenges

USER 1000:1000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
