FROM python:3.12-alpine

WORKDIR /app

RUN adduser -D -u 1000 app

COPY auth-policy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY --chown=1000:1000 auth-policy/app /app/app

USER 1000:1000

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
