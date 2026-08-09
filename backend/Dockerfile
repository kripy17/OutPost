# OutPost backend — FastAPI app server.
#
# The collectors never run here: they live on the machines being monitored
# (outpost agent install) and stream into this backend over HTTP.
FROM python:3.12-slim

WORKDIR /srv/outpost

# Runtime deps only (the app is a plain package dir; PYTHONPATH serves it).
RUN pip install --no-cache-dir \
    "fastapi>=0.110" \
    "uvicorn[standard]>=0.29" \
    "pydantic>=2.6" \
    "requests>=2.31" \
    "httpx>=0.27" \
    "reportlab>=4.0"

COPY app ./app
ENV PYTHONPATH=/srv/outpost

# Persist the SQLite DB outside the container (docker-compose mounts /data).
ENV DATABASE_PATH=/data/outpost.db
VOLUME /data

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
