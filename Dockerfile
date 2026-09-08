FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py alembic.ini seed_admin.py ./
COPY config ./config
COPY db ./db
COPY security ./security
COPY rotas ./rotas
COPY alembic ./alembic

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
