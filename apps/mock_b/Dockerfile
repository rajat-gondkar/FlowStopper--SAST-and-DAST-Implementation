# shoplite-b (Mock B) - deliberately vulnerable FastAPI fixture app (our own work, R8).
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/apps/mock_b
ENV PYTHONPATH=/app SHOPLITE_B_DATA=/app/data
EXPOSE 8090

CMD ["uvicorn", "apps.mock_b.main:app", "--host", "0.0.0.0", "--port", "8090"]
