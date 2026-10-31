FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PORT=5050 FLASK_DEBUG=1
EXPOSE 5050
CMD ["python", "app.py"]
