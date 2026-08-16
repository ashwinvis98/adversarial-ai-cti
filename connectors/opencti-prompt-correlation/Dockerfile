FROM python:3.12-slim

WORKDIR /opt/connector

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

WORKDIR /opt/connector/src
CMD ["python", "main.py"]
