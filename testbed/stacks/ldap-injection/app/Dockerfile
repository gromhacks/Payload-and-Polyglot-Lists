FROM python:3.12-alpine
RUN apk add --no-cache openldap-dev gcc musl-dev
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
CMD ["python", "server.py"]
