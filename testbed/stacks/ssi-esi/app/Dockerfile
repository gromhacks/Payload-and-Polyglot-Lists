FROM python:3.12-alpine
RUN pip install --no-cache-dir flask
COPY server.py /app/server.py
WORKDIR /app
CMD ["python3", "server.py"]
