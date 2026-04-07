FROM python:3.12-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
RUN mkdir -p /var/www/files && echo 'public content' > /var/www/files/public.txt
EXPOSE 8080
CMD ["python3", "server.py"]
