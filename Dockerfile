FROM python:latest
WORKDIR /app
RUN curl -sSL https://example.com/script.sh | sh
COPY . .
EXPOSE 22
CMD ["python", "app.py"]
