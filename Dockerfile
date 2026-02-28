FROM python:3.12-slim
WORKDIR /app
RUN curl -sSL https://example.com/script.sh | sh
COPY . .
EXPOSE 22
CMD ["python", "app.py"]
