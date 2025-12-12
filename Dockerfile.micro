# netflow-collector/Dockerfile.micro
FROM python:3.11-slim-buster

# Метаданные
LABEL org.opencontainers.image.title="NetFlow Collector"
LABEL org.opencontainers.image.description="Collects NetFlow data and stores in PostgreSQL"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="NetFlow Team"

# Устанавливаем зависимости
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    gnupg \
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Добавляем ключ для PostgreSQL
RUN curl https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -

WORKDIR /app

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY netflow_collector.py .
COPY cleanup_db.py .
COPY utils/ ./utils/
COPY config/ ./config/

# Копируем конфигурационные файлы
COPY docker-entrypoint.sh .
COPY healthcheck.py .
COPY prometheus.yml .

# Делаем скрипты исполняемыми
RUN chmod +x docker-entrypoint.sh healthcheck.py

# Создаем пользователя
RUN useradd -m -u 1000 netflow && \
    chown -R netflow:netflow /app

USER netflow

# Порт для NetFlow и метрик
EXPOSE 2055/udp 9996/udp 9090/tcp

# Точка входа
ENTRYPOINT ["./docker-entrypoint.sh"]
