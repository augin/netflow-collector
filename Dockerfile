# netflow-collector/Dockerfile
FROM python:3.11-slim AS builder

WORKDIR /app

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копируем зависимости
COPY requirements.txt .

# Устанавливаем Python зависимости
RUN pip install --no-cache-dir --user -r requirements.txt

# Финальный образ
FROM python:3.11-slim

# Устанавливаем только runtime зависимости
RUN apt-get update && apt-get install -y \
    libpq5 \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Создаем пользователя для безопасности
RUN groupadd -r netflow && useradd -r -g netflow netflow

WORKDIR /app

# Копируем установленные пакеты из builder
COPY --from=builder /root/.local /home/netflow/.local

# Копируем исходный код
COPY --chown=netflow:netflow . .

# Устанавливаем пути Python
ENV PATH=/root/.local/bin:$PATH
ENV PYTHONPATH=/app:$PYTHONPATH

# Создаем директории для логов и данных
RUN mkdir -p /app/logs /app/data && \
    chown -R netflow:netflow /app

USER netflow

# Открываем порт для NetFlow (обычно 2055 или 9996)
EXPOSE 2055/udp
EXPOSE 9996/udp
EXPOSE 8080/tcp

# Переменные окружения по умолчанию
ENV NETFLOW_PORT=2055
ENV LOG_LEVEL=INFO
ENV LOG_FILE=/app/logs/netflow.log
ENV DB_HOST=postgres
ENV DB_PORT=5432
ENV DB_NAME=netflow_db
ENV DB_USER=netflow_user
ENV DB_PASSWORD=netflow_password
ENV DB_SCHEMA=netflow

# Health check для мониторинга
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import socket; sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
    sock.settimeout(2); sock.bind(('0.0.0.0', 0)); sock.close()" || exit 1

# Команда по умолчанию
CMD ["python", "netflow_collector.py"]
