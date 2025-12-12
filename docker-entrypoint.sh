#!/bin/bash
set -e

echo "Starting NetFlow Collector..."
echo "Environment variables:"
echo "  NETFLOW_PORT: ${NETFLOW_PORT}"
echo "  DB_HOST: ${DB_HOST}"
echo "  DB_NAME: ${DB_NAME}"
echo "  LOG_LEVEL: ${LOG_LEVEL}"

# Ждем готовности базы данных
if [ "$WAIT_FOR_DB" = "true" ]; then
    echo "Waiting for database to be ready..."
    until pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER"; do
        echo "Database is unavailable - sleeping"
        sleep 2
    done
    echo "Database is ready!"
fi

# Проверяем наличие таблиц
if [ "$CHECK_DB_TABLES" = "true" ]; then
    echo "Checking database tables..."
    python -c "
import psycopg2
import os
import sys

try:
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST'),
        port=os.getenv('DB_PORT'),
        database=os.getenv('DB_NAME'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    )
    cursor = conn.cursor()
    
    # Проверяем существование схемы
    schema = os.getenv('DB_SCHEMA', 'netflow')
    cursor.execute(f\"SELECT schema_name FROM information_schema.schemata WHERE schema_name = '{schema}';\")
    
    if not cursor.fetchone():
        print(f'Creating schema {schema}...')
        cursor.execute(f'CREATE SCHEMA {schema};')
        conn.commit()
    
    conn.close()
    print('Database check completed.')
except Exception as e:
    print(f'Database check failed: {e}')
    sys.exit(1)
"
fi

# Создаем директорию для логов если её нет
mkdir -p /app/logs

# Запускаем очистку по расписанию если включено
if [ "$ENABLE_CLEANUP" = "true" ]; then
    echo "Setting up scheduled cleanup..."
    echo "$CLEANUP_SCHEDULE python cleanup_db.py --days $RETENTION_DAYS --vacuum --analyze >> /app/logs/cleanup.log 2>&1" | crontab -
    crond -f &
fi

# Запускаем основной процесс
exec python netflow_collector.py "$@"
