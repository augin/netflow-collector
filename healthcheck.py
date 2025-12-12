#!/usr/bin/env python3
"""
Health check для Docker контейнера
"""

import socket
import sys
import os
import psycopg2
from datetime import datetime

def check_udp_socket():
    """Проверка возможности создания UDP сокета"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.bind(('0.0.0.0', 0))
        sock.close()
        return True
    except Exception as e:
        print(f"UDP socket check failed: {e}")
        return False

def check_database():
    """Проверка подключения к базе данных"""
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            database=os.getenv('DB_NAME', 'netflow_db'),
            user=os.getenv('DB_USER', 'netflow_user'),
            password=os.getenv('DB_PASSWORD', '')
        )
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Database check failed: {e}")
        return False

def check_log_file():
    """Проверка доступности лог-файла"""
    log_file = os.getenv('LOG_FILE', '/app/logs/netflow.log')
    if os.path.exists(log_file):
        # Проверяем, что файл был обновлен недавно (в течение 5 минут)
        stat = os.stat(log_file)
        last_modified = datetime.fromtimestamp(stat.st_mtime)
        age = (datetime.now() - last_modified).total_seconds()
        if age < 300:  # 5 минут
            return True
        else:
            print(f"Log file too old: {age} seconds")
            return False
    else:
        # Файл может не существовать, если нет записей
        return True

def main():
    """Основная функция проверки здоровья"""
    checks = [
        ("UDP Socket", check_udp_socket),
        ("Database", check_database),
        ("Log File", check_log_file)
    ]
    
    all_ok = True
    for name, check_func in checks:
        if check_func():
            print(f"✓ {name}: OK")
        else:
            print(f"✗ {name}: FAILED")
            all_ok = False
    
    sys.exit(0 if all_ok else 1)

if __name__ == "__main__":
    main()
