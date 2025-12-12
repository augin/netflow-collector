#!/bin/bash
# Скрипт для сборки и запуска NetFlow коллектора в Docker

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}NetFlow Collector Docker Builder${NC}"
echo "=============================="

# Проверяем наличие Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Ошибка: Docker не установлен${NC}"
    exit 1
fi

# Проверяем наличие docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}Предупреждение: docker-compose не установлен, будет использован docker compose${NC}"
fi

# Создаем .env файл если его нет
if [ ! -f .env ]; then
    echo -e "${YELLOW}Создаю файл .env из примера...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
        echo "Пожалуйста, отредактируйте файл .env перед запуском"
    else
        echo "DB_HOST=postgres" > .env
        echo "DB_PORT=5432" >> .env
        echo "DB_NAME=netflow_db" >> .env
        echo "DB_USER=netflow_user" >> .env
        echo "DB_PASSWORD=$(openssl rand -base64 32)" >> .env
        echo "DB_SCHEMA=netflow" >> .env
        echo "NETFLOW_PORT=2055" >> .env
        echo "LOG_LEVEL=INFO" >> .env
        echo "LOG_FILE=/app/logs/netflow.log" >> .env
        echo -e "${GREEN}Файл .env создан с случайным паролем${NC}"
    fi
fi

# Спрашиваем пользователя о действии
PS3="Выберите действие: "
options=("Собрать и запустить" "Только собрать образ" "Запустить существующий образ" "Остановить все контейнеры" "Просмотреть логи" "Войти в контейнер" "Выход")
select opt in "${options[@]}"
do
    case $opt in
        "Собрать и запустить")
            echo -e "${GREEN}Сборка и запуск NetFlow коллектора...${NC}"
            docker-compose up --build -d
            echo -e "${GREEN}Запущено!${NC}"
            echo "NetFlow Collector: http://localhost:8080"
            echo "PostgreSQL: localhost:5432"
            echo "Grafana: http://localhost:3000 (admin/admin)"
            break
            ;;
        "Только собрать образ")
            echo -e "${GREEN}Сборка образа NetFlow коллектора...${NC}"
            docker-compose build
            echo -e "${GREEN}Сборка завершена!${NC}"
            break
            ;;
        "Запустить существующий образ")
            echo -e "${GREEN}Запуск существующего образа...${NC}"
            docker-compose up -d
            echo -e "${GREEN}Запущено!${NC}"
            break
            ;;
        "Остановить все контейнеры")
            echo -e "${YELLOW}Остановка всех контейнеров...${NC}"
            docker-compose down
            echo -e "${GREEN}Остановлено!${NC}"
            break
            ;;
        "Просмотреть логи")
            echo -e "${GREEN}Просмотр логов NetFlow коллектора:${NC}"
            docker-compose logs -f netflow-collector
            break
            ;;
        "Войти в контейнер")
            echo -e "${GREEN}Вход в контейнер NetFlow коллектора...${NC}"
            docker-compose exec netflow-collector /bin/bash
            break
            ;;
        "Выход")
            echo -e "${GREEN}Выход...${NC}"
            break
            ;;
        *) echo "Неверный вариант $REPLY";;
    esac
done
