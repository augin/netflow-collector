# 1. Клонируйте проект
'''
git clone https://github.com/augin/netflow-collector.git
cd netflow-collector
'''

# 2. Создайте .env файл (или используйте существующий)
'''cp .env.example .env'''
# Отредактируйте .env файл

# 3. Соберите и запустите
'''docker compose up --build -d'''

# 4. Проверьте статус
docker compose ps

# 5. Просмотрите логи
docker compose logs -f netflow-collector

# 6. Остановите контейнеры
docker compose down

# Или используйте Makefile
make build
make run
make logs


# Проверьте, что коллектор принимает пакеты
docker-compose exec netflow-collector python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2055))
print('Listening on port 2055...')
data, addr = sock.recvfrom(1024)
print(f'Received {len(data)} bytes from {addr}')
"

# Проверьте базу данных
docker compose exec postgres psql -U netflow_user -d netflow_db -c "SELECT COUNT(*) FROM netflow.flows;"

# Проверьте метрики
curl http://localhost:8080/metrics
