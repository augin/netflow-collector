#!/usr/bin/env python3
"""
Коллектор NetFlow с улучшенным логированием и проверкой записи в БД
"""

import os
import sys
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Настраиваем логирование
import logging

log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
log_file = os.getenv('LOG_FILE', 'netflow_collector.log')

log_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

log_level = log_levels.get(log_level_str, logging.INFO)

logger = logging.getLogger(__name__)
logger.setLevel(log_level)

# Обработчик для консоли
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(log_level)
console_format = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
console_handler.setFormatter(console_format)

# Обработчик для файла
if log_file:
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(log_level)
    file_handler.setFormatter(console_format)
    logger.addHandler(file_handler)

logger.addHandler(console_handler)
logger.propagate = False

logger.info(f"Логирование настроено. Уровень: {log_level_str}")

import socket
import struct
import threading
import queue
import time
import binascii
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List

class NetFlowCollector:
    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.flow_queue = queue.Queue(maxsize=10000)
        self.running = False

        self.netflow_port = int(os.getenv('NETFLOW_PORT', 2055))
        self.buffer_size = int(os.getenv('BUFFER_SIZE', 65535))
        self.batch_size = int(os.getenv('BATCH_SIZE', 100))
        self.flush_interval = int(os.getenv('FLUSH_INTERVAL', 5))

        self.stats = {
            'packets_received': 0,
            'flows_processed': 0,
            'parse_errors': 0,
            'last_flush': datetime.now(),
            'versions': {}
        }

        logger.info(f"Инициализация коллектора. Порт: {self.netflow_port}")

        self.init_database()

    def init_database(self):
        """Инициализация подключения к базе данных"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            logger.info("Подключение к PostgreSQL установлено")

            schema = os.getenv('DB_SCHEMA', 'netflow')
            logger.info(f"Используем схему: {schema}")

            self.cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
            self.cursor.execute(f"SET search_path TO {schema}")

            self.create_tables()
            self.conn.commit()

        except psycopg2.Error as e:
            logger.error(f"Ошибка подключения к PostgreSQL: {e}")
            raise

    def create_tables(self):
        """Создание таблиц"""
        create_tables_sql = """
        CREATE TABLE IF NOT EXISTS netflow_flows (
            id BIGSERIAL PRIMARY KEY,
            flow_start TIMESTAMP,
            flow_end TIMESTAMP,
            src_ip INET,
            dst_ip INET,
            src_port INTEGER,
            dst_port INTEGER,
            protocol INTEGER,
            packets BIGINT,
            bytes BIGINT,
            flow_duration_ms BIGINT,
            exporter_ip INET,
            input_snmp INTEGER,
            output_snmp INTEGER,
            tcp_flags INTEGER,
            src_tos INTEGER,
            dst_tos INTEGER,
            src_as INTEGER,
            dst_as INTEGER,
            next_hop INET,
            vlan_id INTEGER,
            application_name VARCHAR(256),
            bidirectional BOOLEAN DEFAULT false,
            netflow_version INTEGER,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_netflow_timestamp ON netflow_flows(flow_start);
        CREATE INDEX IF NOT EXISTS idx_netflow_src_ip ON netflow_flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_netflow_dst_ip ON netflow_flows(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_netflow_exporter ON netflow_flows(exporter_ip);

        CREATE TABLE IF NOT EXISTS netflow_exporters (
            id SERIAL PRIMARY KEY,
            exporter_ip INET UNIQUE NOT NULL,
            exporter_name VARCHAR(256),
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_flows BIGINT DEFAULT 0,
            total_bytes BIGINT DEFAULT 0,
            version INTEGER,
            sampling_rate INTEGER DEFAULT 1
        );
        """

        try:
            self.cursor.execute(create_tables_sql)
            self.conn.commit()
            logger.info("Таблицы созданы/проверены успешно")
        except Exception as e:
            logger.error(f"Ошибка создания таблиц: {e}")
            self.conn.rollback()
            raise

    def parse_netflow_v5(self, data: bytes, exporter_ip: str) -> List[Dict]:
        """Парсинг NetFlow v5 пакета"""
        flows = []

        try:
            # Проверяем минимальный размер
            if len(data) < 24:
                logger.error(f"Пакет слишком короткий: {len(data)} байт")
                return flows

            # Парсим заголовок
            header = struct.unpack('!HHIIIIBBH', data[:24])
            version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval = header

            logger.debug(f"NetFlow v5 заголовок: version={version}, count={count}")

            if version != 5:
                logger.warning(f"Ожидалась версия 5, получена {version}")
                return flows

            # Рассчитываем ожидаемый размер
            expected_size = 24 + count * 48

            if len(data) != expected_size:
                logger.warning(f"Размер пакета не совпадает: ожидалось {expected_size}, получено {len(data)}")
                # Пробуем прочитать столько записей, сколько возможно
                available_records = (len(data) - 24) // 48
                if available_records > 0:
                    count = available_records
                    logger.warning(f"Будет прочитано {count} записей из возможных")
                else:
                    logger.error(f"Недостаточно данных для чтения записей")
                    return flows

            offset = 24

            for i in range(count):
                # Проверяем, что достаточно данных для записи
                if offset + 48 > len(data):
                    logger.warning(f"Недостаточно данных для записи {i+1}")
                    break

                # Извлекаем запись
                record_data = data[offset:offset + 48]

                # Парсим запись
                src_addr_int = struct.unpack('!I', record_data[0:4])[0]
                dst_addr_int = struct.unpack('!I', record_data[4:8])[0]
                next_hop_int = struct.unpack('!I', record_data[8:12])[0]

                src_addr = socket.inet_ntoa(struct.pack('!I', src_addr_int))
                dst_addr = socket.inet_ntoa(struct.pack('!I', dst_addr_int))
                next_hop = socket.inet_ntoa(struct.pack('!I', next_hop_int))

                input_intf = struct.unpack('!H', record_data[12:14])[0]
                output_intf = struct.unpack('!H', record_data[14:16])[0]
                packets = struct.unpack('!I', record_data[16:20])[0]
                octets = struct.unpack('!I', record_data[20:24])[0]
                first = struct.unpack('!I', record_data[24:28])[0]
                last = struct.unpack('!I', record_data[28:32])[0]
                src_port = struct.unpack('!H', record_data[32:34])[0]
                dst_port = struct.unpack('!H', record_data[34:36])[0]

                # Байты 36-39
                pad1 = struct.unpack('!B', record_data[36:37])[0]
                tcp_flags = struct.unpack('!B', record_data[37:38])[0]
                protocol = struct.unpack('!B', record_data[38:39])[0]
                tos = struct.unpack('!B', record_data[39:40])[0]

                src_as = struct.unpack('!H', record_data[40:42])[0]
                dst_as = struct.unpack('!H', record_data[42:44])[0]
                src_mask = struct.unpack('!B', record_data[44:45])[0]
                dst_mask = struct.unpack('!B', record_data[45:46])[0]
                pad2 = struct.unpack('!H', record_data[46:48])[0]

                # Рассчитываем временные метки
                try:
                    flow_start_ts = unix_secs - (sys_uptime - first) / 1000.0
                    flow_end_ts = unix_secs - (sys_uptime - last) / 1000.0

                    flow_start = datetime.fromtimestamp(flow_start_ts)
                    flow_end = datetime.fromtimestamp(flow_end_ts)
                    flow_duration = last - first
                except Exception as time_err:
                    logger.warning(f"Ошибка расчета времени для записи {i+1}: {time_err}")
                    flow_start = datetime.fromtimestamp(unix_secs)
                    flow_end = datetime.fromtimestamp(unix_secs)
                    flow_duration = 0

                flow_data = {
                    'flow_start': flow_start,
                    'flow_end': flow_end,
                    'src_ip': src_addr,
                    'dst_ip': dst_addr,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'packets': packets,
                    'bytes': octets,
                    'flow_duration_ms': flow_duration,
                    'exporter_ip': exporter_ip,
                    'input_snmp': input_intf,
                    'output_snmp': output_intf,
                    'tcp_flags': tcp_flags,
                    'src_tos': tos,
                    'dst_tos': tos,
                    'src_as': src_as,
                    'dst_as': dst_as,
                    'next_hop': next_hop,
                    'vlan_id': None,
                    'application_name': self._get_application_name(protocol, dst_port),
                    'bidirectional': False,
                    'netflow_version': 5
                }

                flows.append(flow_data)

                # Логируем первую запись для отладки
                if i == 0 and logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Первая запись: {src_addr}:{src_port} -> {dst_addr}:{dst_port}, "
                               f"протокол: {protocol}, пакеты: {packets}, байты: {octets}")

                offset += 48

            logger.debug(f"Успешно обработано {len(flows)} записей из {count}")

        except struct.error as e:
            logger.error(f"Ошибка структуры при парсинге: {e}")
            # Выводим hex дамп для отладки
            if len(data) > 0:
                hex_dump = binascii.hexlify(data[:min(100, len(data))]).decode('ascii')
                logger.error(f"Hex дамп (первые 100 байт): {hex_dump}")
        except Exception as e:
            logger.error(f"Неожиданная ошибка парсинга: {e}")
            import traceback
            logger.error(traceback.format_exc())

        return flows

    def _get_application_name(self, protocol: int, port: int) -> str:
        """Определение имени приложения"""
        common_ports = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 25: 'SMTP',
            110: 'POP3', 143: 'IMAP', 3389: 'RDP', 3306: 'MySQL',
            5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            21: 'FTP', 23: 'Telnet', 161: 'SNMP', 162: 'SNMP Trap',
            67: 'DHCP Server', 68: 'DHCP Client', 123: 'NTP',
            514: 'Syslog', 1194: 'OpenVPN', 1723: 'PPTP',
            5060: 'SIP', 5061: 'SIPS', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 993: 'IMAPS', 995: 'POP3S',
        }

        if protocol in [6, 17] and port in common_ports:
            return common_ports[port]
        elif protocol == 6:
            return f"TCP-{port}"
        elif protocol == 17:
            return f"UDP-{port}"
        elif protocol == 1:
            return "ICMP"
        else:
            return f"Proto-{protocol}"

    def save_flows_to_db(self, flows: List[Dict]):
        """Сохранение потоков в базу данных"""
        if not flows:
            logger.debug("Нет потоков для сохранения")
            return

        logger.debug(f"Попытка сохранить {len(flows)} потоков в БД")

        try:
            insert_sql = """
                INSERT INTO netflow_flows (
                    flow_start, flow_end, src_ip, dst_ip, src_port, dst_port,
                    protocol, packets, bytes, flow_duration_ms, exporter_ip,
                    input_snmp, output_snmp, tcp_flags, src_tos, dst_tos,
                    src_as, dst_as, next_hop, vlan_id, application_name,
                    netflow_version
                ) VALUES %s
            """

            values = []
            total_bytes = 0
            exporter_ip = flows[0]['exporter_ip'] if flows else None

            for flow in flows:
                values.append((
                    flow['flow_start'], flow['flow_end'], flow['src_ip'], flow['dst_ip'],
                    flow['src_port'] or 0, flow['dst_port'] or 0, flow['protocol'] or 0,
                    flow['packets'] or 0, flow['bytes'] or 0, flow['flow_duration_ms'] or 0,
                    flow['exporter_ip'], flow['input_snmp'] or 0, flow['output_snmp'] or 0,
                    flow['tcp_flags'] or 0, flow['src_tos'] or 0, flow['dst_tos'] or 0,
                    flow['src_as'] or 0, flow['dst_as'] or 0, flow['next_hop'],
                    flow['vlan_id'], flow['application_name'], flow.get('netflow_version', 5)
                ))
                total_bytes += flow.get('bytes', 0)

            # Используем execute_values для пакетной вставки
            from psycopg2.extras import execute_values
            execute_values(self.cursor, insert_sql, values)

            # Обновляем статистику экспортера
            if exporter_ip:
                self.update_exporter_stats(exporter_ip, len(flows), total_bytes)

            self.conn.commit()

            self.stats['flows_processed'] += len(flows)

            logger.debug(f"Успешно сохранено {len(flows)} потоков от {exporter_ip}")

        except Exception as e:
            logger.error(f"Ошибка сохранения потоков в БД: {e}")
            self.conn.rollback()

            # Попробуем сохранить по одному
            self.save_flows_one_by_one(flows)

    def save_flows_one_by_one(self, flows: List[Dict]):
        """Сохранение потоков по одному (fallback)"""
        saved = 0
        logger.debug(f"Попытка сохранить {len(flows)} потоков по одному...")

        for flow in flows:
            try:
                self.cursor.execute("""
                    INSERT INTO netflow_flows (
                        flow_start, flow_end, src_ip, dst_ip, src_port, dst_port,
                        protocol, packets, bytes, flow_duration_ms, exporter_ip,
                        input_snmp, output_snmp, tcp_flags, src_tos, dst_tos,
                        src_as, dst_as, next_hop, vlan_id, application_name,
                        netflow_version
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    flow['flow_start'], flow['flow_end'], flow['src_ip'], flow['dst_ip'],
                    flow['src_port'] or 0, flow['dst_port'] or 0, flow['protocol'] or 0,
                    flow['packets'] or 0, flow['bytes'] or 0, flow['flow_duration_ms'] or 0,
                    flow['exporter_ip'], flow['input_snmp'] or 0, flow['output_snmp'] or 0,
                    flow['tcp_flags'] or 0, flow['src_tos'] or 0, flow['dst_tos'] or 0,
                    flow['src_as'] or 0, flow['dst_as'] or 0, flow['next_hop'],
                    flow['vlan_id'], flow['application_name'], flow.get('netflow_version', 5)
                ))
                saved += 1
            except Exception as e:
                logger.error(f"Ошибка сохранения отдельного потока: {e}")
                # Логируем проблемные данные
                logger.error(f"Проблемный поток: {flow}")

        if saved > 0:
            self.conn.commit()
            logger.debug(f"Сохранено {saved}/{len(flows)} потоков по одному")
        else:
            logger.error("Не удалось сохранить ни одного потока!")

    def update_exporter_stats(self, exporter_ip: str, flow_count: int, bytes_count: int):
        """Обновление статистики экспортера"""
        try:
            self.cursor.execute("""
                INSERT INTO netflow_exporters
                (exporter_ip, first_seen, last_seen, total_flows, total_bytes)
                VALUES (%s, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, %s, %s)
                ON CONFLICT (exporter_ip)
                DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    total_flows = netflow_exporters.total_flows + %s,
                    total_bytes = netflow_exporters.total_bytes + %s
            """, (exporter_ip, flow_count, bytes_count, flow_count, bytes_count))
            self.conn.commit()
            logger.debug(f"Статистика экспортера {exporter_ip} обновлена")
        except Exception as e:
            logger.error(f"Ошибка обновления статистики экспортера: {e}")

    def start_udp_listener(self):
        """Запуск UDP слушателя"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(('0.0.0.0', self.netflow_port))
            sock.settimeout(1)
            logger.info(f"Слушаем NetFlow на порту {self.netflow_port}")

            while self.running:
                try:
                    data, addr = sock.recvfrom(self.buffer_size)
                    exporter_ip = addr[0]

                    self.flow_queue.put((data, exporter_ip))
                    self.stats['packets_received'] += 1

                    logger.debug(f"Получен пакет от {exporter_ip}, размер: {len(data)} байт")

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Ошибка приема UDP: {e}")

        finally:
            sock.close()
            logger.info("UDP сокет закрыт")

    def process_flows(self):
        """Обработка потоков из очереди"""
        batch = []

        while self.running:
            try:
                data, exporter_ip = self.flow_queue.get(timeout=1)

                # Парсим пакет
                flows = self.parse_netflow_v5(data, exporter_ip)

                if flows:
                    batch.extend(flows)
                    logger.debug(f"Добавлено {len(flows)} потоков в batch. Всего: {len(batch)}")

                # Периодическое сохранение
                if len(batch) >= self.batch_size or (datetime.now() - self.stats['last_flush']).seconds > self.flush_interval:
                    if batch:
                        logger.debug(f"Сохранение batch из {len(batch)} потоков...")
                        self.save_flows_to_db(batch)
                        batch = []
                    self.stats['last_flush'] = datetime.now()

                self.flow_queue.task_done()

            except queue.Empty:
                # Сохраняем остатки
                if batch:
                    logger.debug(f"Сохраняем остатки batch из {len(batch)} потоков...")
                    self.save_flows_to_db(batch)
                    batch = []
                continue
            except Exception as e:
                logger.error(f"Ошибка обработчика: {e}")
                import traceback
                logger.error(traceback.format_exc())

    def print_statistics(self):
        """Вывод статистики"""
        while self.running:
            try:
                time.sleep(30)

                logger.debug(f"""
                === СТАТИСТИКА ===
                Пакетов получено: {self.stats['packets_received']}
                Потоков обработано: {self.stats['flows_processed']}
                Ошибок парсинга: {self.stats['parse_errors']}
                В очереди: {self.flow_queue.qsize()}
                ==================
                """)

            except Exception as e:
                logger.error(f"Ошибка вывода статистики: {e}")

    def test_connection(self):
        """Тест подключения к базе данных"""
        try:
            self.cursor.execute("SELECT 1 as test")
            result = self.cursor.fetchone()
            logger.debug(f"Тест подключения к БД: {result['test']}")
            return True
        except Exception as e:
            logger.error(f"Тест подключения к БД не пройден: {e}")
            return False

    def start(self):
        """Запуск коллектора"""
        # Тестируем подключение к БД
        if not self.test_connection():
            logger.error("Не удалось подключиться к базе данных. Завершение работы.")
            return

        self.running = True

        # Запускаем потоки
        threads = []

        udp_thread = threading.Thread(target=self.start_udp_listener, daemon=True)
        threads.append(udp_thread)

        processor_thread = threading.Thread(target=self.process_flows, daemon=True)
        threads.append(processor_thread)

        stats_thread = threading.Thread(target=self.print_statistics, daemon=True)
        threads.append(stats_thread)

        for thread in threads:
            thread.start()

        logger.info("Коллектор NetFlow запущен")

        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Получен сигнал завершения")
        finally:
            self.stop()

    def stop(self):
        """Остановка коллектора"""
        logger.info("Остановка коллектора...")
        self.running = False

        # Ожидаем завершения очереди
        self.flow_queue.join()

        # Закрываем соединение
        if hasattr(self, 'cursor'):
            self.cursor.close()
        if hasattr(self, 'conn'):
            self.conn.close()

        logger.info("Коллектор остановлен")

def load_config():
    """Загрузка конфигурации из .env"""
    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'netflow_db'),
        'user': os.getenv('DB_USER', 'netflow_user'),
        'password': os.getenv('DB_PASSWORD', 'password')
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Коллектор NetFlow")
    parser.add_argument('--verbose', '-v', action='store_true', help='Подробный вывод')
    args = parser.parse_args()

    # Если указан флаг verbose, временно повышаем уровень логирования
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info("Включен подробный режим логирования")

    config = load_config()

    collector = NetFlowCollector(config)

    try:
        collector.start()
    except KeyboardInterrupt:
        logger.info("Получен сигнал завершения")
        collector.stop()
    except Exception as e:
        logger.error(f"Фатальная ошибка: {e}", exc_info=True)
        collector.stop()
