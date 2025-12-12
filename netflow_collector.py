#!/usr/bin/env python3
"""
Исправленный коллектор NetFlow с детальной отладкой
"""

import socket
import struct
import threading
import queue
import time
import logging
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Tuple, Optional, Any
import json
import os
from dotenv import load_dotenv
import binascii

load_dotenv()

# Получаем настройки из .env
log_level_str = os.getenv('LOG_LEVEL', 'INFO').upper()
log_file = os.getenv('LOG_FILE', 'netflow_collector.log')

# Сопоставляем строку с уровнем логирования
log_levels = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

log_level = log_levels.get(log_level_str, logging.INFO)

# Настройка логирования
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetFlowCollector:
    """Коллектор NetFlow потоков с детальной отладкой"""

    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.flow_queue = queue.Queue(maxsize=10000)
        self.running = False
        self.exporters = {}

        # Параметры
        self.netflow_port = int(os.getenv('NETFLOW_PORT', 2055))
        self.buffer_size = 65535

        # Статистика
        self.stats = {
            'packets_received': 0,
            'flows_processed': 0,
            'parse_errors': 0,
            'last_flush': datetime.now(),
            'versions': {}
        }

        self.init_database()

    def init_database(self):
        """Инициализация подключения к базе данных"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            logger.info("Подключение к PostgreSQL установлено")

            # Используем отдельную схему
            schema = os.getenv('DB_SCHEMA', 'netflow')
            self.cursor.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
            self.cursor.execute(f"SET search_path TO {schema}")

            self.create_tables()
            self.conn.commit()

        except Exception as e:
            logger.error(f"Ошибка подключения к PostgreSQL: {e}")
            # Попробуем без схемы
            try:
                self.conn = psycopg2.connect(**self.db_config)
                self.cursor = self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
                self.create_tables()
                self.conn.commit()
            except Exception as e2:
                logger.error(f"Критическая ошибка: {e2}")
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

        CREATE TABLE IF NOT EXISTS netflow_debug_log (
            id BIGSERIAL PRIMARY KEY,
            exporter_ip INET,
            event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_type VARCHAR(50),
            message TEXT,
            packet_data BYTEA,
            packet_length INTEGER
        );
        """

        try:
            self.cursor.execute(create_tables_sql)
            self.conn.commit()
            logger.info("Таблицы проверены/созданы успешно")
        except Exception as e:
            logger.error(f"Ошибка создания таблиц: {e}")
            self.conn.rollback()

    def log_debug(self, exporter_ip: str, event_type: str, message: str, data: bytes = None):
        """Логирование отладочной информации"""
        try:
            self.cursor.execute("""
                INSERT INTO netflow_debug_log
                (exporter_ip, event_type, message, packet_data, packet_length)
                VALUES (%s, %s, %s, %s, %s)
            """, (exporter_ip, event_type, message,
                  psycopg2.Binary(data) if data else None,
                  len(data) if data else None))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Ошибка записи в debug log: {e}")

    def parse_netflow_v5_detailed(self, data: bytes, exporter_ip: str) -> List[Dict]:
        """Детальный парсинг NetFlow v5 с отладкой"""
        flows = []

        # Логируем получение пакета
        self.log_debug(exporter_ip, "PACKET_RECEIVED",
                      f"Получен пакет размером {len(data)} байт", data[:100])

        try:
            # Проверяем минимальный размер
            if len(data) < 24:
                logger.error(f"Пакет слишком короткий: {len(data)} байт")
                return flows

            # Парсим заголовок
            try:
                header = struct.unpack('!HHIIIIBBH', data[:24])
                version, count, sys_uptime, unix_secs, unix_nsecs, flow_sequence, engine_type, engine_id, sampling_interval = header

                logger.debug(f"NetFlow v5 заголовок: version={version}, count={count}, sys_uptime={sys_uptime}")

                if version != 5:
                    logger.warning(f"Ожидалась версия 5, получена {version}")
                    return flows

            except struct.error as e:
                logger.error(f"Ошибка парсинга заголовока: {e}")
                hex_data = binascii.hexlify(data[:24]).decode('ascii')
                logger.error(f"Данные заголовка (hex): {hex_data}")
                return flows

            # Рассчитываем ожидаемый размер
            expected_size = 24 + count * 48

            if len(data) != expected_size:
                logger.warning(f"Размер пакета не совпадает: ожидалось {expected_size}, получено {len(data)}")
                logger.warning(f"Возможно, это не NetFlow v5 или пакет поврежден")

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
                try:
                    # Проверяем, что достаточно данных для записи
                    if offset + 48 > len(data):
                        logger.warning(f"Недостаточно данных для записи {i+1}")
                        break

                    # Извлекаем запись
                    record_data = data[offset:offset + 48]

                    # Парсим запись
                    # Формат NetFlow v5 записи (48 байт):
                    # src_addr(4), dst_addr(4), next_hop(4),
                    # input(2), output(2), packets(4), bytes(4),
                    # first(4), last(4), src_port(2), dst_port(2),
                    # pad1(1), tcp_flags(1), protocol(1), tos(1),
                    # src_as(2), dst_as(2), src_mask(1), dst_mask(1), pad2(2)

                    # Распаковываем по частям
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

                    # Байты 36-39: pad1(1), tcp_flags(1), protocol(1), tos(1)
                    pad1 = struct.unpack('!B', record_data[36:37])[0]
                    tcp_flags = struct.unpack('!B', record_data[37:38])[0]
                    protocol = struct.unpack('!B', record_data[38:39])[0]
                    tos = struct.unpack('!B', record_data[39:40])[0]

                    src_as = struct.unpack('!H', record_data[40:42])[0]
                    dst_as = struct.unpack('!H', record_data[42:44])[0]
                    src_mask = struct.unpack('!B', record_data[44:45])[0]
                    dst_mask = struct.unpack('!B', record_data[45:46])[0]

                    # Байты 46-47: pad2 (2 байта)
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
                    if i == 0:
                        logger.debug(f"Первая запись: {src_addr}:{src_port} -> {dst_addr}:{dst_port}, "
                                   f"протокол: {protocol}, пакеты: {packets}, байты: {octets}")

                except struct.error as e:
                    logger.error(f"Ошибка структуры в записи {i+1}: {e}")
                    hex_record = binascii.hexlify(record_data).decode('ascii') if 'record_data' in locals() else "N/A"
                    logger.error(f"Данные записи (hex): {hex_record}")
                    continue
                except Exception as e:
                    logger.error(f"Неожиданная ошибка в записи {i+1}: {e}")
                    continue

                offset += 48

            logger.debug(f"Успешно обработано {len(flows)} записей из {count}")

        except Exception as e:
            logger.error(f"Критическая ошибка парсинга: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.log_debug(exporter_ip, "PARSE_ERROR", str(e), data[:200])

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
            1433: 'MSSQL', 1521: 'Oracle', 389: 'LDAP',
            636: 'LDAPS', 109: 'POP2', 110: 'POP3',
            143: 'IMAP', 993: 'IMAPS', 995: 'POP3S'
        }

        protocol_names = {
            1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
            47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'
        }

        if protocol in [6, 17]:  # TCP или UDP
            if port in common_ports:
                return common_ports[port]
            elif port < 1024:
                return f"Системный-{port}"
            else:
                return f"Пользовательский-{port}"
        elif protocol in protocol_names:
            return protocol_names[protocol]
        else:
            return f"Протокол-{protocol}"

    def save_flows_to_db(self, flows: List[Dict]):
        """Сохранение потоков в базу данных"""
        if not flows:
            return

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

            if len(flows) > 0:
                logger.info(f"Сохранено {len(flows)} потоков от {exporter_ip}")

        except Exception as e:
            logger.error(f"Ошибка сохранения потоков в БД: {e}")
            self.conn.rollback()

            # Попробуем сохранить по одному
            self.save_flows_one_by_one(flows)

    def save_flows_one_by_one(self, flows: List[Dict]):
        """Сохранение потоков по одному (fallback)"""
        saved = 0
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

        if saved > 0:
            self.conn.commit()
            logger.info(f"Сохранено {saved}/{len(flows)} потоков по одному")

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

                    # Логируем получение пакета
                    self.stats['packets_received'] += 1

                    # Проверяем минимальный размер
                    if len(data) < 24:
                        logger.warning(f"Слишком короткий пакет от {exporter_ip}: {len(data)} байт")
                        continue

                    # Проверяем версию NetFlow
                    try:
                        version = struct.unpack('!H', data[:2])[0]
                    except:
                        logger.warning(f"Не могу определить версию NetFlow от {exporter_ip}")
                        continue

                    if version == 5:
                        self.flow_queue.put((data, exporter_ip))
                    else:
                        logger.info(f"Получен NetFlow v{version} от {exporter_ip}, пока не обрабатываем")

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Ошибка приема UDP: {e}")

        finally:
            sock.close()
            logger.info("UDP сокет закрыт")

    def process_flows(self):
        """Обработка потоков из очереди"""
        batch_size = 100
        batch = []

        while self.running:
            try:
                data, exporter_ip = self.flow_queue.get(timeout=1)

                # Парсим пакет
                flows = self.parse_netflow_v5_detailed(data, exporter_ip)

                if flows:
                    batch.extend(flows)

                # Периодическое сохранение
                if len(batch) >= batch_size or (datetime.now() - self.stats['last_flush']).seconds > 5:
                    if batch:
                        self.save_flows_to_db(batch)
                        batch = []
                    self.stats['last_flush'] = datetime.now()

                self.flow_queue.task_done()

            except queue.Empty:
                # Сохраняем остатки
                if batch:
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

                # Обновляем статистику версий
                versions_str = ', '.join([f'v{k}:{v}' for k, v in sorted(self.stats['versions'].items())])

                logger.info(f"""
                === СТАТИСТИКА ===
                Пакетов получено: {self.stats['packets_received']}
                Потоков обработано: {self.stats['flows_processed']}
                Ошибок парсинга: {self.stats['parse_errors']}
                В очереди: {self.flow_queue.qsize()}
                ==================
                """)

            except Exception as e:
                logger.error(f"Ошибка вывода статистики: {e}")

    def test_parse_function(self):
        """Тестирование функции парсинга"""
        logger.info("Тестирование парсера...")

        # Создаем тестовый сокет
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)

        try:
            sock.bind(('0.0.0.0', self.netflow_port))
            logger.info(f"Ожидаем тестовый пакет на порту {self.netflow_port}...")

            data, addr = sock.recvfrom(self.buffer_size)
            logger.info(f"Получен пакет от {addr[0]}, размер: {len(data)} байт")

            # Тестируем парсер
            flows = self.parse_netflow_v5_detailed(data, addr[0])

            logger.info(f"Парсер обработал {len(flows)} потоков")

            if flows:
                # Показываем первую запись
                flow = flows[0]
                logger.info(f"Первая запись:")
                logger.info(f"  Источник: {flow['src_ip']}:{flow['src_port']}")
                logger.info(f"  Назначение: {flow['dst_ip']}:{flow['dst_port']}")
                logger.info(f"  Протокол: {flow['protocol']}")
                logger.info(f"  Пакеты: {flow['packets']}, Байты: {flow['bytes']}")
                logger.info(f"  Начало: {flow['flow_start']}, Конец: {flow['flow_end']}")

                # Пробуем сохранить
                self.save_flows_to_db([flow])
                logger.info("Запись сохранена в БД")

        except socket.timeout:
            logger.info("Таймаут ожидания пакета")
        except Exception as e:
            logger.error(f"Ошибка тестирования: {e}")
            import traceback
            logger.error(traceback.format_exc())
        finally:
            sock.close()

    def start(self, test_mode=False):
        """Запуск коллектора"""
        if test_mode:
            self.test_parse_function()
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
    """Загрузка конфигурации"""
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
    parser.add_argument('--test', '-t', action='store_true', help='Тестовый режим (парсинг одного пакета)')
    parser.add_argument('--port', '-p', type=int, default=None, help='Порт NetFlow')
    args = parser.parse_args()

    config = load_config()

    if args.port:
        os.environ['NETFLOW_PORT'] = str(args.port)

    collector = NetFlowCollector(config)

    try:
        collector.start(test_mode=args.test)
    except Exception as e:
        logger.error(f"Фатальная ошибка: {e}")
        import traceback
        logger.error(traceback.format_exc())
        collector.stop()
