#!/usr/bin/env python3
"""
Исправленный скрипт очистки базы данных NetFlow
"""

import os
import sys
import argparse
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Загружаем переменные окружения
load_dotenv()

# Настройка логирования
def setup_logging():
    """Настройка логирования"""
    log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
    log_levels = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    
    logger = logging.getLogger(__name__)
    logger.setLevel(log_levels.get(log_level, logging.INFO))
    
    # Форматтер
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Консольный обработчик
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_levels.get(log_level, logging.INFO))
    console_handler.setFormatter(formatter)
    
    # Файловый обработчик
    log_file = os.getenv('LOG_FILE', 'cleanup.log')
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    logger.addHandler(console_handler)
    logger.propagate = False
    
    return logger

logger = setup_logging()

class DatabaseCleanup:
    """Класс для очистки базы данных NetFlow"""
    
    def __init__(self, db_config: Dict):
        self.db_config = db_config
        self.conn = None
        self.cursor = None
        self.schema = os.getenv('DB_SCHEMA', 'netflow')
        self.connect()
    
    def connect(self):
        """Подключение к базе данных"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            self.cursor.execute(f"SET search_path TO {self.schema}")
            logger.info(f"Подключение к PostgreSQL установлено. Схема: {self.schema}")
        except Exception as e:
            logger.error(f"Ошибка подключения к PostgreSQL: {e}")
            raise
    
    def disconnect(self):
        """Отключение от базы данных"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
        logger.info("Отключение от PostgreSQL")
    
    def get_table_sizes(self) -> Dict[str, Dict]:
        """Получение информации о размерах таблиц - ИСПРАВЛЕННЫЙ ЗАПРОС"""
        try:
            # ИСПРАВЛЕННЫЙ ЗАПРОС с явным указанием таблиц
            query = """
            SELECT 
                t.schemaname || '.' || t.tablename as full_table_name,
                t.tablename as table_name,
                t.schemaname as schema_name,
                pg_size_pretty(pg_total_relation_size(t.schemaname || '.' || t.tablename)) as total_size,
                pg_size_pretty(pg_table_size(t.schemaname || '.' || t.tablename)) as table_size,
                pg_size_pretty(pg_indexes_size(t.schemaname || '.' || t.tablename)) as index_size,
                COALESCE(s.n_live_tup, 0) as row_count
            FROM pg_catalog.pg_tables t
            LEFT JOIN pg_stat_user_tables s ON t.schemaname = s.schemaname AND t.tablename = s.relname
            WHERE t.schemaname = %s
            ORDER BY pg_total_relation_size(t.schemaname || '.' || t.tablename) DESC
            """
            
            self.cursor.execute(query, (self.schema,))
            tables = self.cursor.fetchall()
            
            result = {}
            for table in tables:
                result[table['table_name']] = dict(table)
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка получения размеров таблиц: {e}")
            # Пробуем альтернативный запрос
            return self.get_table_sizes_fallback()
    
    def get_table_sizes_fallback(self) -> Dict[str, Dict]:
        """Альтернативный способ получения размеров таблиц"""
        try:
            # Более простой запрос без JOIN
            query = """
            SELECT 
                schemaname || '.' || tablename as full_table_name,
                tablename as table_name,
                schemaname as schema_name
            FROM pg_catalog.pg_tables 
            WHERE schemaname = %s
            ORDER BY tablename
            """
            
            self.cursor.execute(query, (self.schema,))
            tables = self.cursor.fetchall()
            
            result = {}
            for table in tables:
                table_name = table['table_name']
                full_name = table['full_table_name']
                
                # Получаем размеры отдельными запросами
                size_query = """
                SELECT 
                    pg_size_pretty(pg_total_relation_size(%s)) as total_size,
                    pg_size_pretty(pg_table_size(%s)) as table_size,
                    pg_size_pretty(pg_indexes_size(%s)) as index_size
                """
                
                self.cursor.execute(size_query, (full_name, full_name, full_name))
                sizes = self.cursor.fetchone()
                
                # Получаем количество строк
                count_query = f"SELECT COUNT(*) as row_count FROM {self.schema}.{table_name}"
                try:
                    self.cursor.execute(count_query)
                    count_result = self.cursor.fetchone()
                    row_count = count_result['row_count'] if count_result else 0
                except:
                    row_count = 0
                
                result[table_name] = {
                    'full_table_name': full_name,
                    'table_name': table_name,
                    'schema_name': self.schema,
                    'total_size': sizes['total_size'] if sizes else 'N/A',
                    'table_size': sizes['table_size'] if sizes else 'N/A',
                    'index_size': sizes['index_size'] if sizes else 'N/A',
                    'row_count': row_count
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка в альтернативном запросе размеров таблиц: {e}")
            return {}
    
    def get_database_size_simple(self) -> Dict[str, str]:
        """Простой способ получения размеров таблиц"""
        try:
            # Получаем список таблиц в схеме
            self.cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = %s 
                AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """, (self.schema,))
            
            tables = self.cursor.fetchall()
            result = {}
            
            for table in tables:
                table_name = table['table_name']
                full_table_name = f"{self.schema}.{table_name}"
                
                # Размер таблицы
                self.cursor.execute("""
                    SELECT pg_size_pretty(pg_total_relation_size(%s)) as size
                """, (full_table_name,))
                size_result = self.cursor.fetchone()
                
                # Количество строк
                self.cursor.execute(f"SELECT COUNT(*) as count FROM {self.schema}.{table_name}")
                count_result = self.cursor.fetchone()
                
                result[table_name] = {
                    'size': size_result['size'] if size_result else 'N/A',
                    'rows': count_result['count'] if count_result else 0
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка получения простых размеров таблиц: {e}")
            return {}
    
    def get_oldest_record_date(self, table_name: str, date_column: str = 'flow_start') -> Optional[datetime]:
        """Получение даты самой старой записи в таблице"""
        try:
            query = f"""
            SELECT MIN({date_column}) as oldest_date 
            FROM {self.schema}.{table_name}
            WHERE {date_column} IS NOT NULL
            """
            
            self.cursor.execute(query)
            result = self.cursor.fetchone()
            
            if result and result['oldest_date']:
                return result['oldest_date']
            return None
            
        except Exception as e:
            logger.error(f"Ошибка получения даты старой записи: {e}")
            return None
    
    def cleanup_table(self, table_name: str, retention_days: int, 
                     date_column: str = 'flow_start', vacuum: bool = False) -> Tuple[int, int]:
        """
        Очистка таблицы от старых записей
        
        Args:
            table_name: Имя таблицы
            retention_days: Количество дней хранения
            date_column: Колонка с датой для фильтрации
            vacuum: Выполнить VACUUM после удаления
        
        Returns:
            Tuple[int, int]: (количество удаленных записей, время выполнения в мс)
        """
        if retention_days <= 0:
            logger.warning(f"Количество дней хранения должно быть больше 0. Пропускаем таблицу {table_name}")
            return 0, 0
        
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            # Сначала получаем количество записей для удаления
            count_query = f"""
            SELECT COUNT(*) as count 
            FROM {self.schema}.{table_name}
            WHERE {date_column} < %s
            """
            
            self.cursor.execute(count_query, (cutoff_date,))
            count_result = self.cursor.fetchone()
            records_to_delete = count_result['count'] if count_result else 0
            
            if records_to_delete == 0:
                logger.info(f"В таблице {table_name} нет записей старше {cutoff_date}")
                return 0, 0
            
            logger.info(f"Найдено {records_to_delete:,} записей для удаления из {table_name}")
            
            # Удаляем записи с логированием
            start_time = datetime.now()
            
            # Удаляем партиями для избежания блокировок
            batch_size = 10000
            total_deleted = 0
            
            while True:
                # Удаляем порциями
                delete_query = f"""
                WITH deleted AS (
                    DELETE FROM {self.schema}.{table_name}
                    WHERE id IN (
                        SELECT id 
                        FROM {self.schema}.{table_name}
                        WHERE {date_column} < %s
                        ORDER BY id
                        LIMIT %s
                    )
                    RETURNING id
                )
                SELECT COUNT(*) as deleted_count FROM deleted
                """
                
                self.cursor.execute(delete_query, (cutoff_date, batch_size))
                result = self.cursor.fetchone()
                batch_deleted = result['deleted_count'] if result else 0
                total_deleted += batch_deleted
                
                self.conn.commit()
                
                if batch_deleted > 0:
                    logger.debug(f"Удалено {batch_deleted:,} записей из {table_name}. Всего: {total_deleted:,}")
                
                if batch_deleted < batch_size:
                    break
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            logger.info(f"Удалено {total_deleted:,} записей из таблицы {table_name} за {execution_time:.0f} мс")
            
            # Опционально выполняем VACUUM
            if vacuum and total_deleted > 0:
                self.vacuum_table(table_name)
            
            return total_deleted, execution_time
            
        except Exception as e:
            logger.error(f"Ошибка очистки таблицы {table_name}: {e}")
            self.conn.rollback()
            return 0, 0
    
    def cleanup_all_tables(self, retention_days: int, vacuum: bool = False) -> Dict[str, Tuple[int, int]]:
        """Очистка всех таблиц в схеме"""
        results = {}
        
        # Определяем таблицы и соответствующие колонки дат
        tables_config = [
            ('netflow_flows', 'flow_start'),
            ('netflow_debug_log', 'event_time'),
            ('netflow_raw_packets', 'received_at'),
            ('netflow_exporters', 'last_seen'),
        ]
        
        for table_name, date_column in tables_config:
            # Проверяем существование таблицы
            if not self.table_exists(table_name):
                logger.debug(f"Таблица {table_name} не существует, пропускаем")
                continue
            
            # Для netflow_exporters используем другую логику (удаляем только если нет связанных записей)
            if table_name == 'netflow_exporters':
                deleted, time_ms = self.cleanup_exporters(retention_days, vacuum)
            else:
                deleted, time_ms = self.cleanup_table(table_name, retention_days, date_column, vacuum)
            
            results[f"{table_name}.{date_column}"] = (deleted, time_ms)
        
        return results
    
    def table_exists(self, table_name: str) -> bool:
        """Проверка существования таблицы"""
        try:
            query = """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = %s 
                AND table_name = %s
            )
            """
            
            self.cursor.execute(query, (self.schema, table_name))
            result = self.cursor.fetchone()
            return result['exists']
        except Exception as e:
            logger.error(f"Ошибка проверки существования таблицы {table_name}: {e}")
            return False
    
    def cleanup_exporters(self, retention_days: int, vacuum: bool = False) -> Tuple[int, int]:
        """Очистка таблицы экспортеров (удаляем только если нет связанных записей)"""
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            # Сначала находим экспортеров для удаления
            query = f"""
            SELECT e.id, e.exporter_ip
            FROM {self.schema}.netflow_exporters e
            LEFT JOIN {self.schema}.netflow_flows f ON e.exporter_ip = f.exporter_ip
            WHERE e.last_seen < %s
            AND f.id IS NULL
            """
            
            self.cursor.execute(query, (cutoff_date,))
            exporters_to_delete = self.cursor.fetchall()
            
            if not exporters_to_delete:
                logger.info("Нет экспортеров для удаления")
                return 0, 0
            
            logger.info(f"Найдено {len(exporters_to_delete)} экспортеров для удаления")
            
            # Удаляем
            start_time = datetime.now()
            
            delete_query = f"""
            DELETE FROM {self.schema}.netflow_exporters
            WHERE id IN %s
            """
            
            exporter_ids = tuple([e['id'] for e in exporters_to_delete])
            self.cursor.execute(delete_query, (exporter_ids,))
            
            deleted = self.cursor.rowcount
            self.conn.commit()
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            logger.info(f"Удалено {deleted} экспортеров за {execution_time:.0f} мс")
            
            if vacuum and deleted > 0:
                self.vacuum_table('netflow_exporters')
            
            return deleted, execution_time
            
        except Exception as e:
            logger.error(f"Ошибка очистки экспортеров: {e}")
            self.conn.rollback()
            return 0, 0
    
    def vacuum_table(self, table_name: str):
        """Оптимизация таблицы с помощью VACUUM"""
        try:
            logger.info(f"Выполняю VACUUM для таблицы {table_name}...")
            start_time = datetime.now()
            
            # VACUUM ANALYZE для освобождения места и обновления статистики
            self.cursor.execute(f"VACUUM ANALYZE {self.schema}.{table_name}")
            self.conn.commit()
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.info(f"VACUUM для таблицы {table_name} выполнен за {execution_time:.0f} мс")
            
        except Exception as e:
            logger.error(f"Ошибка выполнения VACUUM для таблицы {table_name}: {e}")
            self.conn.rollback()
    
    def analyze_table(self, table_name: str):
        """Обновление статистики для таблицы"""
        try:
            logger.info(f"Обновляю статистику для таблицы {table_name}...")
            self.cursor.execute(f"ANALYZE {self.schema}.{table_name}")
            self.conn.commit()
            logger.info(f"Статистика для таблицы {table_name} обновлена")
        except Exception as e:
            logger.error(f"Ошибка обновления статистики для таблицы {table_name}: {e}")
            self.conn.rollback()
    
    def get_database_size(self) -> str:
        """Получение размера базы данных"""
        try:
            query = """
            SELECT pg_size_pretty(pg_database_size(%s)) as size
            """
            
            self.cursor.execute(query, (self.db_config['database'],))
            result = self.cursor.fetchone()
            return result['size'] if result else "N/A"
        except Exception as e:
            logger.error(f"Ошибка получения размера базы данных: {e}")
            return "N/A"
    
    def archive_old_data(self, retention_days: int, archive_table_suffix: str = "_archive") -> int:
        """
        Архивация старых данных вместо удаления
        
        Args:
            retention_days: Количество дней хранения
            archive_table_suffix: Суффикс для таблиц архива
        
        Returns:
            int: Количество архивированных записей
        """
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        archived_count = 0
        
        try:
            # Создаем таблицу архива если её нет
            archive_table = f"netflow_flows{archive_table_suffix}"
            
            create_archive_query = f"""
            CREATE TABLE IF NOT EXISTS {self.schema}.{archive_table} (
                LIKE {self.schema}.netflow_flows INCLUDING DEFAULTS INCLUDING CONSTRAINTS
            )
            """
            
            self.cursor.execute(create_archive_query)
            
            # Перемещаем старые данные в архив
            archive_query = f"""
            WITH moved_rows AS (
                DELETE FROM {self.schema}.netflow_flows
                WHERE flow_start < %s
                RETURNING *
            )
            INSERT INTO {self.schema}.{archive_table}
            SELECT * FROM moved_rows
            """
            
            self.cursor.execute(archive_query, (cutoff_date,))
            archived_count = self.cursor.rowcount
            self.conn.commit()
            
            logger.info(f"Архивировано {archived_count:,} записей в таблицу {archive_table}")
            
            # Создаем индекс для архива
            if archived_count > 0:
                self.cursor.execute(f"""
                    CREATE INDEX IF NOT EXISTS idx_{archive_table}_timestamp 
                    ON {self.schema}.{archive_table}(flow_start)
                """)
                self.conn.commit()
            
            return archived_count
            
        except Exception as e:
            logger.error(f"Ошибка архивации данных: {e}")
            self.conn.rollback()
            return 0

def load_db_config() -> Dict:
    """Загрузка конфигурации базы данных"""
    return {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'netflow_db'),
        'user': os.getenv('DB_USER', 'netflow_user'),
        'password': os.getenv('DB_PASSWORD', 'password')
    }

def show_database_stats_simple(cleanup: DatabaseCleanup):
    """Упрощенный показ статистики базы данных"""
    logger.info("=" * 60)
    logger.info("СТАТИСТИКА БАЗЫ ДАННЫХ")
    logger.info("=" * 60)
    
    # Размер базы данных
    db_size = cleanup.get_database_size()
    logger.info(f"Размер базы данных: {db_size}")
    
    # Получаем таблицы и их размеры упрощенным способом
    try:
        # Получаем список таблиц в схеме
        cleanup.cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = %s 
            AND table_type = 'BASE TABLE'
            ORDER BY table_name
        """, (cleanup.schema,))
        
        tables = cleanup.cursor.fetchall()
        
        logger.info("\nТаблицы в схеме '%s':", cleanup.schema)
        
        total_rows = 0
        for table in tables:
            table_name = table['table_name']
            full_table_name = f"{cleanup.schema}.{table_name}"
            
            # Размер таблицы
            cleanup.cursor.execute("""
                SELECT pg_size_pretty(pg_total_relation_size(%s)) as size
            """, (full_table_name,))
            size_result = cleanup.cursor.fetchone()
            
            # Количество строк
            cleanup.cursor.execute(f"SELECT COUNT(*) as count FROM {cleanup.schema}.{table_name}")
            count_result = cleanup.cursor.fetchone()
            
            rows = count_result['count'] if count_result else 0
            total_rows += rows
            
            # Дата самой старой записи (если есть timestamp)
            oldest_date = None
            if table_name == 'netflow_flows':
                oldest_date = cleanup.get_oldest_record_date(table_name, 'flow_start')
            elif table_name == 'netflow_debug_log':
                oldest_date = cleanup.get_oldest_record_date(table_name, 'event_time')
            
            age_info = ""
            if oldest_date:
                age_days = (datetime.now() - oldest_date).days
                age_info = f", самая старая запись: {oldest_date.date()} ({age_days} дней)"
            
            logger.info(f"  {table_name}: {size_result['size'] if size_result else 'N/A'}, "
                       f"записей: {rows:,}{age_info}")
        
        logger.info(f"\nВсего таблиц: {len(tables)}, Всего записей: {total_rows:,}")
        
        # Дополнительная информация
        logger.info("\nДополнительная информация:")
        
        # Количество уникальных экспортеров
        if cleanup.table_exists('netflow_exporters'):
            cleanup.cursor.execute("SELECT COUNT(*) as count FROM netflow_exporters")
            exporters_count = cleanup.cursor.fetchone()['count']
            logger.info(f"  Уникальных экспортеров: {exporters_count}")
        
        # Объем трафика за последние 30 дней
        if cleanup.table_exists('netflow_flows'):
            thirty_days_ago = datetime.now() - timedelta(days=30)
            cleanup.cursor.execute("""
                SELECT 
                    SUM(bytes) as total_bytes,
                    COUNT(*) as flow_count
                FROM netflow_flows 
                WHERE flow_start > %s
            """, (thirty_days_ago,))
            
            traffic_data = cleanup.cursor.fetchone()
            if traffic_data and traffic_data['total_bytes']:
                gb = traffic_data['total_bytes'] / (1024**3)
                logger.info(f"  Трафик за 30 дней: {gb:.2f} GB, потоков: {traffic_data['flow_count']:,}")
    
    except Exception as e:
        logger.error(f"Ошибка получения статистики таблиц: {e}")
    
    logger.info("=" * 60)

def main():
    """Основная функция"""
    parser = argparse.ArgumentParser(
        description='Скрипт очистки базы данных NetFlow',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s --days 30                      # Удалить данные старше 30 дней
  %(prog)s --hours 24                     # Удалить данные старше 24 часов
  %(prog)s --retention 90 --vacuum        # Удалить и оптимизировать таблицы
  %(prog)s --days 30 --archive            # Архивировать старые данные
  %(prog)s --stats                        # Показать статистику
  %(prog)s --dry-run --days 7             # Показать что будет удалено
        """
    )
    
    # Параметры времени хранения
    retention_group = parser.add_mutually_exclusive_group()
    retention_group.add_argument('--days', type=int, help='Количество дней хранения данных')
    retention_group.add_argument('--hours', type=int, help='Количество часов хранения данных')
    retention_group.add_argument('--retention', type=int, help='Количество дней хранения (синоним для --days)')
    
    # Параметры таблиц
    parser.add_argument('--table', help='Очистить только указанную таблицу')
    parser.add_argument('--date-column', default='flow_start', 
                       help='Колонка с датой для фильтрации (по умолчанию: flow_start)')
    
    # Дополнительные параметры
    parser.add_argument('--vacuum', action='store_true', help='Выполнить VACUUM после очистки')
    parser.add_argument('--analyze', action='store_true', help='Выполнить ANALYZE для обновления статистики')
    parser.add_argument('--archive', action='store_true', 
                       help='Архивировать старые данные вместо удаления')
    parser.add_argument('--archive-suffix', default='_archive',
                       help='Суффикс для таблиц архива (по умолчанию: _archive)')
    
    # Информационные параметры
    parser.add_argument('--stats', action='store_true', help='Показать статистику базы данных')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Показать что будет удалено без фактического удаления')
    parser.add_argument('--simple-stats', action='store_true', 
                       help='Показать упрощенную статистику')
    
    args = parser.parse_args()
    
    # Определяем время хранения
    retention_days = 0
    if args.days:
        retention_days = args.days
    elif args.hours:
        retention_days = args.hours / 24
    elif args.retention:
        retention_days = args.retention
    
    # Загружаем конфигурацию
    db_config = load_db_config()
    
    # Создаем объект очистки
    try:
        cleanup = DatabaseCleanup(db_config)
    except Exception as e:
        logger.error(f"Не удалось подключиться к базе данных: {e}")
        sys.exit(1)
    
    try:
        # Если запрошена статистика
        if args.stats or args.simple_stats:
            show_database_stats_simple(cleanup)
        
        # Если указан dry-run
        elif args.dry_run and retention_days > 0:
            show_dry_run(cleanup, retention_days, args.table, args.date_column)
        
        # Если нужно архивировать
        elif args.archive and retention_days > 0:
            perform_archive(cleanup, retention_days, args.archive_suffix, args.vacuum)
        
        # Если нужно очистить
        elif retention_days > 0:
            perform_cleanup(cleanup, retention_days, args.table, args.date_column, 
                          args.vacuum, args.analyze)
        
        # Если не указаны параметры
        else:
            parser.print_help()
            
    finally:
        cleanup.disconnect()

def show_dry_run(cleanup: DatabaseCleanup, retention_days: int, 
                table_name: Optional[str], date_column: str):
    """Показать что будет удалено без фактического удаления"""
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    logger.info("=" * 60)
    logger.info("ПРЕДВАРИТЕЛЬНЫЙ ПРОСМОТР (DRY RUN)")
    logger.info("=" * 60)
    logger.info(f"Дата отсечки: {cutoff_date}")
    logger.info(f"Будут удалены записи старше {retention_days} дней")
    
    if table_name:
        # Для одной таблицы
        if not cleanup.table_exists(table_name):
            logger.error(f"Таблица {table_name} не существует")
            return
        
        try:
            query = f"""
            SELECT COUNT(*) as count, 
                   MIN({date_column}) as oldest,
                   MAX({date_column}) as newest
            FROM {cleanup.schema}.{table_name}
            WHERE {date_column} < %s
            """
            
            cleanup.cursor.execute(query, (cutoff_date,))
            result = cleanup.cursor.fetchone()
            
            if result:
                logger.info(f"\nТаблица: {table_name}")
                logger.info(f"  Записей для удаления: {result['count']:,}")
                if result['oldest']:
                    logger.info(f"  Самая старая: {result['oldest']}")
                if result['newest']:
                    logger.info(f"  Самая новая из удаляемых: {result['newest']}")
        
        except Exception as e:
            logger.error(f"Ошибка запроса для таблицы {table_name}: {e}")
    
    else:
        # Для всех таблиц
        tables_to_check = [
            ('netflow_flows', 'flow_start'),
            ('netflow_debug_log', 'event_time'),
            ('netflow_raw_packets', 'received_at'),
        ]
        
        total_records = 0
        
        for table, col in tables_to_check:
            if not cleanup.table_exists(table):
                continue
            
            try:
                query = f"""
                SELECT COUNT(*) as count
                FROM {cleanup.schema}.{table}
                WHERE {col} < %s
                """
                
                cleanup.cursor.execute(query, (cutoff_date,))
                result = cleanup.cursor.fetchone()
                
                if result and result['count'] > 0:
                    logger.info(f"  {table}: {result['count']:,} записей")
                    total_records += result['count']
            
            except Exception as e:
                logger.error(f"Ошибка запроса для таблицы {table}: {e}")
        
        logger.info(f"\nВсего записей для удаления: {total_records:,}")
    
    logger.info("=" * 60)
    logger.info("Режим dry-run: данные НЕ будут удалены")
    logger.info("Для реального удаления запустите без флага --dry-run")

def perform_cleanup(cleanup: DatabaseCleanup, retention_days: int, 
                   table_name: Optional[str], date_column: str,
                   vacuum: bool, analyze: bool):
    """Выполнить очистку базы данных"""
    logger.info("=" * 60)
    logger.info(f"НАЧАЛО ОЧИСТКИ БАЗЫ ДАННЫХ")
    logger.info(f"Срок хранения: {retention_days} дней")
    logger.info(f"Дата отсечки: {datetime.now() - timedelta(days=retention_days)}")
    logger.info("=" * 60)
    
    start_time = datetime.now()
    total_deleted = 0
    
    if table_name:
        # Очистка одной таблицы
        if cleanup.table_exists(table_name):
            deleted, _ = cleanup.cleanup_table(table_name, retention_days, date_column, vacuum)
            total_deleted += deleted
        else:
            logger.error(f"Таблица {table_name} не существует")
    else:
        # Очистка всех таблиц
        results = cleanup.cleanup_all_tables(retention_days, vacuum)
        
        for table_info, (deleted, time_ms) in results.items():
            if deleted > 0:
                total_deleted += deleted
                logger.info(f"Удалено из {table_info}: {deleted:,} записей за {time_ms:.0f} мс")
    
    execution_time = (datetime.now() - start_time).total_seconds()
    
    logger.info("=" * 60)
    logger.info(f"ОЧИСТКА ЗАВЕРШЕНА")
    logger.info(f"Всего удалено записей: {total_deleted:,}")
    logger.info(f"Время выполнения: {execution_time:.2f} секунд")
    logger.info("=" * 60)
    
    # Обновляем статистику если нужно
    if analyze and total_deleted > 0:
        logger.info("Обновление статистики таблиц...")
        if table_name:
            cleanup.analyze_table(table_name)
        else:
            # Для всех таблиц в схеме
            try:
                cleanup.cursor.execute("""
                    SELECT table_name 
                    FROM information_schema.tables 
                    WHERE table_schema = %s 
                    AND table_type = 'BASE TABLE'
                """, (cleanup.schema,))
                tables = cleanup.cursor.fetchall()
                for table in tables:
                    cleanup.analyze_table(table['table_name'])
            except Exception as e:
                logger.error(f"Ошибка обновления статистики: {e}")
    
    # Показываем новую статистику
    if total_deleted > 0:
        logger.info("\nНовая статистика:")
        show_database_stats_simple(cleanup)

def perform_archive(cleanup: DatabaseCleanup, retention_days: int, 
                   archive_suffix: str, vacuum: bool):
    """Выполнить архивацию данных"""
    logger.info("=" * 60)
    logger.info(f"НАЧАЛО АРХИВАЦИИ ДАННЫХ")
    logger.info(f"Срок хранения: {retention_days} дней")
    logger.info(f"Суффикс таблицы архива: {archive_suffix}")
    logger.info("=" * 60)
    
    start_time = datetime.now()
    
    # Архивируем данные
    archived_count = cleanup.archive_old_data(retention_days, archive_suffix)
    
    execution_time = (datetime.now() - start_time).total_seconds()
    
    logger.info("=" * 60)
    logger.info(f"АРХИВАЦИЯ ЗАВЕРШЕНА")
    logger.info(f"Всего архивировано записей: {archived_count:,}")
    logger.info(f"Время выполнения: {execution_time:.2f} секунд")
    logger.info("=" * 60)
    
    # Оптимизируем таблицы если нужно
    if vacuum and archived_count > 0:
        cleanup.vacuum_table('netflow_flows')

if __name__ == "__main__":
    main()
