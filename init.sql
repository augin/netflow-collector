-- Инициализация базы данных для NetFlow коллектора

-- Создаем схему если её нет
CREATE SCHEMA IF NOT EXISTS netflow;

-- Устанавливаем поиск пути
SET search_path TO netflow, public;

-- Таблица потоков
CREATE TABLE IF NOT EXISTS netflow_flows (
    id BIGSERIAL PRIMARY KEY,
    flow_start TIMESTAMP NOT NULL,
    flow_end TIMESTAMP NOT NULL,
    src_ip INET NOT NULL,
    dst_ip INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol INTEGER,
    packets BIGINT DEFAULT 0,
    bytes BIGINT DEFAULT 0,
    flow_duration_ms BIGINT DEFAULT 0,
    exporter_ip INET NOT NULL,
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
    netflow_version INTEGER DEFAULT 5,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для быстрого поиска
CREATE INDEX IF NOT EXISTS idx_netflow_flows_flow_start ON netflow_flows(flow_start);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_src_ip ON netflow_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_dst_ip ON netflow_flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_exporter_ip ON netflow_flows(exporter_ip);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_src_port ON netflow_flows(src_port);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_dst_port ON netflow_flows(dst_port);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_protocol ON netflow_flows(protocol);
CREATE INDEX IF NOT EXISTS idx_netflow_flows_created_at ON netflow_flows(created_at);

-- Таблица экспортеров
CREATE TABLE IF NOT EXISTS netflow_exporters (
    id SERIAL PRIMARY KEY,
    exporter_ip INET UNIQUE NOT NULL,
    exporter_name VARCHAR(256),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_flows BIGINT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    version INTEGER DEFAULT 5,
    sampling_rate INTEGER DEFAULT 1
);

-- Таблица агрегированной статистики
CREATE TABLE IF NOT EXISTS netflow_aggregates (
    id BIGSERIAL PRIMARY KEY,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    src_ip INET,
    dst_ip INET,
    protocol INTEGER,
    total_bytes BIGINT DEFAULT 0,
    total_packets BIGINT DEFAULT 0,
    flow_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индексы для агрегированной статистики
CREATE INDEX IF NOT EXISTS idx_netflow_aggregates_period ON netflow_aggregates(period_start, period_end);

-- Таблица для мониторинга и метрик
CREATE TABLE IF NOT EXISTS netflow_metrics (
    id SERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    metric_labels JSONB,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Индекс для метрик
CREATE INDEX IF NOT EXISTS idx_netflow_metrics_collected_at ON netflow_metrics(collected_at);
CREATE INDEX IF NOT EXISTS idx_netflow_metrics_name ON netflow_metrics(metric_name);

-- Комментарии к таблицам
COMMENT ON TABLE netflow_flows IS 'Сырые данные потоков NetFlow';
COMMENT ON TABLE netflow_exporters IS 'Информация об экспортерах NetFlow';
COMMENT ON TABLE netflow_aggregates IS 'Агрегированная статистика по потокам';
COMMENT ON TABLE netflow_metrics IS 'Метрики для мониторинга системы';

-- Представления для удобства

-- Статистика по экспортерам
CREATE OR REPLACE VIEW netflow_exporters_stats AS
SELECT 
    exporter_ip,
    exporter_name,
    first_seen,
    last_seen,
    total_flows,
    pg_size_pretty(total_bytes) as total_traffic,
    version,
    sampling_rate,
    EXTRACT(DAY FROM (last_seen - first_seen)) as days_active
FROM netflow_exporters
ORDER BY total_bytes DESC;

-- Ежедневная статистика
CREATE OR REPLACE VIEW netflow_daily_stats AS
SELECT 
    DATE(flow_start) as day,
    COUNT(*) as flow_count,
    SUM(bytes) as total_bytes,
    SUM(packets) as total_packets,
    COUNT(DISTINCT src_ip) as unique_src_ips,
    COUNT(DISTINCT dst_ip) as unique_dst_ips,
    COUNT(DISTINCT exporter_ip) as unique_exporters
FROM netflow_flows
GROUP BY DATE(flow_start)
ORDER BY day DESC;

-- Топ источников трафика
CREATE OR REPLACE VIEW netflow_top_sources AS
SELECT 
    src_ip,
    COUNT(*) as flow_count,
    SUM(bytes) as total_bytes,
    SUM(packets) as total_packets,
    COUNT(DISTINCT dst_ip) as unique_destinations
FROM netflow_flows
WHERE flow_start > CURRENT_TIMESTAMP - INTERVAL '1 day'
GROUP BY src_ip
ORDER BY total_bytes DESC
LIMIT 50;

-- Топ приложений
CREATE OR REPLACE VIEW netflow_top_applications AS
SELECT 
    application_name,
    COUNT(*) as flow_count,
    SUM(bytes) as total_bytes,
    SUM(packets) as total_packets
FROM netflow_flows
WHERE flow_start > CURRENT_TIMESTAMP - INTERVAL '1 day'
GROUP BY application_name
ORDER BY total_bytes DESC
LIMIT 20;

-- Права доступа (если используется отдельный пользователь)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA netflow TO netflow_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA netflow TO netflow_user;
GRANT USAGE ON SCHEMA netflow TO netflow_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA netflow 
GRANT ALL ON TABLES TO netflow_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA netflow 
GRANT ALL ON SEQUENCES TO netflow_user;

ALTER USER netflow_user WITH PASSWORD 'your_strong_password_here';

