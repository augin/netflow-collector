-- Создайте базу данных
CREATE DATABASE netflow_db;

-- Создайте таблицу для хранения потоков
CREATE TABLE netflow_flows (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    flow_id BIGINT,
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
    vlan_id INTEGER,
    application_name VARCHAR(256),
    bidirectional BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Индексы для быстрого поиска
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (src_ip),
    INDEX idx_dst_ip (dst_ip),
    INDEX idx_application (application_name)
);

-- Таблица для статистики экспортеров
CREATE TABLE netflow_exporters (
    id SERIAL PRIMARY KEY,
    exporter_ip INET UNIQUE NOT NULL,
    exporter_name VARCHAR(256),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_flows BIGINT DEFAULT 0,
    total_bytes BIGINT DEFAULT 0,
    version INTEGER
);

-- Таблица для агрегированной статистики
CREATE TABLE netflow_aggregates (
    id SERIAL PRIMARY KEY,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    src_ip INET,
    dst_ip INET,
    protocol INTEGER,
    total_bytes BIGINT,
    total_packets BIGINT,
    flow_count INTEGER,

    INDEX idx_period (period_start, period_end)
);
