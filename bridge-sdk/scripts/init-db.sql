-- BlackHole Bridge Database Initialization
-- ==========================================

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS bridge;
CREATE SCHEMA IF NOT EXISTS monitoring;
CREATE SCHEMA IF NOT EXISTS audit;

-- Set search path
SET search_path TO bridge, public;

-- Create transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tx_hash VARCHAR(66) NOT NULL UNIQUE,
    source_chain VARCHAR(20) NOT NULL,
    dest_chain VARCHAR(20) NOT NULL,
    source_address VARCHAR(100) NOT NULL,
    dest_address VARCHAR(100) NOT NULL,
    token_symbol VARCHAR(10) NOT NULL,
    token_contract VARCHAR(100),
    amount DECIMAL(36, 18) NOT NULL,
    fee DECIMAL(36, 18) DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    block_number BIGINT,
    block_hash VARCHAR(66),
    gas_used BIGINT,
    gas_price DECIMAL(36, 18),
    nonce BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    metadata JSONB
);

-- Create events table
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    chain VARCHAR(20) NOT NULL,
    block_number BIGINT NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    log_index INTEGER NOT NULL,
    contract_address VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(chain, tx_hash, log_index)
);

-- Create replay protection table
CREATE TABLE IF NOT EXISTS replay_protection (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_hash VARCHAR(66) NOT NULL UNIQUE,
    chain VARCHAR(20) NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    block_number BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create failed events table
CREATE TABLE IF NOT EXISTS failed_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID REFERENCES events(id),
    error_message TEXT NOT NULL,
    error_code VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    next_retry_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- Create circuit breakers table
CREATE TABLE IF NOT EXISTS circuit_breakers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE,
    state VARCHAR(20) NOT NULL DEFAULT 'closed',
    failure_count INTEGER DEFAULT 0,
    failure_threshold INTEGER DEFAULT 5,
    timeout_duration INTERVAL DEFAULT '5 minutes',
    last_failure_at TIMESTAMP WITH TIME ZONE,
    opened_at TIMESTAMP WITH TIME ZONE,
    half_open_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create monitoring metrics table
CREATE TABLE IF NOT EXISTS monitoring.metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(20, 8) NOT NULL,
    labels JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    user_id VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    request_data JSONB,
    response_data JSONB,
    status_code INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_source_chain ON transactions(source_chain);
CREATE INDEX IF NOT EXISTS idx_transactions_dest_chain ON transactions(dest_chain);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_tx_hash ON transactions(tx_hash);

CREATE INDEX IF NOT EXISTS idx_events_processed ON events(processed);
CREATE INDEX IF NOT EXISTS idx_events_chain ON events(chain);
CREATE INDEX IF NOT EXISTS idx_events_block_number ON events(block_number);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

CREATE INDEX IF NOT EXISTS idx_replay_protection_expires_at ON replay_protection(expires_at);
CREATE INDEX IF NOT EXISTS idx_replay_protection_chain ON replay_protection(chain);

CREATE INDEX IF NOT EXISTS idx_failed_events_retry_count ON failed_events(retry_count);
CREATE INDEX IF NOT EXISTS idx_failed_events_next_retry_at ON failed_events(next_retry_at);

CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON monitoring.metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON monitoring.metrics(metric_name);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit.logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit.logs(action);

-- Create functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_transactions_updated_at 
    BEFORE UPDATE ON transactions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_circuit_breakers_updated_at 
    BEFORE UPDATE ON circuit_breakers 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create function to clean up old replay protection entries
CREATE OR REPLACE FUNCTION cleanup_expired_replay_protection()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM replay_protection WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to get bridge statistics
CREATE OR REPLACE FUNCTION get_bridge_stats()
RETURNS TABLE (
    total_transactions BIGINT,
    pending_transactions BIGINT,
    completed_transactions BIGINT,
    failed_transactions BIGINT,
    total_volume DECIMAL(36, 18),
    avg_processing_time INTERVAL
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_transactions,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_transactions,
        COUNT(*) FILTER (WHERE status = 'completed') as completed_transactions,
        COUNT(*) FILTER (WHERE status = 'failed') as failed_transactions,
        COALESCE(SUM(amount), 0) as total_volume,
        AVG(completed_at - created_at) as avg_processing_time
    FROM transactions;
END;
$$ LANGUAGE plpgsql;

-- Insert initial circuit breakers
INSERT INTO circuit_breakers (name, failure_threshold, timeout_duration) VALUES
    ('ethereum_listener', 5, '5 minutes'),
    ('solana_listener', 5, '5 minutes'),
    ('blackhole_listener', 5, '5 minutes'),
    ('ethereum_relay', 3, '10 minutes'),
    ('solana_relay', 3, '10 minutes'),
    ('blackhole_relay', 3, '10 minutes')
ON CONFLICT (name) DO NOTHING;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA bridge TO bridge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA monitoring TO bridge;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA audit TO bridge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA bridge TO bridge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA monitoring TO bridge;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA audit TO bridge;
