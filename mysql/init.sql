-- ePhish Database Schema
CREATE DATABASE IF NOT EXISTS ephish_db;
USE ephish_db;

-- Analysis logs table
CREATE TABLE analysis_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_type VARCHAR(50) NOT NULL,
    filename VARCHAR(255),
    verdict VARCHAR(50),
    confidence FLOAT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSON
);

-- Email analysis results
CREATE TABLE email_analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    content TEXT,
    phishing_score FLOAT,
    is_phishing BOOLEAN DEFAULT FALSE,
    confidence FLOAT,
    suspicious_urls JSON,
    social_engineering_indicators JSON,
    verdict VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Malware analysis results
CREATE TABLE malware_analyses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    file_hash VARCHAR(64),
    is_malware BOOLEAN DEFAULT FALSE,
    malware_family VARCHAR(100),
    malware_confidence FLOAT,
    entropy FLOAT,
    yara_matches JSON,
    verdict VARCHAR(50),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User activity logs
CREATE TABLE user_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100),
    action VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- URL intelligence database
CREATE TABLE url_intelligence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(2048),
    domain VARCHAR(255),
    reputation_score INT DEFAULT 0,
    category VARCHAR(100),
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    is_suspicious BOOLEAN DEFAULT FALSE
);

-- Create indexes for performance
CREATE INDEX idx_email_phishing ON email_analyses(is_phishing, timestamp);
CREATE INDEX idx_malware_detection ON malware_analyses(is_malware, timestamp);
CREATE INDEX idx_file_hash ON malware_analyses(file_hash);
CREATE INDEX idx_analysis_timestamp ON analysis_logs(timestamp);

-- Insert sample data for testing
INSERT INTO analysis_logs (analysis_type, filename, verdict, confidence) VALUES
('email', 'test_phishing.eml', 'phishing_detected', 0.85),
('malware', 'suspicious.exe', 'malware_detected', 0.92),
('email', 'legitimate.eml', 'clean', 0.15);

-- Set proper permissions
GRANT ALL PRIVILEGES ON ephish_db.* TO 'root'@'%';
FLUSH PRIVILEGES;