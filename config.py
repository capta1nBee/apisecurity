"""
API Security Dashboard Configuration
"""

import os

class Config:
    
    # MongoDB Configuration
    MONGODB_URI = os.environ.get('MONGODB_URI') or 'mongodb://apinizer:PASSWORD@MONGOIP:25080/'
    MONGODB_DB = 'apinizerdb'

    # Elasticsearch Configurations - Now loaded from MongoDB connection_config_elasticsearch collection

    # Sensitive Keywords File
    SENSITIVE_KEYWORDS_FILE = os.environ.get('SENSITIVE_KEYWORDS_FILE') or 'sample.txt'

    # Security Score Weights
    SECURITY_SCORE_WEIGHTS = {
        'ip_whitelist_coverage': 0.15,       # IP whitelist kullanım oranı
        'throttling_configured': 0.15,       # Throttling policy varlığı
        'quota_configured': 0.05,            # Quota policy varlığı
        'authentication_strength': 0.20,     # Authentication policy güçlülüğü
        'allowed_hours': 0.05,               # Allowed hours policy (zaman kısıtlaması)
        'traffic_anomaly': 0.05,             # Trafik anomalisi
        'error_rate': 0.05,                  # Hata oranı
        'ssl_tls_status': 0.10,              # SSL/TLS kullanımı (client + backend)
        'logging_status': 0.20               # Logging durumu ve sensitive data kontrolü
    }
    
    # Dashboard Settings
    DEFAULT_DATE_RANGE_DAYS = 7
    MAX_DATE_RANGE_DAYS = 90
    ITEMS_PER_PAGE = 20
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

