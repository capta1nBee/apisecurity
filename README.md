# API Security Dashboard

API güvenlik analizi ve raporlama için geliştirilmiş Flask tabanlı dashboard uygulaması.

![Dashboard](./images/dashboard.png)
![Recommedations](./images/recommendations.png)
![Details 1](./images/details_1.png)
![Details 2](./images/details_2.png)
![Details 3](./images/details_3.png)
![Details 4](./images/details_4.png)

##  Özellikler

### Güvenlik Analizi
- **9 Bileşenli Güvenlik Skorlaması**
  - IP Whitelist Coverage (15%)
  - Throttling Configuration (15%)
  - Quota Configuration (5%)
  - Authentication Strength (20%)
  - Allowed Hours (5%)
  - Traffic Anomaly (5%)
  - Error Rate (5%)
  - SSL/TLS Status (10%)
  - Logging Status (20%)

### SSL/TLS Analizi
- Client SSL durumu kontrolü
- Backend SSL durumu kontrolü
- HTTPS kullanım oranı analizi

### Sensitive Data Detection
- Loglarda hassas veri tespiti
- Configüre edilebilir keyword listesi
- Header ve body bazlı tarama
- Yüzdelik analiz ve raporlama

### Trafik Analizi
- Gerçek zamanlı trafik istatistikleri
- Saatlik dağılım heatmap
- Anomali tespiti
- Hata oranı analizi

### Raporlama
- **PDF Export**: Detaylı güvenlik raporu
- **Excel Export**: Çok sayfalı analiz raporu
- **Share**: Paylaşılabilir link oluşturma
- **JSON Export**: Programatik erişim

## 📋 Gereksinimler

- Python 3.8+
- MongoDB
- Elasticsearch
- Flask ve bağımlılıklar (requirements.txt)

## 🔧 Kurulum

### 1. Repository'yi Klonlayın
```bash
git clone <repository-url>
cd api_security_dashboard
```

### 2. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 3. Konfigürasyon

#### MongoDB Bağlantısı
`config.py` dosyasında MongoDB URI'yi ayarlayın:
```python
MONGODB_URI = 'mongodb://username:password@host:port/'
MONGODB_DATABASE = 'apinizer'
```

#### Elasticsearch Konfigürasyonu
Elasticsearch konfigürasyonları MongoDB'den otomatik olarak alınır.
`connection_config_elasticsearch` koleksiyonuna kayıt ekleyin:

```javascript
{
  "name": "PROD-ES",
  "enabled": true,
  "type": "READ_WRITE",
  "elasticHostList": [
    {
      "scheme": "HTTP",
      "host": "10.10.10.14",
      "port": 9200
    }
  ],
  "authenticate": false,
  "indexName": "apinizer-log-apiproxy-default"
}
```

#### Sensitive Keywords
`sample.txt` dosyasında hassas kelimeleri tanımlayın (virgülle ayrılmış):
```
tc,kimlik,tel,numara,password,email
```

Veya environment variable ile özel dosya belirtin:
```bash
export SENSITIVE_KEYWORDS_FILE="/path/to/keywords.txt"
```

## 🚀 Çalıştırma

### Development
```bash
python app.py
```

Uygulama `http://localhost:5000` adresinde çalışacaktır.

### Production
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 📊 Kullanım

### Ana Dashboard
- Tüm API'lerin listesi ve güvenlik skorları
- Filtreleme ve arama
- Tarih aralığı seçimi
- Elasticsearch seçimi

### API Detay Sayfası
- Detaylı güvenlik analizi
- Bileşen bazlı skorlar
- Güvenlik önerileri
- Trafik istatistikleri
- Hassas veri analizi

### Export İşlemleri

#### PDF Export
```javascript
exportReport('api_id', 'pdf')
```
- Kapsamlı güvenlik raporu
- Görsel tablolar
- Renk kodlu skorlar
- Öneriler listesi

#### Excel Export
```javascript
exportReport('api_id', 'excel')
```
- Summary sheet
- Components sheet
- Recommendations sheet
- Traffic stats sheet

#### Share
```javascript
shareReport('api_id')
```
- Paylaşılabilir link oluşturma
- Opsiyonel email gönderimi
- Clipboard'a otomatik kopyalama


## 🔐 Güvenlik Skorlama Detayları

### SSL/TLS Status (10%)
- **Client SSL (60%)**: API endpoint'lerinin HTTPS kullanımı
- **Backend SSL (40%)**: Backend bağlantılarının HTTPS kullanımı

### Logging Status (20%)
Sadece hassas veri varlığına göre skorlama:
- Hassas veri yok: 100 puan
- ≤1% hassas veri: 80 puan
- >1% hassas veri: 70 puan
- >5% hassas veri: 60 puan
- >10% hassas veri: 50 puan
- >20% hassas veri: 40 puan
- >50% hassas veri: 20 puan
- >80% hassas veri: 10 puan

### Authentication Strength (20%)
- No Auth: 0 puan
- API Key: 40 puan
- Basic Auth: 50 puan
- OAuth: 80 puan
- JWT: 90 puan
- mTLS: 100 puan


## �📝 Environment Variables

```bash
# MongoDB
MONGODB_URI=mongodb://username:password@host:port/
MONGODB_DATABASE=apinizer

# Elasticsearch (MongoDB'den alınır)
# Manuel konfigürasyon gerekmez

# Sensitive Keywords
SENSITIVE_KEYWORDS_FILE=sample.txt

# Flask
FLASK_ENV=development
DEBUG=True
```
