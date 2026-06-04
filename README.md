# Network Anomaly Detection System

Python tabanlı, modüler ve genişletilebilir bir ağ anomali tespit sistemi.

Bu proje; PCAP dosyalarını okuyabilen, ağ paketlerinden IP bazlı feature çıkarabilen, kural tabanlı anomali tespiti yapabilen ve ileride makine öğrenmesi ile dashboard katmanları üzerinden büyütülebilecek profesyonel bir güvenlik analiz altyapısı sunar. Fedora 42+ üzerinde Python 3.11+ ile geliştirme hedeflenmiştir.

## Sistem Mimarisi

```text
PCAP Upload / Raw PCAP
        |
        v
app/capture/pcap_reader.py
        |
        v
app/processing/feature_extractor.py
        |
        v
app/detection/rule_engine.py
        |
        +--> data/processed/features.csv
        +--> data/processed/anomalies.csv
        |
        v
FastAPI Backend <----> Streamlit Dashboard
```

Mimari katmanlı tasarlanmıştır. PCAP okuma, veri işleme, tespit motoru, API, dashboard ve model dosyaları birbirinden ayrılmıştır. Bu yapı ileride ML modeli, veritabanı, kimlik doğrulama, SIEM entegrasyonu veya gerçek zamanlı trafik analizi eklemeyi kolaylaştırır.

## Özellikler

- PCAP ve PCAPNG dosyalarını Scapy ile okuma.
- Paket bazlı alan çıkarımı: timestamp, kaynak/hedef IP, port, protokol ve paket boyutu.
- IP bazlı feature extraction.
- Rule-based anomaly detection engine.
- Port scan, high traffic, suspicious connection rate ve multi-target scan kuralları.
- Isolation Forest tabanlı ML hazırlık modülü.
- FastAPI backend ile PCAP analiz endpointleri.
- Streamlit dashboard ile dosya yükleme, metrikler, tablolar ve grafikler.
- CSV çıktı desteği.
- Merkezi konfigürasyon yönetimi.
- Logging altyapısı.
- Test edilebilir ve modüler proje yapısı.

## Kullanılan Teknolojiler

- Python 3.11+
- FastAPI
- Uvicorn
- Streamlit
- Scapy
- pandas
- scikit-learn
- Pydantic Settings
- requests
- pytest

## Kurulum

Fedora 42+ üzerinde gerekli temel paketleri kurun:

```bash
sudo dnf install -y python python-pip python-devel gcc
```

Projeyi klonladıktan veya indirdikten sonra:

```bash
cd network-anomaly-detection
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## FastAPI Çalıştırma

Backend servisini başlatmak için:

```bash
uvicorn app.main:app --reload
```

Servis varsayılan olarak şu adreste çalışır:

```text
http://127.0.0.1:8000
```

Kullanılabilir temel endpointler:

- `GET /`: sistem durum bilgisi
- `GET /api/health`: servis sağlık kontrolü
- `POST /api/analyze-pcap`: PCAP dosyası yükleme ve analiz
- `GET /api/features`: son üretilen feature çıktısı
- `GET /api/anomalies`: son üretilen anomali çıktısı
- `GET /docs`: OpenAPI dokümantasyonu

## Streamlit Çalıştırma

FastAPI backend çalışırken ayrı bir terminalde:

```bash
source .venv/bin/activate
streamlit run dashboard/streamlit_app.py
```

Dashboard varsayılan olarak şu adreste açılır:

```text
http://127.0.0.1:8501
```

Backend API adresi `.env` üzerinden yönetilebilir:

```bash
BACKEND_API_URL=http://127.0.0.1:8000
```

Geliştirme ortamında Streamlit için izin verilen CORS origin değerleri de `.env` üzerinden yönetilebilir. Varsayılan değerler `http://127.0.0.1:8501` ve `http://localhost:8501` adresleridir.

```bash
CORS_ALLOW_ORIGINS=["http://127.0.0.1:8501","http://localhost:8501"]
```

Başlangıç için `.env.example` dosyasını kullanabilirsiniz:

```bash
cp .env.example .env
```

## Örnek Kullanım Akışı

1. Backend servisini başlatın:

```bash
uvicorn app.main:app --reload
```

2. Dashboard'u başlatın:

```bash
streamlit run dashboard/streamlit_app.py
```

3. Dashboard üzerinden bir PCAP veya PCAPNG dosyası yükleyin.

4. Sistem şu akışı çalıştırır:

```text
PCAP dosyası -> paket okuma -> feature extraction -> rule-based detection -> JSON + CSV çıktı
```

5. Sonuçlar dashboard üzerinde metrikler, anomali tablosu, feature tablosu ve dağılım grafikleriyle görüntülenir.

API üzerinden manuel analiz için:

```bash
curl -X POST "http://127.0.0.1:8000/api/analyze-pcap" \
  -F "file=@data/raw/sample.pcap"
```

Son üretilen çıktıları okumak için:

```bash
curl "http://127.0.0.1:8000/api/features"
curl "http://127.0.0.1:8000/api/anomalies"
```

## Klasör Yapısı

```text
network-anomaly-detection/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── capture/
│   │   └── pcap_reader.py
│   ├── processing/
│   │   └── feature_extractor.py
│   ├── detection/
│   │   ├── rule_engine.py
│   │   └── ml_detector.py
│   ├── database/
│   ├── api/
│   │   └── routes.py
│   └── utils/
│       └── logging.py
├── dashboard/
│   └── streamlit_app.py
├── data/
│   ├── raw/
│   ├── processed/
│   └── models/
├── tests/
├── LICENSE
├── requirements.txt
├── README.md
└── .gitignore
```

## Modül Açıklamaları

- `app/capture`: PCAP okuma ve paket düzeyinde veri çıkarımı.
- `app/processing`: IP bazlı feature extraction.
- `app/detection`: Kural tabanlı tespit ve ML hazırlık modülleri.
- `app/api`: FastAPI endpointleri.
- `app/utils`: Logging ve ortak yardımcı bileşenler.
- `dashboard`: Streamlit arayüzü.
- `data/raw`: Yüklenen veya test amaçlı kullanılan PCAP dosyaları.
- `data/processed`: Feature ve anomali CSV çıktıları.
- `data/models`: ML model dosyaları.

## Test

Testleri çalıştırmak için sanal ortam aktifken:

```bash
pytest
```

## Makine Öğrenmesi Hazırlığı

`app/detection/ml_detector.py` modülü Isolation Forest tabanlı bir hazırlık katmanı içerir. Bu modül henüz backend akışına zorunlu olarak bağlanmamıştır.

```python
from app.detection.ml_detector import predict_anomalies, train_model

train_model(features_df)
ml_results_df = predict_anomalies(features_df)
```

Model varsayılan olarak şu dosyaya kaydedilir:

```text
data/models/isolation_forest.pkl
```

## Geliştirme Yol Haritası

- Flow-level feature extraction.
- ML modelinin backend analiz akışına opsiyonel entegrasyonu.
- Veritabanı katmanı ve analiz geçmişi.
- Kullanıcı kimlik doğrulama ve rol bazlı erişim.
- Gerçek zamanlı trafik yakalama desteği.
- SIEM entegrasyonu.
- Docker ve Compose desteği.
- CI/CD pipeline.
- Gelişmiş test kapsamı.
- Model performans izleme ve drift analizi.

## Güvenlik Notu

Bu proje eğitim, araştırma ve savunma amaçlı ağ güvenliği analizi için tasarlanmıştır. PCAP dosyaları hassas ağ bilgileri, IP adresleri, servis izleri veya kurum içi trafik örüntüleri içerebilir. Üretim ortamında kullanmadan önce dosya erişim kontrolleri, kimlik doğrulama, yetkilendirme, veri maskeleme ve güvenli saklama politikaları uygulanmalıdır.

Yalnızca analiz etmeye yetkili olduğunuz ağ trafiği üzerinde kullanın.

## Terminal Komutları

Projeyi temiz bir Fedora/Linux ortamında kurmak, test etmek ve çalıştırmak için temel komutlar:

```bash
cd network-anomaly-detection
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pytest
uvicorn app.main:app --reload
```

Dashboard için ayrı bir terminalde:

```bash
cd network-anomaly-detection
source .venv/bin/activate
streamlit run dashboard/streamlit_app.py
```

API smoke test:

```bash
curl "http://127.0.0.1:8000/"
curl "http://127.0.0.1:8000/api/health"
```

## Lisans

Bu proje MIT lisansı ile yayınlanmıştır. Ayrıntılar için `LICENSE` dosyasını inceleyin.
