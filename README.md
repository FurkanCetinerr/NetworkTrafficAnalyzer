# Network Traffic Analyzer

Bu proje, ağ trafiğini analiz etmek için kullanılan bir Python tabanlı uygulamadır. Uygulama, ağ trafiğini dinleyerek verileri CSV dosyasına kaydeder ve bu verileri analiz etmek için basit görselleştirmeler oluşturur. Ayrıca, ICMP paketlerini izler ve potansiyel güvenlik uyarıları sağlar.

## Özellikler

- **Ağ Trafiği İzleme**: ICMP, TCP ve UDP paketlerini analiz eder.
- **Görselleştirme**: Kaydedilen ağ trafiği verilerini bar grafikleri olarak görselleştirir.
- **Güvenlik Uyarıları**: Port taraması ve TCP üçlü el sıkışma gibi güvenlik tehditlerini tespit eder.
- **Web Arayüzü**: Flask tabanlı basit bir web arayüzü üzerinden raporları görüntüleme.

## Kurulum

Bu projeyi çalıştırmak için aşağıdaki adımları izleyin:

### 1. Python ve Gerekli Paketler

Python 3.x ve gerekli paketlerin yüklü olduğundan emin olun. Proje için gereken paketleri yüklemek için şu komutları kullanabilirsiniz:

```bash
pip install -r requirements.txt
