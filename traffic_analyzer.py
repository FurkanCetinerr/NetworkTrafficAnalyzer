import scapy.all as scapy
import csv
import pandas as pd
import matplotlib.pyplot as plt
from flask import Flask, render_template, send_file
import os

# Flask Uygulamasını Başlat
app = Flask(__name__)

# CSV dosyasına veri kaydetme fonksiyonu
def save_packet_data(source_ip, dest_ip, source_port, dest_port, protocol):
    with open("traffic_reports.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([source_ip, dest_ip, source_port, dest_port, protocol])

# ICMP paketlerini kaydetme fonksiyonu
def save_icmp_traffic(source_ip, dest_ip):
    with open("icmp_traffic.csv", "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([source_ip, dest_ip, "ICMP"])

# TCP üçlü el sıkışma kontrolü
def check_syn(packet):
    if packet.haslayer(scapy.TCP):
        # Eğer SYN bayrağı set edildiyse, bağlantı başlatılıyor demektir
        if packet[scapy.TCP].flags == "S":  # SYN bayrağı
            print(f"Yeni bağlantı başlatılıyor: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}")

# Güvenlik uyarıları
def security_alert(packet):
    # Port taraması tespiti
    if packet.haslayer(scapy.TCP):
        source_port = packet[scapy.TCP].sport
        dest_port = packet[scapy.TCP].dport
        # Eğer aynı port üzerinden çok sayıda bağlantı varsa, bu bir port taraması olabilir.
        if source_port == dest_port:
            print(f"Potansiyel port taraması tespit edildi: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}")

# Paketleri filtreleme ve analiz etme fonksiyonu
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        dest_ip = packet[scapy.IP].dst

        # Filtreleme koşulları (Örneğin, belirli bir IP'yi izlemek)
        if source_ip == "192.168.1.100" or dest_ip == "192.168.1.100":
            if packet.haslayer(scapy.TCP):
                source_port = packet[scapy.TCP].sport
                dest_port = packet[scapy.TCP].dport
                protocol = "TCP"
                # Belirli portları izleme
                if source_port == 80 or dest_port == 80:  # HTTP trafiğini izleyelim
                    save_packet_data(source_ip, dest_ip, source_port, dest_port, protocol)
            elif packet.haslayer(scapy.UDP):
                source_port = packet[scapy.UDP].sport
                dest_port = packet[scapy.UDP].dport
                protocol = "UDP"
                save_packet_data(source_ip, dest_ip, source_port, dest_port, protocol)

            # ICMP paketlerini izleyelim
            if packet.haslayer(scapy.ICMP):
                print(f"ICMP paketleri: {packet[scapy.IP].src} -> {packet[scapy.IP].dst}")
                save_icmp_traffic(source_ip, dest_ip)

            # TCP üçlü el sıkışma kontrolü
            check_syn(packet)

            # Güvenlik uyarıları
            security_alert(packet)

# Trafiği yakalamaya başlamak için Scapy kullanma
def start_sniffing():
    print("Trafik yakalanıyor...")
    scapy.sniff(prn=packet_callback, store=0)  # Paketleri yakalayıp işleme fonksiyonuna gönder

# Veri analizi için basit bir rapor hazırlama
def generate_report():
    df = pd.read_csv('traffic_reports.csv')
    print(df.describe())

    # Grafikleri görselleştirme
    df['Source Port'].value_counts().plot(kind='bar', title="Source Port Distribution")
    plt.savefig('static/source_port_distribution.png')
    plt.close()

    df['Destination Port'].value_counts().plot(kind='bar', title="Destination Port Distribution")
    plt.savefig('static/destination_port_distribution.png')
    plt.close()

    df['Protocol'].value_counts().plot(kind='pie', autopct='%1.1f%%', colors=['#FF9999','#66B3FF','#99FF99'], title="Protocol Distribution")
    plt.savefig('static/protocol_distribution.png')
    plt.close()

# Web Arayüzü: Ana Sayfa
@app.route('/')
def index():
    return render_template('index.html')

# Web Arayüzü: Rapor Oluşturma
@app.route('/generate_report')
def generate():
    generate_report()
    return render_template('report_generated.html')

# Web Arayüzü: Grafik Görselleştirmeleri
@app.route('/view_graphs')
def view_graphs():
    return render_template('view_graphs.html')

# Web Arayüzü: Grafikleri Gösterme
@app.route('/static/<filename>')
def send_graph(filename):
    return send_file(os.path.join('static', filename))

# Flask Uygulamasını Başlat
if __name__ == "__main__":
    start_sniffing()  # Trafik yakalamaya başla
    app.run(debug=True)  # Web arayüzünü başlat
