from flask import Flask, render_template, send_from_directory
import scapy.all as scapy
import csv
import pandas as pd
import matplotlib.pyplot as plt

app = Flask(__name__)

# Diğer fonksiyonlar (save_packet_data, save_icmp_traffic, packet_callback vb.) burada yer almalı

# Ana sayfayı render et
@app.route('/')
def index():
    return render_template('index.html')

# Rapor sayfasını render et
@app.route('/generate_report')
def generate_report():
    df = pd.read_csv('traffic_reports.csv')

    # Verileri görselleştir
    df['Source Port'].value_counts().plot(kind='bar', title="Source Port Distribution")
    plt.savefig('static/source_port_distribution.png')
    df['Destination Port'].value_counts().plot(kind='bar', title="Destination Port Distribution")
    plt.savefig('static/destination_port_distribution.png')

    return render_template('report.html')

if __name__ == "__main__":
    app.run(debug=True)
