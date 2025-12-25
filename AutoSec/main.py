import argparse
import socket
from modules import recon
from modules import scan
from modules import intel
from modules import report  # Rapor modülünü ekledik

def main():
    parser = argparse.ArgumentParser(description="Otomatize Siber Güvenlik Aracı v1.0")
    parser.add_argument("-t", "--target", help="Hedef Domain", required=True)
    
    args = parser.parse_args()
    target = args.target

    print("-" * 50)
    print(f"HEDEF: {target}")
    print("-" * 50)

    # --- VERİ TOPLAMA ---
    active_ips = set()
    domain_ip_map = {} 
    
    # Raporlama için veri tutucular (HTML tablosu satırları olacak)
    html_ip_satirlari = ""
    html_scan_satirlari = ""

    # Root domain çözümü
    try:
        root_ip = socket.gethostbyname(target)
        active_ips.add(root_ip)
        domain_ip_map[target] = root_ip
    except:
        pass

    # Subdomain bulma
    bulunan_subdomainler = recon.subdomain_bul(target)
    if bulunan_subdomainler:
        ip_sonuclari = recon.ip_cozumle(bulunan_subdomainler)
        for sub, ip in ip_sonuclari.items():
            if ip:
                active_ips.add(ip)
                domain_ip_map[sub] = ip

    if not active_ips:
        print("[-] IP bulunamadı.")
        return

    # --- İSTİHBARAT VE IP LİSTELEME ---
    print("\n" + "-" * 60)
    print(f"{'DOMAIN':<30} | {'IP ADRESİ':<15} | {'KONUM / ISP'}")
    print("-" * 60)
    
    for domain, ip in domain_ip_map.items():
        intel_info = intel.ip_bilgisi_getir(ip)
        print(f"{domain:<30} | {ip:<15} | {intel_info}")
        
        # Rapor için satır ekle
        html_ip_satirlari += f"<tr><td>{domain}</td><td>{ip}</td><td>{intel_info}</td></tr>"

    # --- AKTİF TARAMA ---
    print("\n" + "=" * 60)
    secim = input(f"Toplam {len(active_ips)} adet IP taransın mı? (E/H): ").lower()
    
    if secim == 'e':
        print("\n[*] Taranıyor...")
        for ip in active_ips:
            sonuclar = scan.tara_hedef(ip) # scan.py artık sonuç listesi dönüyor
            
            if sonuclar:
                for res in sonuclar:
                    # Rapor için satır ekle
                    html_scan_satirlari += f"<tr><td>{ip}</td><td>{res['port']}</td><td class='danger'>AÇIK</td><td>{res['banner']}</td></tr>"
            else:
                 html_scan_satirlari += f"<tr><td>{ip}</td><td colspan='3'>Açık port bulunamadı</td></tr>"
                 
            print("-" * 30)
            
        # --- RAPOR OLUŞTURMA ---
        print("\n[*] Rapor hazırlanıyor...")
        report.html_rapor_olustur(target, html_ip_satirlari, html_scan_satirlari)
        
    else:
        print("[!] Tarama iptal edildi.")

if __name__ == "__main__":
    main()
