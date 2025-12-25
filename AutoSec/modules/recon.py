import requests
import socket

def subdomain_bul(hedef_domain):
    """
    crt.sh üzerinden subdomainleri bulan fonksiyon.
    """
    print(f"[*] {hedef_domain} için pasif tarama başlatılıyor...")
    
    # crt.sh veritabanına sorgu atıyoruz (JSON formatında çıktı istiyoruz)
    url = f"https://crt.sh/?q=%.{hedef_domain}&output=json"
    
    subdomainler = set() # Tekrar edenleri engellemek için set kullanıyoruz
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                sub = entry['name_value']
                # Bazı sonuçlar alt satıra geçebilir, onları temizleyelim
                if "\n" in sub:
                    sub = sub.split("\n")[0]
                if "*" not in sub: # Wildcard domainleri filtreleyelim
                    subdomainler.add(sub)
            print(f"[+] Toplam {len(subdomainler)} adet subdomain bulundu.")
            return list(subdomainler)
        else:
            print("[-] crt.sh servisine ulaşılamadı.")
            return []
    except Exception as e:
        print(f"[-] Hata oluştu: {e}")
        return []

def ip_cozumle(subdomain_listesi):
    """
    Bulunan subdomainlerin IP adreslerini çözer.
    """
    print("[*] IP adresleri çözümleniyor...")
    sonuclar = {} # {subdomain: ip_adresi} şeklinde tutacağız

    for sub in subdomain_listesi:
        try:
            # DNS sorgusu yapıyoruz
            ip = socket.gethostbyname(sub)
            sonuclar[sub] = ip
            print(f"   [+] {sub} -> {ip}")
        except socket.gaierror:
            # IP çözülemezse pas geçiyoruz (ölü domain olabilir)
            print(f"   [-] {sub} -> IP Çözülemedi")
            pass
    
    return sonuclar
