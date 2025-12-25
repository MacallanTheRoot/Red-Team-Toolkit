import socket
from concurrent.futures import ThreadPoolExecutor

# Taranacak yaygın portlar listesi (Hız için sadece önemlileri seçtik)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 3389, 5432, 8080]

def port_kontrol(ip, port):
    """
    Tek bir IP ve Port için bağlantı dener.
    Açıksa Banner (servis bilgisi) almaya çalışır.
    """
    banner = None
    try:
        # Socket nesnesi oluştur
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # 1 saniye içinde cevap gelmezse geç
        
        # Bağlantı dene (connect_ex başarılıysa 0 döner)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            # Port açık! Şimdi servis bilgisini çekmeye çalışalım (Banner Grabbing)
            try:
                # Bazı servisler bağlantı kurulunca direkt veri gönderir (SSH, FTP gibi)
                # Bazıları için (HTTP) istek atmak gerekebilir, şimdilik basit tutuyoruz.
                banner_data = s.recv(1024).decode().strip()
                banner = banner_data if banner_data else "Servis Bilgisi Yok"
            except:
                banner = "Banner Alınamadı"
            
            s.close()
            return port, True, banner
        
        s.close()
        return port, False, None
    except:
        return port, False, None

def tara_hedef(ip):
    """
    Verilen IP için çoklu iş parçacığı (threading) ile port taraması başlatır.
    """
    print(f"[*] {ip} üzerinde aktif port taraması başlatılıyor...")
    acik_portlar = []
    
    # Threading: Aynı anda birden fazla portu taramak için (Hız için kritik!)
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Her port için port_kontrol fonksiyonunu çalıştır
        futures = [executor.submit(port_kontrol, ip, port) for port in COMMON_PORTS]
        
        for future in futures:
            port, is_open, banner = future.result()
            if is_open:
                print(f"    [+] AÇIK: Port {port} - {banner}")
                acik_portlar.append({"port": port, "banner": banner})
                
    if not acik_portlar:
        print(f"    [-] {ip} üzerinde yaygın açık port bulunamadı.")
        
    return acik_portlar
