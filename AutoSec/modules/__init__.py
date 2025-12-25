import requests

def ip_bilgisi_getir(ip):
    """
    ip-api.com servisini kullanarak IP adresinin coğrafi ve ISP bilgilerini getirir.
    """
    url = f"http://ip-api.com/json/{ip}"
    
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                ulke = data.get('country', 'Bilinmiyor')
                sehir = data.get('city', 'Bilinmiyor')
                isp = data.get('isp', 'Bilinmiyor')
                return f"{ulke} / {sehir} - {isp}"
            else:
                return "Bilgi Bulunamadı (Private IP olabilir)"
        else:
            return "API Hatası"
    except Exception as e:
        return f"Hata: {e}"
