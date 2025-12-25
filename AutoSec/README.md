# 🛡️ AutoSec - Otomatize Siber Güvenlik ve Keşif Aracı

Bu proje, hedef sistemler üzerinde pasif bilgi toplama (Reconnaissance), tehdit istihbaratı (Threat Intel) ve aktif port tarama süreçlerini otomatize eden Python tabanlı bir CLI aracıdır.

## 🚀 Özellikler

- **Pasif Keşif:** `crt.sh` kullanarak subdomain tespiti.
- **Tehdit İstihbaratı:** IP adreslerinin coğrafi konumunu ve ISP bilgisini (ip-api.com) sorgular.
- **Aktif Tarama:** `Socket` kütüphanesi ve `Multithreading` kullanılarak yüksek hızlı port taraması ve Banner Grabbing.
- **Raporlama:** Sonuçları analiz edip okunabilir HTML formatında rapor üretir.
- **Hata Yönetimi:** API kesintilerine karşı dayanıklı mimari.

## 🛠️ Kurulum

```bash
git clone [https://github.com/KULLANICI_ADIN/AutoSec.git](https://github.com/KULLANICI_ADIN/AutoSec.git)
cd AutoSec
pip install -r requirements.txt
