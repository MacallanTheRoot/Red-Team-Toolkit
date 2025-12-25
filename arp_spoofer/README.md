# 🕵️‍♂️ PySpoof - Python ARP Spoofer & MitM Tool

**PySpoof**, yerel ağ güvenliğini test etmek ve ARP (Address Resolution Protocol) zafiyetlerini simüle etmek için geliştirilmiş bir **Man-in-the-Middle (MitM)** aracıdır.

Bu proje, bir saldırganın ağ trafiğini nasıl manipüle edebileceğini anlamak ve buna karşı savunma mekanizmaları geliştirmek amacıyla yazılmıştır.

## 🚀 Özellikler

- **Çift Yönlü Zehirleme:** Hedef cihaz ve Gateway arasındaki trafiği saldırgan makine üzerine yönlendirir.
- **Ethernet Frame Injection:** Scapy kullanarak Layer 2 seviyesinde özelleştirilmiş paket gönderimi yapar.
- **Arayüz Seçimi:** `-i` parametresi ile Wi-Fi veya Ethernet kartı üzerinden saldırı simülasyonu yapılabilir.
- **Fail-Safe (Güvenli Çıkış):** İşlem durdurulduğunda ARP tablolarını otomatik olarak onarır (Re-ARPing), böylece ağ bağlantısı kopmaz.

## 🛠️ Teknik Detaylar

- **Protokol Manipülasyonu:** ARP Request/Reply döngüsü manipüle edilerek hedef cihazın ARP önbelleği (Cache) zehirlenir.
- **Linux IP Forwarding:** Linux çekirdeğinin paket yönlendirme özelliği kullanılarak trafik akışı sağlanır.
- **Scapy Framework:** Paket oluşturma ve gönderme işlemleri için Scapy kütüphanesi kullanılmıştır.

## 💻 Kurulum ve Kullanım

```bash
# Gerekli kütüphaneleri kurun
pip install -r requirements.txt

# Linux IP Yönlendirmeyi Açın (Test ortamında)
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Aracı Çalıştırın (Root yetkisi gerekir)
# -t: Hedef IP
# -g: Gateway IP
# -i: Arayüz (wlan0/eth0)
sudo python main.py -t 192.168.1.15 -g 192.168.1.1 -i wlan0
```

## ⚠️ Yasal Uyarı (Disclaimer)
Bu yazılım **sadece** geliştiricinin kendi laboratuvar ortamında veya izinli Penetrasyon Testlerinde (Pentest) kullanılmak üzere eğitim amaçlı geliştirilmiştir. Kamu ağlarında veya izinsiz şahıslar üzerinde kullanılması kesinlikle yasaktır ve suç teşkil eder.

---
*Developed for Ethical Hacking & Network Security Research.*
