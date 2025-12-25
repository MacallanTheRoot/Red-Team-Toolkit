# 🦈 PySniffer - Düşük Seviye Ağ Trafiği Analizcisi

**PySniffer**, Python'un `Raw Sockets` (Ham Soketler) yeteneğini kullanarak OSI modelinin 2, 3 ve 4. katmanlarındaki ağ trafiğini dinleyen, analiz eden ve çözümleyen (sniffing) bir siber güvenlik aracıdır.

Herhangi bir harici kütüphane (Scapy vb.) kullanılmadan, tamamen **Native Python** ile geliştirilmiştir. Bu sayede TCP/IP yığını ve Binary veri işleme (struct unpacking) konusundaki derinlemesine anlayışı temsil eder.

## 🚀 Özellikler

- **Layer 2 (Data Link):** Ethernet Çerçevelerini (Frame) yakalar ve MAC adreslerini ayrıştırır.
- **Layer 3 (Network):** IP Başlıklarını (Header) bit seviyesinde (Bitwise Operations) analiz eder, kaynak ve hedef IP'leri süzer.
- **Layer 4 (Transport):** TCP Segmentlerini inceler, Port numaralarını ve TCP Bayraklarını (SYN, ACK, PSH vb.) detaylandırır.
- **Application Layer Decoding:** Yakalanan paketlerin içerisindeki (Payload) okunabilir metin verilerini (HTTP, JSON vb.) UTF-8/ASCII formatında decode eder.

## 🛠️ Teknik Detaylar

Bu proje geliştirilirken aşağıdaki teknik konseptler uygulanmıştır:
- **Socket Programming:** `AF_PACKET` ve `SOCK_RAW` kullanılarak Kernel seviyesinde paket yakalama.
- **Binary Data Manipulation:** `struct` kütüphanesi ile "Big Endian" formatındaki ağ verisinin parse edilmesi.
- **Bitwise Operations:** IP Header uzunluğu ve TCP Flag'lerinin bit kaydırma işlemleriyle hesaplanması.

## 💻 Kurulum ve Kullanım

Bu araç standart Python kütüphanelerini kullandığı için ekstra kuruluma ihtiyaç duymaz. Ancak ağ kartını dinlemek için **Root (Yönetici)** yetkisi gerekir.

```bash
# Projeyi Klonlayın
git clone https://github.com/KULLANICI_ADIN/PySniffer.git
cd PySniffer

# Çalıştırın (Sudo yetkisi ile)
sudo python main.py
```

## ⚠️ Yasal Uyarı
Bu yazılım sadece eğitim amaçlı ve izinli ağlarda test yapmak (Network Debugging) için geliştirilmiştir. İzinsiz ağ dinleme (Wiretapping) suç teşkil edebilir. Geliştirici, aracın kötüye kullanımından sorumlu değildir.

---
*Developed with ❤️ and Python.*
