# 🛡️ Red Team Toolkit & Adversary Emulation Portfolio

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Red%20Team-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

## 📌 Proje Hakkında
Bu depo, **İleri Seviye Siber Güvenlik Operasyonları**, **Zararlı Yazılım Analizi** ve **Ağ Güvenliği** üzerine geliştirdiğim araçların ve simülasyonların bir koleksiyonudur.

Buradaki projeler, basit scriptler olmanın ötesinde; **Komuta Kontrol (C2) mimarileri**, **Kriptografik süreçler**, **Otomasyon** ve **Ağ protokolleri** üzerine derinlemesine teknik yetkinlikleri sergilemek amacıyla tasarlanmıştır.

---

## 📂 Projeler ve Modüller

### 1. 🦠 Adversary Emulation Lab (PyRansom Framework)
Modern fidye yazılımı (Ransomware) operasyonlarını ve C2 altyapılarını simüle eden kapsamlı bir framework.
* **📂 Konum:** `/Adversary-Emulation-Lab`
* **Özellikler:**
    * **Multi-Protocol C2:** HTTP (Flask API) ve SMTP (Serverless Email) desteği.
    * **Weaponization:** Python scriptlerini otomatik olarak `.EXE` formatına derleyen Builder GUI.
    * **Advanced Tactics:** Persistence (Registry Run Key), Data Exfiltration (Double Extortion) ve Hibrit Şifreleme (RSA-2048 + AES-128).
    * **Defense Evasion:** Anti-Forensic teknikleri ve `AppData` gizlenmesi.

### 2. 🤖 AutoSec (Automated Reconnaissance)
Sızma testlerinin bilgi toplama (Recon) aşamasını otomatize eden modüler araç.
* **📂 Konum:** `/AutoSec`
* **Özellikler:**
    * **Modüler Yapı:** Scan, Intel, Recon ve Reporting modülleri.
    * **Nmap Entegrasyonu:** Port taramalarını otomatikleştirir ve analiz eder.
    * **Raporlama:** Tarama sonuçlarını yönetici özetine dönüştüren HTML raporlama motoru.

### 3. 📡 Network Attack Tools
Düşük seviyeli ağ manipülasyonu ve trafik analizi araçları.
* **📂 Konum:** `/arp_spoofer` & `/packet_sniffer`
* **Özellikler:**
    * **ARP Spoofing:** Yerel ağda Man-in-the-Middle (MITM) saldırısı gerçekleştirerek trafiği yönlendirir.
    * **Packet Sniffing:** Scapy kütüphanesi ile HTTP trafiğindeki hassas verileri (URL, Login bilgileri) yakalar ve analiz eder.

---

## 🛠️ Teknik Yetkinlikler (Tech Stack)

Bu projelerin geliştirilmesinde aşağıdaki teknolojiler ve kütüphaneler kullanılmıştır:

| Kategori | Teknolojiler |
|----------|--------------|
| **Diller** | Python 3, Bash |
| **Kriptografi** | `cryptography` (Fernet/AES, RSA, PKCS8), Hashing |
| **Networking** | `scapy`, `socket`, `requests`, `smtplib`, TCP/IP, ARP, DNS |
| **Frameworks** | `Flask` (REST API), `Tkinter` (GUI Development) |
| **Sistem** | `winreg` (Windows API), `threading`, `multiprocessing`, Linux/Kali |
| **Build Tools** | `PyInstaller`, `Git` |

---

## ⚠️ Yasal Uyarı (Disclaimer)

> **Bu depo sadece EĞİTİM, ARAŞTIRMA ve YETKİLENDİRİLMİŞ GÜVENLİK TESTLERİ (Red Teaming) amacıyla oluşturulmuştur.**

Burada bulunan araçların izinsiz sistemlerde kullanılması, veri şifrelenmesi veya ağ trafiğinin dinlenmesi suç teşkil eder. Geliştirici (**MacallanTheRoot**), bu yazılımların kötüye kullanımından doğacak yasal ve maddi sonuçlardan sorumlu değildir.

Bu projeler, savunma ekiplerinin (Blue Team) saldırı vektörlerini anlaması ve tespit mekanizmaları geliştirmesi için bir kaynak niteliğindedir.

---

### 📬 İletişim & Profil
**Developer:** MacallanTheRoot
*Siber Güvenlik Araştırmacısı & Yazılım Geliştirici*
