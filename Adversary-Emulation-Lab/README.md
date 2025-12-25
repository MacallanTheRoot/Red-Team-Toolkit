# 🛡️ PyRansom: Master Edition (Adversary Emulation Framework)

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Security](https://img.shields.io/badge/Security-Red%20Team-red)
![License](https://img.shields.io/badge/License-Educational-green)

**PyRansom Master Edition**, modern fidye yazılımı (ransomware) operasyonlarını, Komuta & Kontrol (C2) mimarilerini ve veri sızdırma tekniklerini simüle etmek için geliştirilmiş kapsamlı bir **Siber Güvenlik Araştırma ve Eğitim Aracıdır**.

Bu proje, tekil zararlı yazılımlar yerine, saldırganların kullandığı **"Ransomware-as-a-Service (RaaS)"** ekosistemini (Panel, Builder, Payload, Decryptor) uçtan uca simüle eder.

---

## 🏗️ Mimari ve İş Akışı

PyRansom, esnek bir C2 mimarisi üzerine kuruludur ve saldırı vektörünü duruma göre değiştirebilir.



### 1. Multi-Protocol C2 (Komuta Kontrol)
Sistem iki farklı iletişim protokolünü destekler:
* **HTTP Mode (Flask Server):** Zararlı yazılım, merkezi bir REST API sunucusu ile haberleşir. Kurban kaydı ve dosya transferi HTTP POST istekleri üzerinden yapılır.
* **SMTP Mode (Serverless):** "Sunucusuz" mimari. Zararlı yazılım, çaldığı verileri ve şifreleme anahtarlarını doğrudan saldırganın E-Mail adresine (Gmail/SMTP) gönderir. Bu yöntem, web filtrelerini atlatmak (evasion) için kullanılır.



### 2. Hybrid Encryption (Hibrit Şifreleme)
Veri güvenliği ve kurtarılabilirliği için endüstri standardı kriptografi kullanır:
* **Simetrik (AES-128):** Dosyalar hızlı şifreleme için Fernet (AES-CBC) ile kilitlenir.
* **Asimetrik (RSA-2048):** AES anahtarı, saldırganın Public Key'i ile şifrelenerek saklanır.
* **Sonuç:** Dosyalar, sadece saldırganın elindeki Private Key ile açılabilir.

---

## 🚀 Temel Özellikler

### 🛠️ Weaponization (Silahlandırma)
* **Dynamic Builder GUI:** Kullanıcı dostu arayüz ile payload ayarları (IP, Port, Hedef) dinamik olarak yapılandırılır.
* **Binary Compilation:** Python scriptleri, `PyInstaller` motoru ile otomatik olarak taşınabilir **.EXE** dosyasına dönüştürülür.
* **Target Scoping:**
    * *Custom Scope:* Belirli bir klasörü hedefler.
    * *Full Profile:* Kurbanın tüm ana dizinini (`/home/user` veya `C:\Users\User`) hedefler.

### 🕵️‍♂️ Advanced Adversary Tactics
* **Double Extortion (Çifte Şantaj):** Dosyalar şifrelenmeden önce kritik veriler (.pdf, .docx, .txt) C2 sunucusuna veya E-Posta adresine sızdırılır.
* **Persistence (Kalıcılık):** Windows Registry (`HKCU\...\Run`) manipülasyonu ile sistem yeniden başlatılsa bile zararlı yazılım çalışmaya devam eder.
* **Stealth Execution:** Arka planda sessizce çalışır ve kendini `AppData` dizinine kopyalayarak gizler.

---

## 💻 Kurulum ve Kullanım

### Gereksinimler
```bash
pip install -r requirements.txt
