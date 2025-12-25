import os
from datetime import datetime

def html_rapor_olustur(hedef, ip_bilgileri, tarama_sonuclari):
    """
    Tarama sonuçlarını HTML formatında raporlar.
    """
    tarih = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dosya_adi = f"rapor_{hedef}.html"
    
    html_icerik = f"""
    <html>
    <head>
        <title>Güvenlik Tarama Raporu - {hedef}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
            h1 {{ color: #2c3e50; }}
            .box {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ padding: 12px; border-bottom: 1px solid #ddd; text-align: left; }}
            th {{ background-color: #2980b9; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
            .danger {{ color: red; font-weight: bold; }}
            .footer {{ margin-top: 20px; font-size: 12px; color: #777; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Otomatize Güvenlik Tarama Raporu</h1>
        <div class="box">
            <h3>Hedef Bilgileri</h3>
            <p><strong>Hedef Domain:</strong> {hedef}</p>
            <p><strong>Tarama Tarihi:</strong> {tarih}</p>
        </div>

        <div class="box">
            <h3>🌍 Keşif ve İstihbarat Sonuçları</h3>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>IP Adresi</th>
                    <th>Konum / ISP</th>
                </tr>
                {ip_bilgileri}
            </table>
        </div>

        <div class="box">
            <h3>🔓 Port Tarama Sonuçları</h3>
            <table>
                <tr>
                    <th>IP Adresi</th>
                    <th>Port</th>
                    <th>Durum</th>
                    <th>Banner / Servis</th>
                </tr>
                {tarama_sonuclari}
            </table>
        </div>

        <div class="footer">
            Bu rapor Python ile geliştirilen Otomatize Siber Güvenlik Aracı tarafından oluşturulmuştur.
        </div>
    </body>
    </html>
    """
    
    with open(dosya_adi, "w", encoding="utf-8") as f:
        f.write(html_icerik)
    
    print(f"\n[+] Rapor başarıyla oluşturuldu: {os.path.abspath(dosya_adi)}")
