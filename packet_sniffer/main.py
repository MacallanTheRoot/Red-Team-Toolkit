import socket
import struct
import textwrap

def main():
    # 1. Ham Soket (Raw Socket) - Tüm arayüzleri dinler
    # socket.ntohs(0x0003) -> Tüm protokolleri yakala demektir.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print("[*] Packet Sniffer Başlatıldı... (Tüm Trafik Dinleniyor)")
    print("[*] Çıkış için Ctrl+C basın.")

    while True:
        try:
            # Veriyi yakala
            raw_data, addr = conn.recvfrom(65535)
            
            # addr[0] genellikle paketin hangi arayüzden (eth0, wlan0) geldiğini söyler
            interface_name = addr[0] 

            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            # Sadece IPv4 (8)
            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                
                # Sadece TCP (6)
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    
                    # Ekrana Bas
                    print("-" * 60)
                    print(f"[{interface_name}] Ethernet: {src_mac} -> {dest_mac}")
                    print(f"      IP:       {src} -> {target} | Protokol: TCP")
                    print(f"      Port:     {src_port} -> {dest_port}")
                    print(f"      Bayraklar: URG:{flag_urg}, ACK:{flag_ack}, PSH:{flag_psh}, RST:{flag_rst}, SYN:{flag_syn}, FIN:{flag_fin}")
                    
                    # --- GÖRSELLEŞTİRME (Payload Decode) ---
                    if len(data) > 0:
                        try:
                            # UTF-8 decode et, bozuk karakterleri yoksay
                            decoded = data.decode('utf-8', errors='ignore')
                            
                            # Terminali bozmamak için sadece yazılabilir karakterleri al
                            clean_text = ''.join([c if c.isprintable() else '.' for c in decoded])
                            
                            # Eğer anlamlı bir metin varsa yazdır
                            if len(clean_text) > 1 and any(c.isalnum() for c in clean_text):
                                print(f'\t[Payload] > {clean_text}')
                        except:
                            pass
                    # ---------------------------------------

        except KeyboardInterrupt:
            print("\n[*] Program durduruldu.")
            break
        except Exception:
            pass # Hataları sessizce geç

# --- YARDIMCI FONKSİYONLAR ---

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

if __name__ == "__main__":
    main()
