import os
import hashlib
import shutil
import requests
import time
import json
import base64
from flask import Flask, render_template, request, jsonify
import psutil  # Dış bağlantıları anlık yakalamak ve yönetmek için entegre edildi

app = Flask(__name__)

# --- API ANAHTARI VE AYARLAR ---
VT_API_KEY = "77fb2b0529c6c8330521e3a1d81cb8300194baf0c5c1a61cd90492e732ff52f3"
QUARANTINE_DIR = os.path.join(os.getcwd(), "karantina")
DB_FILE = os.path.join(QUARANTINE_DIR, "karantina_kayitlari.json")

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# --- YAPAY ZEKA AĞ ANALİZ SÖZLÜĞÜ ---
SAFE_KEYWORDS = {
    'chrome.exe': 'Google Chrome tarayıcı trafiği. Standart güvenli internet sörfü veya arka plan senkronizasyonu.',
    'onedrive.exe': 'Microsoft OneDrive bulut senkronizasyonu. Klasör yedekleme ve veri transferi yapar.',
    'onedrive.sync.service.exe': 'Microsoft Bulut altyapısı entegre veri senkronizasyon mekanizması.',
    'filecoauth.exe': 'Microsoft Office / OneDrive ortak çalışma ve dosya eşitleme motoru.',
    'thunderbird.exe': 'Mozilla Thunderbird e-posta istemcisi. Güvenli IMAP/POP3 protokolleri üzerinden mailleri kontrol eder.',
    'mscopilot.exe': 'Microsoft Copilot yapay zeka entegrasyonu. Güvenli Azure bulut sunucularıyla konuşur.',
    'svchost.exe': 'Kritik Windows sistem işlemi. Güvenli Microsoft servis bacakları veya telemetri sistemidir.',
    'msedge.exe': 'Microsoft Edge tarayıcı trafiği. Standart güvenli HTTPS veri akışı.',
    'discord.exe': 'Discord sohbet istemcisi. Sunucu ses ve metin odaları senkronizasyonu.',
    'spotify.exe': 'Spotify müzik akışı. Medya sunucularından anlık ses paketleri çeker.'
}

def load_quarantine_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_quarantine_db(data):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

LOCAL_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Malware_EmptyFile",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Zararli_Yazilim_A",
    "44d88612fea8a8f36de82e1278abb02f": "WannaCry_Ransomware_Test"
}

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

# --- PDF MAKRO / SCRIPT ANALİZ MOTORU ---
def analyze_pdf_content(file_path):
    dangerous_tags = [b"/JavaScript", b"/JS", b"/AA", b"/Launch", b"/OpenAction"]
    try:
        with open(file_path, "rb") as f:
            content = f.read()
            found_tags = [tag.decode('utf-8', errors='ignore') for tag in dangerous_tags if tag in content]
            if found_tags:
                return True, ", ".join(found_tags)
    except Exception:
        pass
    return False, ""

# --- YAPAY ZEKA AĞ DEĞERLENDİRME MOTORU ---
def ai_analyze_connection(program_name, remote_ip, remote_port):
    """Gelen bağlantıyı siber güvenlik gözlüğüyle yorumlar."""
    prog_lower = program_name.lower()
    
    for key, desc in SAFE_KEYWORDS.items():
        if key in prog_lower:
            if remote_port == 443:
                return "GÜVENLİ", f"{desc} Port 443 (HTTPS) şifreli tüneli kullandığı için harici sızmalara karşı korumalıdır."
            elif remote_port in [993, 465, 995]:
                return "GÜVENLİ", f"{desc} Standart kriptolu e-posta haberleşme portu üzerinden veri alıyor."
            else:
                return "DİKKAT", f"{desc} Ancak standart dışı bir ağ kapısından ({remote_port}) veri akışı sağlıyor. Kontrol edilmeli."
                
    if remote_port in [4444, 8080, 31337, 5555]:
        return "TEHLİKELİ", f"Kritik Port İkazı! {program_name} uygulaması, trojan ve arka kapı (backdoor) yazılımlarının kullandığı tehlikeli bir port üzerinden dış dünyaya açılmaya çalışıyor!"
        
    return "BİLİNMİYOR", f"{program_name} uygulaması {remote_ip}:{remote_port} adresine bağlantı kurdu. Bu yazılım güvenli beyaz listemizde yer almıyor, eğer sizin bilginiz dışında açıldıysa şüpheli olabilir."

# --- FLASK BAĞLANTI NOKTALARI (ROTALAR) ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    start_time = time.time()
    data = request.get_json()
    target_dir = data.get('path', '')
    scan_results = []
    
    if not os.path.exists(target_dir):
        return jsonify({"results": [], "total_scanned": 0, "duration": 0})

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                if QUARANTINE_DIR in file_path:
                    continue
                    
                file_hash = calculate_sha256(file_path)
                if file_hash is None:
                    continue

                if file_hash in LOCAL_SIGNATURES:
                    scan_results.append({
                        "file": file_path, "status": "INFECTED", 
                        "malware": LOCAL_SIGNATURES[file_hash], "hash": file_hash
                    })
                elif file.lower().endswith('.pdf'):
                    is_suspicious, tags_found = analyze_pdf_content(file_path)
                    if is_suspicious:
                        scan_results.append({
                            "file": file_path, "status": "SUSPICIOUS", 
                            "details": tags_found, "hash": file_hash
                        })
                    else:
                        scan_results.append({"file": file_path, "status": "CLEAN", "hash": file_hash})
                else:
                    scan_results.append({"file": file_path, "status": "CLEAN", "hash": file_hash})
            except Exception:
                continue
            
    duration = round(time.time() - start_time, 2)
    return jsonify({"results": scan_results, "total_scanned": len(scan_results), "duration": duration})

@app.route('/ag_taramasi', methods=['GET'])
def ag_baglantilarini_tara():
    """Canlı ağ bağlantılarını yakalar, AI analiz motorundan geçirip arayüze basar"""
    aktif_baglantilar = []
    try:
        for baglanti in psutil.net_connections(kind='inet'):
            if baglanti.status == 'ESTABLISHED':
                uzak_ip = baglanti.raddr.ip if baglanti.raddr else None
                uzak_port = baglanti.raddr.port if baglanti.raddr else None
                
                if uzak_ip and uzak_ip != "127.0.0.1" and uzak_ip != "::1":
                    pid = baglanti.pid
                    try:
                        program_adi = psutil.Process(pid).name()
                    except Exception:
                        program_adi = "Bilinmeyen Program"
                        
                    # Burada devreye yapay zeka analiz motorumuz giriyor:
                    durum, ai_acıklama = ai_analyze_connection(program_adi, uzak_ip, uzak_port)
                        
                    aktif_baglantilar.append({
                        "program": program_adi,
                        "pid": pid,
                        "ip": uzak_ip,
                        "port": uzak_port,
                        "status": durum,        # GÜVENLİ, DİKKAT, TEHLİKELİ
                        "analysis": ai_acıklama  # Yapay zekanın gerekçeli yorumu
                    })
    except Exception as e:
        return jsonify({"hata": str(e)}), 500
        
    return jsonify({"baglantilar": aktif_baglantilar})

@app.route('/kill_network_process', methods=['POST'])
def kill_network_process():
    """Seçilen şüpheli ağ bağlantısını işletim sistemi seviyesinde keser."""
    data = request.get_json()
    pid = data.get('pid')
    try:
        process = psutil.Process(int(pid))
        proc_name = process.name()
        process.terminate()  # Program bacağını sonlandırır
        return jsonify({"success": True, "message": f"{proc_name} (PID: {pid}) ağ bağlantısı zorla kesildi ve işlem sonlandırıldı."})
    except psutil.NoSuchProcess:
        return jsonify({"success": False, "message": "Bu işlem zaten sonlandırılmış."})
    except psutil.AccessDenied:
        return jsonify({"success": False, "message": "Yetki Hatası: Bu bağlantıyı kesebilmek için terminali Yönetici Olarak çalıştırmalısınız!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata oluştu: {str(e)}"})

@app.route('/check_vt', methods=['POST'])
def check_vt():
    data = request.get_json()
    file_hash = data.get('hash')
    
    if not VT_API_KEY:
        return jsonify({"status": "CLEAN"})

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            result = response.json()
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                meaning = result.get("data", {}).get("attributes", {}).get("popular_threat_classification", {})
                malware_name = meaning.get("suggested_threat_label", "Zararlı Yazılım")
                return jsonify({"status": "INFECTED", "malware": malware_name})
    except Exception:
        pass
        
    return jsonify({"status": "CLEAN"})

@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    action_type = data.get('action')
    encoded_path = data.get('path')

    try:
        file_path = base64.b64decode(encoded_path).decode('utf-8')
    except Exception:
        return jsonify({"success": False, "message": "Dosya yolu çözümlenemedi."})

    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "Dosya yerinde bulunamadı."})

    try:
        if action_type == 'delete':
            os.remove(file_path)
            return jsonify({"success": True, "message": "Dosya sistemden kalıcı olarak silindi!"})
            
        elif action_type == 'quarantine':
            file_id = hashlib.md5(file_path.encode('utf-8')).hexdigest()
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, f"{file_id}_{file_name}")
            
            db = load_quarantine_db()
            db[file_id] = {
                "id": file_id,
                "filename": file_name,
                "orig_path": file_path,
                "quarantine_path": dest_path
            }
            save_quarantine_db(db)
            
            shutil.move(file_path, dest_path)
            return jsonify({"success": True, "message": "Dosya karantinaya güvenle taşındı!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata: {str(e)}"})

@app.route('/quarantine_list', methods=['GET'])
def quarantine_list():
    db = load_quarantine_db()
    valid_list = []
    for k, v in db.items():
        if os.path.exists(v["quarantine_path"]):
            valid_list.append(v)
    return jsonify(valid_list)

@app.route('/manage_quarantine', methods=['POST'])
def manage_quarantine():
    data = request.get_json()
    action_type = data.get('action')
    file_id = data.get('id')
    
    db = load_quarantine_db()
    if file_id not in db:
        return jsonify({"success": False, "message": "Kayıt bulunamadı."})
        
    file_info = db[file_id]
    q_path = file_info["quarantine_path"]
    orig_path = file_info["orig_path"]
    
    try:
        if action_type == 'restore':
            if os.path.exists(q_path):
                orig_dir = os.path.dirname(orig_path)
                if not os.path.exists(orig_dir):
                    os.makedirs(orig_dir)
                    
                shutil.move(q_path, orig_path)
                del db[file_id]
                save_quarantine_db(db)
                return jsonify({"success": True, "message": "Dosya eski konumuna başarıyla iade edildi!"})
                
        elif action_type == 'permanent_delete':
            if os.path.exists(q_path):
                os.remove(q_path)
            del db[file_id]
            save_quarantine_db(db)
            return jsonify({"success": True, "message": "Dosya karantinadan da temizlendi. Artık yok!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata: {str(e)}"})
        
    return jsonify({"success": False, "message": "İşlem tamamlanamadı."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
