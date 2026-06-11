import os
import hashlib
import shutil
import requests
import time
import json
import base64
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# --- API ANAHTARI VE AYARLAR ---
VT_API_KEY = "77fb2b0529c6c8330521e3a1d81cb8300194baf0c5c1a61cd90492e732ff52f3"
QUARANTINE_DIR = os.path.join(os.getcwd(), "karantina")
DB_FILE = os.path.join(QUARANTINE_DIR, "karantina_kayitlari.json")

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# Karantina geçmişini tutan basit JSON veri tabanı fonksiyonları
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
    """PDF içinde gizlenmiş otomatik tetiklenen script veya tehlikeli etiketleri arar"""
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

# --- GELİŞMİŞ ARAYÜZ (Yeni Karantina Paneli Dahil) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Hibrit Pro Antivirüs</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 40px; color: #333; }
        .container { max-width: 1000px; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 0 15px rgba(0,0,0,0.05); margin-bottom: 30px; }
        input[type="text"] { width: 70%; padding: 12px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 12px 24px; font-size: 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: bold;}
        button:hover { background-color: #0056b3; }
        .btn-delete { background-color: #dc3545; font-size: 12px; padding: 6px 12px; margin-left: 10px; color: white; border: none; border-radius:3px; cursor:pointer;}
        .btn-quarantine { background-color: #ffc107; color: black; font-size: 12px; padding: 6px 12px; margin-left: 5px; border: none; border-radius:3px; cursor:pointer; font-weight: bold;}
        .btn-vt { background-color: #6f42c1; color: white; font-size: 12px; padding: 6px 12px; margin-left: 5px; border: none; border-radius:3px; cursor:pointer;}
        .btn-restore { background-color: #28a745; color: white; font-size: 12px; padding: 6px 12px; border: none; border-radius:3px; cursor:pointer; font-weight: bold;}
        #results { margin-top: 20px; max-height: 400px; overflow-y: auto; border-top: 2px solid #eee; padding-top: 10px; }
        .clean { color: #155724; background: #d4edda; margin: 5px 0; padding: 10px; border-radius:4px; font-size: 14px; display: flex; justify-content: space-between; align-items: center; }
        .danger { color: #721c24; background: #f8d7da; font-weight: bold; margin: 5px 0; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        .warning { color: #856404; background: #fff3cd; font-weight: bold; margin: 5px 0; padding: 10px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
        
        /* Karantina Bölümü Stilleri */
        .quarantine-section { max-width: 1000px; background: #e9ecef; padding: 25px; border-radius: 8px; border: 1px solid #ced4da; }
        .quarantine-item { background: white; padding: 12px; margin: 8px 0; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; border-left: 5px solid #ffc107; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Hibrit Antivirüs Motoru (Pro Sürüm)</h1>
        <p>Klasör yolunu girin. Sistem imza taraması yaparken, <b>PDF dosyalarını gömülü script/makro risklerine karşı</b> derinlemesine inceler:</p>
        
        <input type="text" id="folderPath" placeholder="Örn: C:\\Users\\Asus\\Downloads">
        <button onclick="startScan()">⚡ Derinlemesine Tara</button>

        <h3 id="status"></h3>
        <div id="results"></div>
    </div>

    <div class="quarantine-section">
        <h2>☣️ Karantina Yönetim Merkezi</h2>
        <p>Karantinaya taşınan tehditleri buradan yönetebilir, güvenli olduğunu bildiğiniz dosyaları eski yerlerine iade edebilirsiniz.</p>
        <button onclick="loadQuarantineList()" style="background-color: #6c757d; padding: 8px 16px; font-size: 14px; margin-bottom: 15px;">🔄 Listeyi Yenile</button>
        <div id="quarantineList"><p style="color: #6c757d;">Yükleniyor veya karantina boş...</p></div>
    </div>

    <script>
        // Sayfa ilk açıldığında karantina listesini yükle
        window.onload = function() {
            loadQuarantineList();
        };

        async function startScan() {
            const path = document.getElementById('folderPath').value;
            const statusText = document.getElementById('status');
            const resultsDiv = document.getElementById('results');
            
            if (!path) { alert("Lütfen bir klasör yolu girin!"); return; }
            statusText.innerText = "⚡ Klasör derinlemesine analiz ediliyor, lütfen bekleyin...";
            resultsDiv.innerHTML = "";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                
                if (!response.ok) {
                    statusText.innerText = "❌ Sunucu yanıt vermedi veya klasör okunamadı.";
                    return;
                }

                const data = await response.json();
                statusText.innerText = `✅ Tarama ${data.duration} saniyede bitti! Toplam ${data.total_scanned} dosya incelendi.`;
                
                data.results.forEach((item, index) => {
                    const p = document.createElement('p');
                    const encodedPath = btoa(unescape(encodeURIComponent(item.file)));
                    
                    if (item.status === 'INFECTED') {
                        p.className = 'danger';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>🚨 [TEHLİKE] ${item.file} -> VİRÜS: ${item.malware}</span>
                            <div>
                                <button class="btn-quarantine" onclick="actionFile('quarantine', '${encodedPath}', 'row-${index}')">Karantina</button>
                                <button class="btn-delete" onclick="actionFile('delete', '${encodedPath}', 'row-${index}')">Sil</button>
                            </div>
                        `;
                    } else if (item.status === 'SUSPICIOUS') {
                        p.className = 'warning';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>⚠️ [ŞÜPHELİ SCRIPT] ${item.file} -> Tetikleyiciler: ${item.details}</span>
                            <div>
                                <button class="btn-quarantine" onclick="actionFile('quarantine', '${encodedPath}', 'row-${index}')">Karantina</button>
                                <button class="btn-delete" onclick="actionFile('delete', '${encodedPath}', 'row-${index}')">Sil</button>
                            </div>
                        `;
                    } else {
                        p.className = 'clean';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>✔️ [TEMİZ] ${item.file}</span>
                            <button class="btn-vt" onclick="checkVT('${item.hash}', 'row-${index}')">Bulutta Sorgula (VirusTotal)</button>
                        `;
                    }
                    resultsDiv.appendChild(p);
                });
            } catch (error) { 
                statusText.innerText = "❌ Zaman aşımı veya sunucu bağlantı hatası."; 
            }
        }

        async function checkVT(fileHash, rowId) {
            const row = document.getElementById(rowId);
            row.style.opacity = "0.5";
            try {
                const response = await fetch('/check_vt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ hash: fileHash })
                });
                const data = await response.json();
                row.style.opacity = "1";

                if (data.status === 'INFECTED') {
                    row.className = 'danger';
                    row.innerHTML = `<span>🚨 [BULUTTA YAKALANDI] -> VİRÜS: ${data.malware}</span>`;
                } else {
                    alert("✨ Temiz! Devasa VirusTotal veri tabanında da bu dosya güvenli çıktı.");
                }
            } catch (e) {
                row.style.opacity = "1";
                alert("VirusTotal sorgusu esnasında bir hata oluştu.");
            }
        }

        async function actionFile(action, encodedPath, rowId) {
            try {
                const response = await fetch('/action', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action, path: encodedPath })
                });
                const data = await response.json();
                alert(data.message);
                if(data.success) {
                    document.getElementById(rowId).style.backgroundColor = "#e2e3e5";
                    document.getElementById(rowId).style.color = "#383d41";
                    document.getElementById(rowId).innerHTML = `✅ İşlem tamamlandı.`;
                    loadQuarantineList(); // Karantina listesini canlı güncelle
                }
            } catch(e) {
                alert("İşlem gerçekleştirilemedi.");
            }
        }

        // Karantina listesini arka plandan çeker ve ekrana basar
        async function loadQuarantineList() {
            const qListDiv = document.getElementById('quarantineList');
            try {
                const response = await fetch('/quarantine_list');
                const data = await response.json();
                
                if (data.length === 0) {
                    qListDiv.innerHTML = "<p style='color: #6c757d;'>Karantina bölgesi şu an tertemiz. Tehdit bulunmuyor.</p>";
                    return;
                }
                
                qListDiv.innerHTML = "";
                data.forEach(item => {
                    const div = document.createElement('div');
                    div.className = 'quarantine-item';
                    div.innerHTML = `
                        <div>
                            <strong>📄 Dosya Adı:</strong> ${item.filename}<br>
                            <small style="color: #6c757d;">Orijinal Konum: ${item.orig_path}</small>
                        </div>
                        <div>
                            <button class="btn-restore" onclick="manageQuarantine('restore', '${item.id}')">Geri Yükle</button>
                            <button class="btn-delete" onclick="manageQuarantine('permanent_delete', '${item.id}')">Kalıcı Sil</button>
                        </div>
                    `;
                    qListDiv.appendChild(div);
                });
            } catch(e) {
                qListDiv.innerHTML = "<p style='color: red;'>Karantina listesi yüklenirken hata oluştu.</p>";
            }
        }

        async function manageQuarantine(action, fileId) {
            try {
                const response = await fetch('/manage_quarantine', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: action, id: fileId })
                });
                const data = await response.json();
                alert(data.message);
                loadQuarantineList();
            } catch(e) {
                alert("Karantina işlemi başarısız.");
            }
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

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
                
                # Karantina klasörünün kendisini taratmayalım
                if QUARANTINE_DIR in file_path:
                    continue
                    
                file_hash = calculate_sha256(file_path)
                if file_hash is None:
                    continue

                # 1. Kural: Yerel Zararlı İmzası Kontrolü
                if file_hash in LOCAL_SIGNATURES:
                    scan_results.append({
                        "file": file_path, "status": "INFECTED", 
                        "malware": LOCAL_SIGNATURES[file_hash], "hash": file_hash
                    })
                # 2. Kural: PDF İçerik ve Makro Analizi
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
            
            # Orijinal konumu veri tabanına kaydet
            db = load_quarantine_db()
            db[file_id] = {
                "id": file_id,
                "filename": file_name,
                "orig_path": file_path,
                "quarantine_path": dest_path
            }
            save_quarantine_db(db)
            
            # Dosyayı taşı
            shutil.move(file_path, dest_path)
            return jsonify({"success": True, "message": "Dosya karantinaya güvenle taşındı!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata: {str(e)}"})

# --- KARANTİNA YÖNETİM API UÇLARI ---

@app.route('/quarantine_list', methods=['GET'])
def quarantine_list():
    db = load_quarantine_db()
    # Sadece fiziksel olarak gerçekten karantinada duran dosyaları listele
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
                # Orijinal klasör silindiyse geri yüklemek için yeniden oluştur
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
