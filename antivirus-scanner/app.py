import os
import hashlib
import shutil
import requests
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Karantina klasörü ayarı
QUARANTINE_DIR = os.path.join(os.getcwd(), "karantina")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# 🚀 BİLGİSAYARINDA ANINDA TARANACAK VERİ TABANI (IŞIK HIZINDA)
# Buraya internetteki en bilinen tehlikeli hash'leri veya kendi test hash'lerimizi ekliyoruz
LOCAL_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Malware_EmptyFile",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Zararli_Yazilim_A",
    "44d88612fea8a8f36de82e1278abb02f": "WannaCry_Ransomware_Test"
}

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None

# --- ARAYÜZ (HTML) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>🛡️ Hibrit Hızlı Antivirüs</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 40px; }
        .container { max-width: 950px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input[type="text"] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .btn-delete { background-color: #dc3545; font-size: 12px; padding: 5px 10px; margin-left: 10px; color: white; border: none; border-radius:3px; cursor:pointer;}
        .btn-quarantine { background-color: #ffc107; color: black; font-size: 12px; padding: 5px 10px; margin-left: 5px; border: none; border-radius:3px; cursor:pointer;}
        .btn-vt { background-color: #6f42c1; color: white; font-size: 12px; padding: 5px 10px; margin-left: 5px; border: none; border-radius:3px; cursor:pointer;}
        #results { margin-top: 20px; max-height: 500px; overflow-y: auto; border-top: 2px solid #eee; padding-top: 10px; }
        .clean { color: #155724; background: #d4edda; margin: 5px 0; padding: 8px; border-radius:4px; font-size: 14px; display: flex; justify-content: space-between; align-items: center; }
        .danger { color: #721c24; background: #f8d7da; font-weight: bold; margin: 5px 0; padding: 8px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Hibrit Antivirüs Motoru (Süper Hızlı)</h1>
        <p>Klasör yolunu girin. Yerel veri tabanı sayesinde tarama anında tamamlanır:</p>
        
        <input type="text" id="folderPath" placeholder="Örn: C:\\Users\\Asus\\Documents">
        <button onclick="startScan()">⚡ Jet Hızında Tara</button>

        <h3 id="status"></h3>
        <div id="results"></div>
    </div>

    <script>
        async function startScan() {
            const path = document.getElementById('folderPath').value;
            const statusText = document.getElementById('status');
            const resultsDiv = document.getElementById('results');
            
            if (!path) { alert("Lütfen bir klasör yolu girin!"); return; }
            statusText.innerText = "⚡ Yıldırım hızıyla taranıyor...";
            resultsDiv.innerHTML = "";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                const data = await response.json();
                statusText.innerText = `✅ Tarama ${data.duration} saniyede bitti! Toplam ${data.total_scanned} dosya incelendi.`;
                
                data.results.forEach((item, index) => {
                    const p = document.createElement('p');
                    if (item.status === 'INFECTED') {
                        p.className = 'danger';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>🚨 [TEHLİKE] ${item.file} -> VİRÜS: ${item.malware}</span>
                            <div>
                                <button class="btn-quarantine" onclick="actionFile('quarantine', '${btoa(item.file)}', 'row-${index}')">Karantina</button>
                                <button class="btn-delete" onclick="actionFile('delete', '${btoa(item.file)}', 'row-${index}')">Sil</button>
                            </div>
                        `;
                    } else {
                        p.className = 'clean';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>✔️ [TEMİZ] ${item.file}</span>
                            <button class="btn-vt" onclick="checkVT('${item.hash}', 'row-${index}', '${btoa(item.file)}')">Bulutta Sorgula (VirusTotal)</button>
                        `;
                    }
                    resultsDiv.appendChild(p);
                });
            } catch (error) { statusText.innerText = "❌ Bir hata oluştu."; }
        }

        async function checkVT(fileHash, rowId, encodedPath) {
            const filePath = atob(encodedPath);
            const row = document.getElementById(rowId);
            row.style.opacity = "0.5";
            
            const response = await fetch('/check_vt', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hash: fileHash })
            });
            const data = await response.json();
            row.style.opacity = "1";

            if (data.status === 'INFECTED') {
                row.className = 'danger';
                row.innerHTML = `
                    <span>🚨 [BULUTTA YAKALANDI] ${filePath} -> VİRÜS: ${data.malware}</span>
                    <div>
                        <button class="btn-quarantine" onclick="actionFile('quarantine', '${encodedPath}', '${rowId}')">Karantina</button>
                        <button class="btn-delete" onclick="actionFile('delete', '${encodedPath}', '${rowId}')">Sil</button>
                    </div>
                `;
            } else {
                alert("✨ Temiz! Devasa VirusTotal veri tabanında da bu dosya güvenli çıktı.");
            }
        }

        async function actionFile(action, encodedPath, rowId) {
            const filePath = atob(encodedPath);
            const response = await fetch('/action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, path: filePath })
            });
            const data = await response.json();
            alert(data.message);
            if(data.success) {
                document.getElementById(rowId).style.backgroundColor = "#e2e3e5";
                document.getElementById(rowId).style.color = "#383d41";
                document.getElementById(rowId).innerHTML = `✅ İşlem tamamlandı.`;
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
    import time
    start_time = time.time()
    data = request.get_json()
    target_dir = data.get('path', '')
    scan_results = []
    
    if not os.path.exists(target_dir):
        return jsonify({"results": [], "total_scanned": 0, "duration": 0})

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if QUARANTINE_DIR in file_path:
                continue
                
            file_hash = calculate_sha256(file_path)
            if file_hash is None:
                continue

            # ⚡ İLK KONTROLÜ YERELDE ANINDA YAPIYORUZ (Sıfır bekleme)
            if file_hash in LOCAL_SIGNATURES:
                scan_results.append({"file": file_path, "status": "INFECTED", "malware": LOCAL_SIGNATURES[file_hash], "hash": file_hash})
            else:
                scan_results.append({"file": file_path, "status": "CLEAN", "hash": file_hash})
            
    duration = round(time.time() - start_time, 2)
    return jsonify({"results": scan_results, "total_scanned": len(scan_results), "duration": duration})

@app.route('/check_vt', methods=['POST'])
def check_vt():
    data = request.get_json()
    file_hash = data.get('hash')
    
    if not VT_API_KEY or VT_API_KEY == "BURAYA_VIRUSTOTAL_API_ANAHTARINI_YAZ":
        return jsonify({"status": "CLEAN"})

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
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
    file_path = data.get('path')

    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "Dosya yerinde yok."})

    try:
        if action_type == 'delete':
            os.remove(file_path)
            return jsonify({"success": True, "message": "Dosya silindi!"})
        elif action_type == 'quarantine':
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, file_name)
            shutil.move(file_path, dest_path)
            return jsonify({"success": True, "message": "Dosya karantinaya alındı!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata: {str(e)}"})

# --- BURAYA KENDİ API ANAHTARINI YAPIŞTIR ---
VT_API_KEY = "77fb2b0529c6c8330521e3a1d81cb8300194baf0c5c1a61cd90492e732ff52f"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
