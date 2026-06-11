import os
import hashlib
import shutil
import requests
import time
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Karantina klasörü ayarı
QUARANTINE_DIR = os.path.join(os.getcwd(), "karantina")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# --- VIRUSTOTAL SORGULAMA MOTORU ---
def check_virus_total(file_hash, api_key):
    """Dosya özetini VirusTotal API'sine sorar."""
    if not api_key or api_key == "BURAYA_VIRUSTOTAL_API_ANAHTARINI_YAZ":
        # API Anahtarı girilmediyse eski test modunda çalışır
        if file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
            return "INFECTED", "Test_Malware_EmptyFile (API Yok)"
        return "CLEAN", None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            # Antivirüs şirketlerinin kaç tanesi buna 'zararlı' demiş?
            stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            
            if malicious_count > 0:
                # En popüler zararlı adını çekelim
                meaning = result.get("data", {}).get("attributes", {}).get("popular_threat_classification", {})
                malware_name = meaning.get("suggested_threat_label", f"Zararlı Yazılım ({malicious_count} Antivirüs Yakaladı)")
                return "INFECTED", malware_name
                
        elif response.status_code == 404:
            # VirusTotal bu dosyayı hiç görmemiş, yani bilinen bir virüs değil
            return "CLEAN", None
    except Exception:
        pass
    
    return "CLEAN", None

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
    <title>🛡️ VirusTotal Güçlü Antivirüs</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 40px; }
        .container { max-width: 950px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        input[type="text"] { width: 75%; padding: 10px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #218838; }
        .btn-delete { background-color: #dc3545; font-size: 12px; padding: 5px 10px; margin-left: 10px; color: white; border: none; border-radius:3px; cursor:pointer;}
        .btn-quarantine { background-color: #ffc107; color: black; font-size: 12px; padding: 5px 10px; margin-left: 5px; border: none; border-radius:3px; cursor:pointer;}
        #results { margin-top: 20px; max-height: 500px; overflow-y: auto; border-top: 2px solid #eee; padding-top: 10px; }
        .clean { color: #155724; background: #d4edda; margin: 5px 0; padding: 6px; border-radius:4px; font-size: 14px; }
        .danger { color: #721c24; background: #f8d7da; font-weight: bold; margin: 5px 0; padding: 8px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Bulut Tabanlı Gerçek Antivirüs Motoru (VirusTotal)</h1>
        <p>Bilgisayarınızda taratmak istediğiniz klasörün tam yolunu girin. Dosyalarınız küresel veri tabanında taranacaktır:</p>
        
        <input type="text" id="folderPath" placeholder="Örn: C:\\Users\\Asus\\Downloads">
        <button onclick="startScan()">Bulut Taramasını Başlat</button>

        <h3 id="status"></h3>
        <div id="results"></div>
    </div>

    <script>
        async function startScan() {
            const path = document.getElementById('folderPath').value;
            const statusText = document.getElementById('status');
            const resultsDiv = document.getElementById('results');
            
            if (!path) { alert("Lütfen bir klasör yolu girin!"); return; }
            statusText.innerText = "⏳ VirusTotal üzerinden küresel tarama yapılıyor (Dosya sayısına göre biraz sürebilir)...";
            resultsDiv.innerHTML = "";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                const data = await response.json();
                statusText.innerText = `✅ Tarama Bitti! ${data.total_scanned} dosya küresel veri tabanında sorgulandı.`;
                
                data.results.forEach((item, index) => {
                    const p = document.createElement('p');
                    if (item.status === 'INFECTED') {
                        p.className = 'danger';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>🚨 [TEHLİKE] ${item.file} -> VİRÜS TİPİ: ${item.malware}</span>
                            <div>
                                <button class="btn-quarantine" onclick="actionFile('quarantine', '${btoa(item.file)}', 'row-${index}')">Karantina</button>
                                <button class="btn-delete" onclick="actionFile('delete', '${btoa(item.file)}', 'row-${index}')">Sil</button>
                            </div>
                        `;
                    } else {
                        p.className = 'clean';
                        p.innerText = `✔️ [TEMİZ] ${item.file}`;
                    }
                    resultsDiv.appendChild(p);
                });
            } catch (error) { statusText.innerText = "❌ Tarama sırasında bir internet veya sistem hatası oluştu."; }
        }

        async function actionFile(action, encodedPath, rowId) {
            const filePath = atob(encodedPath);
            if(!confirm(`${filePath} dosyası silinsin mi/karantinaya alınsın mı?`)) return;

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
                document.getElementById(rowId).innerHTML = `✅ Bu tehlike giderildi (${action === 'delete' ? 'Silindi' : 'Karantinaya Alındı'}).`;
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
    data = request.get_json()
    target_dir = data.get('path', '')
    scan_results = []
    
    if not os.path.exists(target_dir):
        return jsonify({"results": [], "total_scanned": 0})

    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            if QUARANTINE_DIR in file_path:
                continue
                
            file_hash = calculate_sha256(file_path)
            if file_hash is None:
                continue

            # Burada VirusTotal'e soruyoruz
            status, malware_name = check_virus_total(file_hash, VT_API_KEY)
            
            if status == "INFECTED":
                scan_results.append({"file": file_path, "status": "INFECTED", "malware": malware_name})
            else:
                scan_results.append({"file": file_path, "status": "CLEAN"})
            
            # Ücretsiz API saniyede en fazla 4 istek kabul ettiği için küçük bir bekleme koyuyoruz
            time.sleep(0.25)
            
    return jsonify({"results": scan_results, "total_scanned": len(scan_results)})

@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    action_type = data.get('action')
    file_path = data.get('path')

    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "Dosya zaten yerinde yok."})

    try:
        if action_type == 'delete':
            os.remove(file_path)
            return jsonify({"success": True, "message": "Dosya tamamen imha edildi!"})
        elif action_type == 'quarantine':
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, file_name)
            if os.path.exists(dest_path):
                dest_path = dest_path + "_yedek"
            shutil.move(file_path, dest_path)
            return jsonify({"success": True, "message": "Dosya karantina klasörüne hapsedildi!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Hata: {str(e)}"})

# --- BURAYA KENDİ API ANAHTARINI YAPIŞTIR ---
VT_API_KEY = "77fb2b0529c6c8330521e3a1d81cb8300194baf0c5c1a61cd90492e732ff52f3"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
