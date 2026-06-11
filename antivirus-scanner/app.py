import os
import hashlib
import shutil
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Karantina klasörünün yolu (Proje klasörünün içinde otomatik oluşacak)
QUARANTINE_DIR = os.path.join(os.getcwd(), "karantina")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# Örnek Zararlı Yazılım Hash Veri Tabanı
SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Malware_EmptyFile",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Zararli_Yazilim_A"
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

# --- YENİ WEB ARAYÜZÜ ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Gelişmiş Antivirüs Tarayıcı</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 40px; }
        .container { max-width: 900px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        input[type="text"] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .btn-delete { background-color: #dc3545; font-size: 12px; padding: 5px 10px; margin-left: 10px;}
        .btn-quarantine { background-color: #ffc107; color: black; font-size: 12px; padding: 5px 10px; margin-left: 5px;}
        #results { margin-top: 20px; max-height: 400px; overflow-y: auto; border-top: 2px solid #eee; padding-top: 10px; }
        .clean { color: green; margin: 5px 0; font-size: 14px; }
        .danger { color: red; font-weight: bold; margin: 5px 0; background: #f8d7da; padding: 8px; border-radius: 4px; display: flex; justify-content: space-between; align-items: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Gelişmiş Antivirüs Tarama Modülü</h1>
        <p>Bilgisayarınızda taratmak istediğiniz klasörün tam yolunu girin:</p>
        
        <input type="text" id="folderPath" placeholder="Klasör yolu yapıştırın...">
        <button onclick="startScan()">Tara</button>

        <h3 id="status"></h3>
        <div id="results"></div>
    </div>

    <script>
        async function startScan() {
            const path = document.getElementById('folderPath').value;
            const statusText = document.getElementById('status');
            const resultsDiv = document.getElementById('results');
            
            if (!path) { alert("Lütfen bir klasör yolu girin!"); return; }
            statusText.innerText = "⏳ Tarama yapılıyor...";
            resultsDiv.innerHTML = "";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                const data = await response.json();
                statusText.innerText = `✅ Tarama Tamamlandı! Toplam ${data.total_scanned} dosya incelendi.`;
                
                data.results.forEach((item, index) => {
                    const p = document.createElement('p');
                    if (item.status === 'INFECTED') {
                        p.className = 'danger';
                        p.id = `row-${index}`;
                        p.innerHTML = `
                            <span>🚨 [TEHLİKE] ${item.file} -> ${item.malware}</span>
                            <div>
                                <button class="btn-quarantine" onclick="actionFile('quarantine', '${btoa(item.file)}', 'row-${index}')">Karantinaya Al</button>
                                <button class="btn-delete" onclick="actionFile('delete', '${btoa(item.file)}', 'row-${index}')">Sil</button>
                            </div>
                        `;
                    } else {
                        p.className = 'clean';
                        p.innerText = `✔️ [TEMİZ] ${item.file}`;
                    }
                    resultsDiv.appendChild(p);
                });
            } catch (error) { statusText.innerText = "❌ Bir hata oluştu."; }
        }

        async function actionFile(action, encodedPath, rowId) {
            const filePath = atob(encodedPath);
            if(!confirm(`${filePath} dosyasına ${action === 'delete' ? 'SİLME' : 'KARANTİNA'} işlemi uygulansın mı?`)) return;

            const response = await fetch('/action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: action, path: filePath })
            });
            const data = await response.json();
            alert(data.message);
            if(data.success) {
                document.getElementById(rowId).style.backgroundColor = "#d4edda";
                document.getElementById(rowId).style.color = "#155724";
                document.getElementById(rowId).innerHTML = `✅ Dosya başarıyla ${action === 'delete' ? 'silindi' : 'karantinaya taşındı'}.`;
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
            # Karantina klasörünün kendisini taramasını engelle
            if QUARANTINE_DIR in file_path:
                continue
            file_hash = calculate_sha256(file_path)
            if file_hash is None:
                continue

            if file_hash in SIGNATURES:
                scan_results.append({"file": file_path, "status": "INFECTED", "malware": SIGNATURES[file_hash]})
            else:
                scan_results.append({"file": file_path, "status": "CLEAN"})
    return jsonify({"results": scan_results, "total_scanned": len(scan_results)})

@app.route('/action', methods=['POST'])
def action():
    data = request.get_json()
    action_type = data.get('action')
    file_path = data.get('path')

    if not os.path.exists(file_path):
        return jsonify({"success": False, "message": "Dosya bulunamadı."})

    try:
        if action_type == 'delete':
            os.remove(file_path)
            return jsonify({"success": True, "message": "Dosya bilgisayardan kalıcı olarak silindi!"})
            
        elif action_type == 'quarantine':
            file_name = os.path.basename(file_path)
            dest_path = os.path.join(QUARANTINE_DIR, file_name)
            # Aynı isimde dosya varsa üzerine yazmasın diye kontrol
            if os.path.exists(dest_path):
                dest_path = dest_path + "_karantina"
            shutil.move(file_path, dest_path)
            return jsonify({"success": True, "message": f"Dosya güvenli karantina klasörüne taşındı!\nKonum: {QUARANTINE_DIR}"})
            
    except Exception as e:
        return jsonify({"success": False, "message": f"İşlem başarısız (Yetki hatası olabilir): {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
