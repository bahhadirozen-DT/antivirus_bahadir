import os
import hashlib
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

# Örnek Zararlı Yazılım Hash Veri Tabanı
SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Test_Malware_EmptyFile",
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "Zararli_Yazilim_A"
}

def calculate_sha256(file_path):
    """Dosyanın SHA-256 değerini hesaplar."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None

# --- WEB ARAYÜZÜ (HTML + CSS) ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Yerel Antivirüs Tarayıcı</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 40px; }
        .container { max-width: 800px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; }
        input[type="text"] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        #results { margin-top: 20px; max-height: 400px; overflow-y: auto; border-top: 2px solid #eee; padding-top: 10px; }
        .clean { color: green; margin: 5px 0; font-size: 14px; }
        .danger { color: red; font-weight: bold; margin: 5px 0; background: #f8d7da; padding: 5px; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Yerel Antivirüs Tarama Modülü</h1>
        <p>Bilgisayarınızda taratmak istediğiniz klasörün tam yolunu (Path) girin:</p>
        
        <input type="text" id="folderPath" placeholder="Örn: C:\\Users\\Adiniz\\Downloads veya /home/user/downloads">
        <button onclick="startScan()">Tara</button>

        <h3 id="status"></h3>
        <div id="results"></div>
    </div>

    <script>
        async function startScan() {
            const path = document.getElementById('folderPath').value;
            const statusText = document.getElementById('status');
            const resultsDiv = document.getElementById('results');
            
            if (!path) {
                alert("Lütfen bir klasör yolu girin!");
                return;
            }

            statusText.innerText = "⏳ Tarama yapılıyor, lütfen bekleyin...";
            resultsDiv.innerHTML = "";

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: path })
                });
                
                const data = await response.json();
                statusText.innerText = `✅ Tarama Tamamlandı! Toplam ${data.total_scanned} dosya incelendi.`;
                
                if (data.results.length === 0) {
                    resultsDiv.innerHTML = "<p>Klasör boş veya erişilemedi.</p>";
                    return;
                }

                data.results.forEach(item => {
                    const p = document.createElement('p');
                    if (item.status === 'INFECTED') {
                        p.className = 'danger';
                        p.innerText = `🚨 [TEHLİKE] ${item.file} -> Virüs Tipi: ${item.malware}`;
                    } else {
                        p.className = 'clean';
                        p.innerText = `✔️ [TEMİZ] ${item.file}`;
                    }
                    resultsDiv.appendChild(p);
                });

            } catch (error) {
                statusText.innerText = "❌ Bir hata oluştu.";
                console.error(error);
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
        return jsonify({"results": [], "total_scanned": 0, "error": "Yol bulunamadı"})

    # Klasörü tara
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_sha256(file_path)

            if file_hash is None:
                continue

            if file_hash in SIGNATURES:
                scan_results.append({
                    "file": file_path,
                    "status": "INFECTED",
                    "malware": SIGNATURES[file_hash]
                })
            else:
                # GitHub arayüzünde çok fazla dosya birikip tarayıcıyı dondurmasın diye 
                # sadece virüsleri veya son birkaç dosyayı göstermek mantıklıdır ancak şimdilik hepsini gönderiyoruz.
                scan_results.append({
                    "file": file_path,
                    "status": "CLEAN"
                })

    return jsonify({"results": scan_results, "total_scanned": len(scan_results)})

if __name__ == '__main__':
    # Localhost üzerinde 5000 portunda çalıştırıyoruz
    app.run(debug=True, port=5000)
