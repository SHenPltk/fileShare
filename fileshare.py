import os
import socket
import shutil
import zipfile
import io
from flask import Flask, request, render_template, send_from_directory, jsonify, abort, send_file, make_response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

SHARED_FOLDER = os.path.abspath("shared_files")
if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def safe_join(base, *paths):
    joined = os.path.normpath(os.path.join(base, *paths))
    if not joined.startswith(base):
        abort(403)
    return joined

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
def index(subpath=""):
    full_path = safe_join(SHARED_FOLDER, subpath)
    if not os.path.exists(full_path):
        return "Directory not found", 404

    items = []
    for name in os.listdir(full_path):
        item_path = os.path.join(full_path, name)
        is_dir = os.path.isdir(item_path)
        items.append({
            "name": name,
            "is_dir": is_dir,
            "rel_path": os.path.relpath(item_path, SHARED_FOLDER).replace("\\", "/")
        })
    
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    
    path_parts = [p for p in subpath.split("/") if p]
    breadcrumbs = []
    curr_path = ""
    for part in path_parts:
        curr_path = os.path.join(curr_path, part).replace("\\", "/")
        breadcrumbs.append({"name": part, "path": curr_path})

    return render_template("index.html", 
                           items=items, 
                           ip=get_local_ip(), 
                           current_path=subpath,
                           breadcrumbs=breadcrumbs)

@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return "No file", 400
    file = request.files["file"]
    subpath = request.form.get("path", "")
    rel_path = request.form.get("webkitRelativePath", "")
    
    target_path = safe_join(SHARED_FOLDER, subpath, rel_path if rel_path else file.filename)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    file.save(target_path)
    return "OK", 200

@app.route("/download/<path:filename>", methods=["GET"])
def download_item(filename):
    full_path = safe_join(SHARED_FOLDER, filename)
    
    if os.path.isdir(full_path):
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(full_path))
                    zf.write(file_path, arcname)
        memory_file.seek(0)
        response = send_file(memory_file, 
                           mimetype='application/zip', 
                           as_attachment=True, 
                           download_name=f"{os.path.basename(full_path)}.zip")
    else:
        response = make_response(send_from_directory(SHARED_FOLDER, filename, as_attachment=True))
    
    # 增加一些头信息，尝试减少浏览器对非安全连接下载的拦截警告
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    return response

@app.route("/delete", methods=["POST"])
def delete_items():
    data = request.get_json()
    for path in data.get("paths", []):
        full_path = safe_join(SHARED_FOLDER, path)
        if os.path.exists(full_path):
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
            else:
                os.remove(full_path)
    return "OK", 200

@app.route("/fs_op", methods=["POST"])
def file_system_operation():
    data = request.get_json()
    op = data.get("op")
    src_paths = data.get("src_paths", [])
    dest_dir = data.get("dest_dir", "")
    
    try:
        if op == 'rename':
            src = safe_join(SHARED_FOLDER, src_paths[0])
            dest = safe_join(os.path.dirname(src), data.get("new_name"))
            os.rename(src, dest)
        elif op in ['move', 'copy']:
            dest_base = safe_join(SHARED_FOLDER, dest_dir)
            for path in src_paths:
                src = safe_join(SHARED_FOLDER, path)
                # 修复移动逻辑：确保目标路径正确，且不覆盖同名文件夹
                dest_name = os.path.basename(src)
                dest = os.path.join(dest_base, dest_name)
                
                if src == dest: continue # 同目录操作跳过
                
                if op == 'move':
                    shutil.move(src, dest)
                else:
                    if os.path.isdir(src):
                        shutil.copytree(src, dest, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dest)
        return "OK", 200
    except Exception as e:
        return str(e), 500

@app.route("/mkdir", methods=["POST"])
def make_directory():
    data = request.get_json()
    target_dir = safe_join(SHARED_FOLDER, data.get("path", ""), data.get("dirname", ""))
    os.makedirs(target_dir, exist_ok=True)
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
