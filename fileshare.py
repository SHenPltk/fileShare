import os
import socket
import shutil
import zipfile
import io
from flask import Flask, request, render_template, send_from_directory, jsonify, abort, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# 共享的文件夹路径
SHARED_FOLDER = os.path.abspath("shared_files")
if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

def get_local_ip():
    """获取本机局域网IP"""
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
    """安全地拼接路径，防止目录穿越"""
    joined = os.path.abspath(os.path.join(base, *paths))
    if os.path.commonpath([base, joined]) != base:
        abort(403)
    return joined

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
def index(subpath=""):
    """首页及目录浏览"""
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
            "rel_path": os.path.join(subpath, name).replace("\\", "/")
        })
    
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    
    path_parts = subpath.split("/") if subpath else []
    breadcrumbs = []
    curr_path = ""
    for part in path_parts:
        if part:
            curr_path = os.path.join(curr_path, part).replace("\\", "/")
            breadcrumbs.append({"name": part, "path": curr_path})

    return render_template("index.html", 
                           items=items, 
                           ip=get_local_ip(), 
                           current_path=subpath,
                           breadcrumbs=breadcrumbs)

@app.route("/upload", methods=["POST"])
def upload_file():
    """文件上传接口"""
    if "file" not in request.files:
        return "No file uploaded", 400
    
    file = request.files["file"]
    subpath = request.form.get("path", "")
    rel_path = request.form.get("webkitRelativePath", "")
    
    if rel_path:
        target_path = safe_join(SHARED_FOLDER, subpath, rel_path)
    else:
        target_path = safe_join(SHARED_FOLDER, subpath, file.filename)

    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    file.save(target_path)
    return "OK", 200

@app.route("/download/<path:filename>", methods=["GET"])
def download_item(filename):
    """下载文件或文件夹（文件夹自动打包为ZIP）"""
    full_path = safe_join(SHARED_FOLDER, filename)
    
    if os.path.isdir(full_path):
        # 打包文件夹
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(full_path))
                    zf.write(file_path, arcname)
        memory_file.seek(0)
        return send_file(memory_file, 
                         mimetype='application/zip', 
                         as_attachment=True, 
                         download_name=f"{os.path.basename(full_path)}.zip")
    
    return send_from_directory(SHARED_FOLDER, filename, as_attachment=True)

@app.route("/delete", methods=["POST"])
def delete_items():
    """批量删除文件或文件夹"""
    data = request.get_json()
    paths = data.get("paths", [])
    for path in paths:
        full_path = safe_join(SHARED_FOLDER, path)
        if os.path.exists(full_path):
            if os.path.isdir(full_path):
                shutil.rmtree(full_path)
            else:
                os.remove(full_path)
    return "OK", 200

@app.route("/fs_op", methods=["POST"])
def file_system_operation():
    """文件系统操作：移动、复制、重命名"""
    data = request.get_json()
    op = data.get("op") # 'move', 'copy', 'rename'
    src_paths = data.get("src_paths", [])
    dest_dir = data.get("dest_dir", "")
    new_name = data.get("new_name") # 仅用于重命名

    try:
        if op == 'rename':
            if len(src_paths) != 1 or not new_name:
                return "Invalid rename request", 400
            src = safe_join(SHARED_FOLDER, src_paths[0])
            dest = safe_join(os.path.dirname(src), new_name)
            os.rename(src, dest)
        
        elif op in ['move', 'copy']:
            dest_base = safe_join(SHARED_FOLDER, dest_dir)
            for path in src_paths:
                src = safe_join(SHARED_FOLDER, path)
                dest = os.path.join(dest_base, os.path.basename(src))
                if op == 'move':
                    shutil.move(src, dest)
                else:
                    if os.path.isdir(src):
                        shutil.copytree(src, dest)
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
    local_ip = get_local_ip()
    print(f"\n=== 文件共享服务已启动 ===")
    print(f"在浏览器访问: http://{local_ip}:5000")
    app.run(host="0.0.0.0", port=5000)
