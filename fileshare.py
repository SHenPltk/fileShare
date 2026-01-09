import os
import socket
from flask import Flask, request, render_template, send_from_directory, jsonify, abort
from flask_cors import CORS
from werkzeug.utils import secure_filename

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

@app.route("/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
def index(subpath=""):
    """首页及目录浏览"""
    full_path = os.path.join(SHARED_FOLDER, subpath)
    
    # 安全检查：防止目录穿越
    if not os.path.commonpath([SHARED_FOLDER, os.path.abspath(full_path)]) == SHARED_FOLDER:
        abort(403)
        
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
    
    # 排序：文件夹在前，文件在后
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    
    # 计算面包屑导航
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
    """文件上传接口，支持上传到指定子目录"""
    if "file" not in request.files:
        return "No file uploaded", 400
    
    file = request.files["file"]
    subpath = request.form.get("path", "")
    
    if file.filename == "":
        return "No file selected", 400
    
    # 处理文件夹上传时的相对路径
    # 很多浏览器在上传文件夹时会提供 webkitRelativePath
    rel_path = request.form.get("webkitRelativePath", "")
    if rel_path:
        target_dir = os.path.join(SHARED_FOLDER, subpath, os.path.dirname(rel_path))
        filename = os.path.basename(rel_path)
    else:
        target_dir = os.path.join(SHARED_FOLDER, subpath)
        filename = file.filename

    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    file.save(os.path.join(target_dir, filename))
    return "File uploaded successfully", 200

@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    """文件下载接口"""
    return send_from_directory(SHARED_FOLDER, filename, as_attachment=True)

@app.route("/delete/<path:filename>", methods=["DELETE"])
def delete_item(filename):
    """文件或文件夹删除接口"""
    full_path = os.path.join(SHARED_FOLDER, filename)
    
    # 安全检查
    if not os.path.commonpath([SHARED_FOLDER, os.path.abspath(full_path)]) == SHARED_FOLDER:
        abort(403)

    if os.path.exists(full_path):
        try:
            if os.path.isdir(full_path):
                import shutil
                shutil.rmtree(full_path)
            else:
                os.remove(full_path)
            return "Item deleted successfully", 200
        except Exception as e:
            return f"Error deleting item: {str(e)}", 500
    else:
        return "Item not found", 404

@app.route("/mkdir", methods=["POST"])
def make_directory():
    """创建新文件夹"""
    data = request.get_json()
    subpath = data.get("path", "")
    dirname = data.get("dirname", "")
    
    if not dirname:
        return "Directory name required", 400
        
    target_dir = os.path.join(SHARED_FOLDER, subpath, dirname)
    
    # 安全检查
    if not os.path.commonpath([SHARED_FOLDER, os.path.abspath(target_dir)]) == SHARED_FOLDER:
        abort(403)
        
    try:
        os.makedirs(target_dir, exist_ok=True)
        return "Directory created", 200
    except Exception as e:
        return str(e), 500

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"\n=== 文件共享服务已启动 ===")
    print(f"在浏览器访问（其他设备）: http://{local_ip}:5000")
    print(f"存储目录: {os.path.abspath(SHARED_FOLDER)}")
    print("按 Ctrl+C 停止服务\n")
    app.run(host="0.0.0.0", port=5000)
