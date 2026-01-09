import os
from flask import Flask, request, render_template, send_from_directory
from flask_cors import CORS
import socket

app = Flask(__name__)
CORS(app)  # 允许跨域访问

# 共享的文件夹路径（修改为你想要的目录）
SHARED_FOLDER = "shared_files"
if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

def get_local_ip():
    """获取本机局域网IP"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 随便连接一个外部地址（不会真正发送数据）
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

@app.route("/", methods=["GET"])
def index():
    """首页，显示文件列表和上传接口"""
    files = os.listdir(SHARED_FOLDER)
    return render_template("index.html", files=files, ip=get_local_ip())

@app.route("/upload", methods=["POST"])
def upload_file():
    """文件上传接口"""
    if "file" not in request.files:
        return "No file uploaded", 400
    file = request.files["file"]
    if file.filename == "":
        return "No file selected", 400
    file.save(os.path.join(SHARED_FOLDER, file.filename))
    return "File uploaded successfully", 200

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    """文件下载接口"""
    return send_from_directory(SHARED_FOLDER, filename, as_attachment=True)

@app.route("/delete/<filename>", methods=["DELETE"])
def delete_file(filename):
    """文件删除接口"""
    file_path = os.path.join(SHARED_FOLDER, filename)
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return "File deleted successfully", 200
        except Exception as e:
            return f"Error deleting file: {str(e)}", 500
    else:
        return "File not found", 404

if __name__ == "__main__":
    local_ip = get_local_ip()
    print(f"\n=== 文件共享服务已启动 ===")
    print(f"在浏览器访问（其他设备）: http://{local_ip}:5000")
    print(f"存储目录: {os.path.abspath(SHARED_FOLDER)}")
    print("按 Ctrl+C 停止服务\n")
    app.run(host="0.0.0.0", port=5000)
