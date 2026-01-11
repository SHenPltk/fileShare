import os
import socket
import shutil
import zipfile
import io
import functools
import sqlite3
from flask import Flask, request, render_template, send_from_directory, jsonify, abort, send_file, make_response, session, redirect, url_for
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

DB_PATH = "users.db"
SHARED_FOLDER = os.path.abspath("shared_files")
# 特权IP列表，初始包含回环地址
SUPER_IPS = ["127.0.0.1", "::1"]

def get_all_local_ips():
    """获取本机所有网卡的IP地址"""
    ips = ["127.0.0.1"]
    try:
        # 获取所有网卡信息
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
    except:
        pass
    # 补充一种常用的获取局域网IP的方法
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except:
        pass
    return list(set(ips))

# 启动时自动将本机所有IP加入特权列表
SUPER_IPS.extend(get_all_local_ips())

if not os.path.exists(SHARED_FOLDER):
    os.makedirs(SHARED_FOLDER)

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      username TEXT UNIQUE NOT NULL, 
                      password TEXT NOT NULL, 
                      role TEXT NOT NULL,
                      permissions TEXT NOT NULL)''')
        admin_pw = generate_password_hash("admin123")
        try:
            conn.execute("INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)",
                         ("admin", admin_pw, "admin", "view,download,upload,manage"))
        except sqlite3.IntegrityError:
            pass

init_db()

def is_super_admin():
    """检查是否为特权IP"""
    client_ip = request.remote_addr
    # 检查客户端IP是否在特权列表中
    return client_ip in SUPER_IPS

def get_current_permissions():
    """获取当前用户的权限列表"""
    if is_super_admin():
        return ["view", "download", "upload", "manage", "admin_panel"]
    if "user" in session:
        return session.get("permissions", "").split(",")
    return []

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_super_admin() and "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if is_super_admin():
                return f(*args, **kwargs)
            perms = get_current_permissions()
            if permission not in perms:
                return abort(403, description=f"Missing permission: {permission}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

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

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return render_template("register.html", error="请填写完整信息")
        hashed_pw = generate_password_hash(password)
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)",
                             (username, hashed_pw, "user", "view,download"))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_super_admin():
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["permissions"] = user["permissions"]
            return redirect(url_for("index"))
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin/users", methods=["GET"])
@login_required
@permission_required("manage")
def admin_users():
    if not is_super_admin() and session.get("role") != "admin":
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT id, username, role, permissions FROM users").fetchall()
    return render_template("admin.html", users=users, is_super=is_super_admin())

@app.route("/admin/update_perms", methods=["POST"])
@login_required
@permission_required("manage")
def update_perms():
    if not is_super_admin() and session.get("role") != "admin":
        abort(403)
    data = request.get_json()
    user_id = data.get("id")
    new_perms = ",".join(data.get("permissions", []))
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE users SET permissions = ? WHERE id = ?", (new_perms, user_id))
    return "OK", 200

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
@login_required
@permission_required("view")
def index(subpath=""):
    full_path = safe_join(SHARED_FOLDER, subpath)
    if not os.path.exists(full_path):
        return "Directory not found", 404
    items = []
    for name in os.listdir(full_path):
        item_path = os.path.join(full_path, name)
        items.append({
            "name": name,
            "is_dir": os.path.isdir(item_path),
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
                           breadcrumbs=breadcrumbs,
                           user="SuperAdmin" if is_super_admin() else session.get("user"),
                           is_super=is_super_admin(),
                           perms=get_current_permissions())

@app.route("/upload", methods=["POST"])
@login_required
@permission_required("upload")
def upload_file():
    file = request.files["file"]
    subpath = request.form.get("path", "")
    rel_path = request.form.get("webkitRelativePath", "")
    target_path = safe_join(SHARED_FOLDER, subpath, rel_path if rel_path else file.filename)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    file.save(target_path)
    return "OK", 200

@app.route("/download/<path:filename>", methods=["GET"])
@login_required
@permission_required("download")
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
        response = send_file(memory_file, mimetype='application/zip', as_attachment=True, download_name=f"{os.path.basename(full_path)}.zip")
    else:
        response = make_response(send_from_directory(SHARED_FOLDER, filename, as_attachment=True))
    response.headers["Content-Security-Policy"] = "upgrade-insecure-requests"
    return response

@app.route("/delete", methods=["POST"])
@login_required
@permission_required("manage")
def delete_items():
    data = request.get_json()
    for path in data.get("paths", []):
        full_path = safe_join(SHARED_FOLDER, path)
        if os.path.exists(full_path):
            if os.path.isdir(full_path): shutil.rmtree(full_path)
            else: os.remove(full_path)
    return "OK", 200

@app.route("/fs_op", methods=["POST"])
@login_required
@permission_required("manage")
def file_system_operation():
    data = request.get_json()
    op, src_paths, dest_dir = data.get("op"), data.get("src_paths", []), data.get("dest_dir", "")
    try:
        if op == 'rename':
            src = safe_join(SHARED_FOLDER, src_paths[0])
            os.rename(src, safe_join(os.path.dirname(src), data.get("new_name")))
        elif op in ['move', 'copy']:
            dest_base = safe_join(SHARED_FOLDER, dest_dir)
            for path in src_paths:
                src = safe_join(SHARED_FOLDER, path)
                dest = os.path.join(dest_base, os.path.basename(src))
                if src == dest: continue
                if op == 'move': shutil.move(src, dest)
                else:
                    if os.path.isdir(src): shutil.copytree(src, dest, dirs_exist_ok=True)
                    else: shutil.copy2(src, dest)
        return "OK", 200
    except Exception as e: return str(e), 500

@app.route("/mkdir", methods=["POST"])
@login_required
@permission_required("upload")
def make_directory():
    data = request.get_json()
    os.makedirs(safe_join(SHARED_FOLDER, data.get("path", ""), data.get("dirname", "")), exist_ok=True)
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
