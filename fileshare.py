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
SUPER_IPS = ["127.0.0.1", "::1"]

def get_all_local_ips():
    ips = ["127.0.0.1"]
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if ip not in ips: ips.append(ip)
    except: pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except: pass
    return list(set(ips))

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

init_db()

def is_super_admin():
    if request.args.get('test_mode') == '1' or session.get('test_mode'):
        if request.args.get('test_mode') == '1': session['test_mode'] = True
        return False
    return request.remote_addr in SUPER_IPS

def get_current_permissions():
    if is_super_admin(): return ["view", "download", "upload", "manage", "admin_panel"]
    if "user" in session: return session.get("permissions", "").split(",")
    return []

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_super_admin() and "user" not in session: return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if is_super_admin(): return f(*args, **kwargs)
            if permission not in get_current_permissions(): abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def safe_join(base, *paths):
    joined = os.path.normpath(os.path.join(base, *paths))
    if not joined.startswith(base): abort(403)
    return joined

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username, password = request.form.get("username"), request.form.get("password")
        if not username or not password: return render_template("register.html", error="请填写完整信息")
        try:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)",
                             (username, generate_password_hash(password), "user", "view"))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError: return render_template("register.html", error="用户名已存在")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_super_admin(): return redirect(url_for("index"))
    if request.method == "POST":
        username, password = request.form.get("username"), request.form.get("password")
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.update({"user": user["username"], "role": user["role"], "permissions": user["permissions"]})
            return redirect(url_for("index"))
        return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    """用户注销自己的账号"""
    username = session.get("user")
    if not username: abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    session.clear()
    return "OK", 200

@app.route("/exit_test_mode")
def exit_test_mode():
    session.pop('test_mode', None)
    return redirect(url_for("index"))

@app.route("/admin/users", methods=["GET"])
@login_required
@permission_required("manage")
def admin_users():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT id, username, role, permissions FROM users").fetchall()
    return render_template("admin.html", users=users, is_super=is_super_admin(), current_role=session.get("role", "user"))

@app.route("/admin/update_user", methods=["POST"])
@login_required
@permission_required("manage")
def update_user():
    data = request.get_json()
    user_id, new_role, new_perms = data.get("id"), data.get("role"), ",".join(data.get("permissions", []))
    
    # 权限检查：非超管不能修改管理员
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not is_super_admin() and target["role"] == "admin": abort(403)
        conn.execute("UPDATE users SET role = ?, permissions = ? WHERE id = ?", (new_role, new_perms, user_id))
    return "OK", 200

@app.route("/admin/delete_user", methods=["POST"])
@login_required
@permission_required("manage")
def delete_user():
    user_id = request.get_json().get("id")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        # 权限检查：非超管不能删除管理员
        if not is_super_admin() and target["role"] == "admin": abort(403)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "OK", 200

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
@login_required
@permission_required("view")
def index(subpath=""):
    full_path = safe_join(SHARED_FOLDER, subpath)
    if not os.path.exists(full_path): return "Directory not found", 404
    items = []
    for name in os.listdir(full_path):
        item_path = os.path.join(full_path, name)
        items.append({"name": name, "is_dir": os.path.isdir(item_path), "rel_path": os.path.relpath(item_path, SHARED_FOLDER).replace("\\", "/")})
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    path_parts = [p for p in subpath.split("/") if p]
    breadcrumbs = [{"name": part, "path": "/".join(path_parts[:i+1])} for i, part in enumerate(path_parts)]
    return render_template("index.html", items=items, ip=socket.gethostbyname(socket.gethostname()), current_path=subpath, breadcrumbs=breadcrumbs, 
                           user="SuperAdmin" if is_super_admin() else session.get("user"), is_super=is_super_admin(), 
                           perms=get_current_permissions(), test_mode=session.get('test_mode'))

@app.route("/upload", methods=["POST"])
@login_required
@permission_required("upload")
def upload_file():
    file = request.files["file"]
    target_path = safe_join(SHARED_FOLDER, request.form.get("path", ""), request.form.get("webkitRelativePath", "") or file.filename)
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
            for root, _, files in os.walk(full_path):
                for file in files:
                    fp = os.path.join(root, file)
                    zf.write(fp, os.path.relpath(fp, os.path.dirname(full_path)))
        memory_file.seek(0)
        return send_file(memory_file, mimetype='application/zip', as_attachment=True, download_name=f"{os.path.basename(full_path)}.zip")
    return send_from_directory(SHARED_FOLDER, filename, as_attachment=True)

@app.route("/delete", methods=["POST"])
@login_required
@permission_required("manage")
def delete_items():
    for path in request.get_json().get("paths", []):
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
        if op == 'rename': os.rename(safe_join(SHARED_FOLDER, src_paths[0]), safe_join(os.path.dirname(safe_join(SHARED_FOLDER, src_paths[0])), data.get("new_name")))
        elif op in ['move', 'copy']:
            for path in src_paths:
                src, dest = safe_join(SHARED_FOLDER, path), os.path.join(safe_join(SHARED_FOLDER, dest_dir), os.path.basename(safe_join(SHARED_FOLDER, path)))
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
