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
        # 用户表
        conn.execute('''CREATE TABLE IF NOT EXISTS users 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      username TEXT UNIQUE NOT NULL, 
                      password TEXT NOT NULL, 
                      role TEXT NOT NULL,
                      permissions TEXT NOT NULL)''')
        # 文件所有权与 ACL 表
        conn.execute('''CREATE TABLE IF NOT EXISTS file_acl 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      path TEXT UNIQUE NOT NULL, 
                      owner TEXT NOT NULL,
                      shared_with TEXT)''') # shared_with 格式: "user1:view,download;user2:view"

init_db()

def is_super_admin():
    """检查是否为特权IP，且未开启测试模式"""
    if session.get('test_mode'): return False
    return request.remote_addr in SUPER_IPS

def get_file_permissions(path, username):
    """获取特定用户对特定文件的权限"""
    if is_super_admin(): return ["view", "download", "upload", "manage"]
    
    # 规范化路径
    rel_path = os.path.relpath(safe_join(SHARED_FOLDER, path), SHARED_FOLDER).replace("\\", "/")
    if rel_path == ".": rel_path = ""

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        acl = conn.execute("SELECT * FROM file_acl WHERE path = ?", (rel_path,)).fetchone()
        
        # 如果是所有者，拥有所有权限
        if acl and acl["owner"] == username:
            return ["view", "download", "upload", "manage"]
        
        # 检查全局用户权限作为基础
        user_perms = session.get("permissions", "").split(",")
        
        # 检查特定文件的共享权限 (ACL)
        if acl and acl["shared_with"]:
            for entry in acl["shared_with"].split(";"):
                if ":" in entry:
                    u, p = entry.split(":")
                    if u == username:
                        return list(set(user_perms + p.split(",")))
        
        return user_perms

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_super_admin() and "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

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
    # 只有在非测试模式下，超管才自动跳转
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
    # 退出登录时不清除 test_mode，确保留在登录页
    test_mode = session.get('test_mode')
    session.clear()
    if test_mode: session['test_mode'] = True
    return redirect(url_for("login"))

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    username = session.get("user")
    if not username: return "Not logged in", 401
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    session.clear()
    return "OK", 200

@app.route("/enter_test_mode")
def enter_test_mode():
    session.clear()
    session['test_mode'] = True
    return redirect(url_for("login"))

@app.route("/exit_test_mode")
def exit_test_mode():
    session.clear() # 完全清除，包括 test_mode
    return redirect(url_for("index"))

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
@login_required
def index(subpath=""):
    username = session.get("user", "SuperAdmin" if is_super_admin() else "Guest")
    perms = get_file_permissions(subpath, username)
    
    if "view" not in perms: abort(403)
    
    full_path = safe_join(SHARED_FOLDER, subpath)
    if not os.path.exists(full_path): return "Not found", 404
    
    items = []
    for name in os.listdir(full_path):
        item_rel = os.path.relpath(os.path.join(full_path, name), SHARED_FOLDER).replace("\\", "/")
        item_perms = get_file_permissions(item_rel, username)
        if "view" in item_perms:
            items.append({
                "name": name,
                "is_dir": os.path.isdir(os.path.join(full_path, name)),
                "rel_path": item_rel,
                "perms": item_perms
            })
            
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    path_parts = [p for p in subpath.split("/") if p]
    breadcrumbs = [{"name": part, "path": "/".join(path_parts[:i+1])} for i, part in enumerate(path_parts)]
    
    return render_template("index.html", items=items, ip=get_local_ip(), current_path=subpath, breadcrumbs=breadcrumbs, 
                           user=username, is_super=is_super_admin(), perms=perms, test_mode=session.get('test_mode'))

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    username = session.get("user", "SuperAdmin")
    subpath = request.form.get("path", "")
    if "upload" not in get_file_permissions(subpath, username): abort(403)
    
    file = request.files["file"]
    rel_name = request.form.get("webkitRelativePath", "") or file.filename
    target_path = safe_join(SHARED_FOLDER, subpath, rel_name)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    file.save(target_path)
    
    # 记录所有权
    rel_db_path = os.path.relpath(target_path, SHARED_FOLDER).replace("\\", "/")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO file_acl (path, owner) VALUES (?, ?)", (rel_db_path, username))
    return "OK", 200

@app.route("/download/<path:filename>", methods=["GET"])
@login_required
def download_item(filename):
    if "download" not in get_file_permissions(filename, session.get("user", "SuperAdmin")): abort(403)
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
def delete_items():
    username = session.get("user", "SuperAdmin")
    for path in request.get_json().get("paths", []):
        if "manage" in get_file_permissions(path, username):
            full_path = safe_join(SHARED_FOLDER, path)
            if os.path.exists(full_path):
                if os.path.isdir(full_path): shutil.rmtree(full_path)
                else: os.remove(full_path)
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("DELETE FROM file_acl WHERE path = ?", (path,))
    return "OK", 200

@app.route("/fs_op", methods=["POST"])
@login_required
def file_system_operation():
    username = session.get("user", "SuperAdmin")
    data = request.get_json()
    op, src_paths, dest_dir = data.get("op"), data.get("src_paths", []), data.get("dest_dir", "")
    
    if "manage" not in get_file_permissions(dest_dir, username): abort(403)
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            if op == 'rename':
                src = src_paths[0]
                if "manage" not in get_file_permissions(src, username): abort(403)
                dest = os.path.join(os.path.dirname(src), data.get("new_name")).replace("\\", "/")
                os.rename(safe_join(SHARED_FOLDER, src), safe_join(SHARED_FOLDER, dest))
                conn.execute("UPDATE file_acl SET path = ? WHERE path = ?", (dest, src))
            elif op in ['move', 'copy']:
                for path in src_paths:
                    if "manage" not in get_file_permissions(path, username): continue
                    src = safe_join(SHARED_FOLDER, path)
                    dest_rel = os.path.join(dest_dir, os.path.basename(path)).replace("\\", "/")
                    dest = safe_join(SHARED_FOLDER, dest_rel)
                    if src == dest: continue
                    if op == 'move':
                        shutil.move(src, dest)
                        conn.execute("UPDATE file_acl SET path = ? WHERE path = ?", (dest_rel, path))
                    else:
                        if os.path.isdir(src): shutil.copytree(src, dest, dirs_exist_ok=True)
                        else: shutil.copy2(src, dest)
                        conn.execute("INSERT OR REPLACE INTO file_acl (path, owner) VALUES (?, ?)", (dest_rel, username))
        return "OK", 200
    except Exception as e: return str(e), 500

@app.route("/mkdir", methods=["POST"])
@login_required
def make_directory():
    username = session.get("user", "SuperAdmin")
    data = request.get_json()
    parent = data.get("path", "")
    if "upload" not in get_file_permissions(parent, username): abort(403)
    
    new_dir_rel = os.path.join(parent, data.get("dirname", "")).replace("\\", "/")
    os.makedirs(safe_join(SHARED_FOLDER, new_dir_rel), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO file_acl (path, owner) VALUES (?, ?)", (new_dir_rel, username))
    return "OK", 200

@app.route("/admin/users", methods=["GET"])
@login_required
def admin_users():
    if not is_super_admin() and session.get("role") != "admin": abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT id, username, role, permissions FROM users").fetchall()
    return render_template("admin.html", users=users, is_super=is_super_admin(), current_role=session.get("role", "user"))

@app.route("/admin/update_user", methods=["POST"])
@login_required
def update_user():
    if not is_super_admin() and session.get("role") != "admin": abort(403)
    data = request.get_json()
    user_id, new_role, new_perms = data.get("id"), data.get("role"), ",".join(data.get("permissions", []))
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not is_super_admin() and target["role"] == "admin": abort(403)
        conn.execute("UPDATE users SET role = ?, permissions = ? WHERE id = ?", (new_role, new_perms, user_id))
    return "OK", 200

@app.route("/admin/delete_user", methods=["POST"])
@login_required
def delete_user():
    if not is_super_admin() and session.get("role") != "admin": abort(403)
    user_id = request.get_json().get("id")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        target = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not is_super_admin() and target["role"] == "admin": abort(403)
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "OK", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
