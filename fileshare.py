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
        conn.execute('''CREATE TABLE IF NOT EXISTS file_acl 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      path TEXT UNIQUE NOT NULL, 
                      owner TEXT NOT NULL,
                      shared_with TEXT)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS chat_messages 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                      username TEXT NOT NULL, 
                      content TEXT NOT NULL, 
                      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                      is_deleted INTEGER NOT NULL DEFAULT 0)''')
        try:
            conn.execute("ALTER TABLE chat_messages ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass

init_db()

with sqlite3.connect(DB_PATH) as _conn:
    _conn.row_factory = sqlite3.Row
    row = _conn.execute("SELECT MAX(id) AS max_id FROM chat_messages").fetchone()
    CHAT_BASELINE_ID = row["max_id"] or 0

def get_current_user_record():
    username = session.get("user")
    if not username:
        return {"username": None, "role": session.get("role", "user"), "permissions": session.get("permissions", "")}
    if session.get("is_super_admin"):
        return {"username": "SuperAdmin", "role": "admin", "permissions": "upload,chat,chat_manage"}
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT username, role, permissions FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        return {"username": row["username"], "role": row["role"], "permissions": row["permissions"] or ""}
    return {"username": username, "role": session.get("role", "user"), "permissions": session.get("permissions", "")}

def is_super_admin():
    """只有在 session 中明确标记为 super_admin 时才是超管"""
    return session.get('is_super_admin') is True

def can_access_super_privilege():
    """检查当前 IP 是否有资格申请超管权限"""
    return request.remote_addr in SUPER_IPS

def get_file_permissions(path, username):
    if is_super_admin():
        return ["view", "download", "upload", "manage"]
    rel_path = os.path.relpath(safe_join(SHARED_FOLDER, path), SHARED_FOLDER).replace("\\", "/")
    if rel_path == ".": rel_path = ""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        acl = conn.execute("SELECT * FROM file_acl WHERE path = ?", (rel_path,)).fetchone()
        perms = set()
        role = session.get("role", "user")
        if acl and acl["owner"] == username:
            perms.update(["view", "download", "upload", "manage"])
        if role == "admin":
            perms.update(["view", "download", "upload", "manage"])
        if acl and acl["shared_with"]:
            for entry in acl["shared_with"].split(";"):
                if ":" in entry:
                    u, p = entry.split(":", 1)
                    if u == username:
                        for item in p.split(","):
                            if item:
                                perms.add(item)
        user_perms = set([p for p in session.get("permissions", "").split(",") if p])
        if "upload" in user_perms:
            perms.add("upload")
        if rel_path == "":
            perms.add("view")
        return list(perms)

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
                             (username, generate_password_hash(password), "user", "chat"))
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form.get("username"), request.form.get("password")
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.update({"user": user["username"], "role": user["role"], "permissions": user["permissions"], "is_super_admin": False})
            return redirect(url_for("index"))
        return render_template("login.html", error="用户名或密码错误", can_super=can_access_super_privilege())
    return render_template("login.html", can_super=can_access_super_privilege())

@app.route("/super_login")
def super_login():
    """本机特权登录入口"""
    if can_access_super_privilege():
        session.clear()
        session["is_super_admin"] = True
        session["user"] = "SuperAdmin"
        session["role"] = "admin"
        session["permissions"] = "upload,chat,chat_manage"
        return redirect(url_for("index"))
    abort(403)

@app.route("/logout")
def logout():
    test_mode = session.get('test_mode')
    session.clear()
    if test_mode:
        session['test_mode'] = True # 保持测试模式状态
    return redirect(url_for("login"))

@app.route("/enter_test_mode")
def enter_test_mode():
    if can_access_super_privilege():
        session.clear()
        session['test_mode'] = True
        return redirect(url_for("login"))
    abort(403)

@app.route("/exit_test_mode")
def exit_test_mode():
    session.clear()
    return redirect(url_for("login"))

@app.route("/delete_account", methods=["POST"])
@login_required
def delete_account():
    username = session.get("user")
    if not username or is_super_admin(): return "Forbidden", 403
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    session.clear()
    return "OK", 200

@app.route("/", methods=["GET"])
@app.route("/view/", methods=["GET"])
@app.route("/view/<path:subpath>", methods=["GET"])
@login_required
def index(subpath=""):
    user_rec = get_current_user_record()
    username = user_rec["username"]
    perms = get_file_permissions(subpath, username)
    if "view" not in perms: abort(403)
    
    full_path = safe_join(SHARED_FOLDER, subpath)
    if not os.path.exists(full_path): return "Not found", 404
    
    items = []
    for name in os.listdir(full_path):
        item_rel = os.path.relpath(os.path.join(full_path, name), SHARED_FOLDER).replace("\\", "/")
        item_perms = get_file_permissions(item_rel, username)
        if "view" in item_perms:
            items.append({"name": name, "is_dir": os.path.isdir(os.path.join(full_path, name)), "rel_path": item_rel, "perms": item_perms})
            
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    path_parts = [p for p in subpath.split("/") if p]
    breadcrumbs = [{"name": part, "path": "/".join(path_parts[:i+1])} for i, part in enumerate(path_parts)]
    
    return render_template(
        "index.html",
        items=items,
        ip=socket.gethostbyname(socket.gethostname()),
        current_path=subpath,
        breadcrumbs=breadcrumbs,
        user=username,
        is_super=is_super_admin(),
        perms=perms,
        test_mode=session.get("test_mode"),
        user_perms=user_rec["permissions"],
        user_role=user_rec["role"],
    )

@app.route("/chat/messages", methods=["GET"])
@login_required
def get_chat_messages():
    since_id = request.args.get("since_id", type=int)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        base = CHAT_BASELINE_ID
        if since_id:
            rows = conn.execute(
                "SELECT id, username, content, created_at FROM chat_messages WHERE is_deleted = 0 AND id > ? AND id > ? ORDER BY id ASC",
                (since_id, base),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username, content, created_at FROM chat_messages WHERE is_deleted = 0 AND id > ? ORDER BY id ASC",
                (base,),
            ).fetchall()
    return jsonify(
        [
            {
                "id": row["id"],
                "user": row["username"],
                "content": row["content"],
                "time": row["created_at"],
            }
            for row in rows
        ]
    )

@app.route("/chat/send", methods=["POST"])
@login_required
def send_chat_message():
    data = request.get_json() or {}
    content = (data.get("content") or "").strip()
    if not content:
        return "Empty", 400
    if len(content) > 2000:
        content = content[:2000]
    user_rec = get_current_user_record()
    username = user_rec["username"] or "SuperAdmin"
    user_perms = set([p for p in (user_rec["permissions"] or "").split(",") if p])
    if not is_super_admin() and "chat" not in user_perms:
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "INSERT INTO chat_messages (username, content) VALUES (?, ?)",
            (username, content),
        )
        msg_id = cur.lastrowid
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, username, content, created_at FROM chat_messages WHERE id = ?",
            (msg_id,),
        ).fetchone()
    return jsonify(
        {
            "id": row["id"],
            "user": row["username"],
            "content": row["content"],
            "time": row["created_at"],
        }
    )

@app.route("/chat/revoke", methods=["POST"])
@login_required
def revoke_chat_message():
    data = request.get_json() or {}
    msg_id = data.get("id")
    if not isinstance(msg_id, int):
        abort(400)
    current_user = session.get("user")
    user_rec = get_current_user_record()
    user_perms = set([p for p in (user_rec["permissions"] or "").split(",") if p])
    has_chat_manage = "chat_manage" in user_perms or user_rec["role"] == "admin" or is_super_admin()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id, username FROM chat_messages WHERE id = ?", (msg_id,)).fetchone()
        if not row:
            return "Not found", 404
        author = row["username"]
        if is_super_admin():
            allowed = True
        elif author == current_user:
            allowed = True
        elif has_chat_manage:
            if author == "SuperAdmin":
                author_has_manage = True
            else:
                author_row = conn.execute("SELECT role, permissions FROM users WHERE username = ?", (author,)).fetchone()
                if not author_row:
                    author_has_manage = False
                else:
                    author_perms = set([p for p in (author_row["permissions"] or "").split(",") if p])
                    author_has_manage = "chat_manage" in author_perms or author_row["role"] == "admin"
            allowed = not author_has_manage
        else:
            allowed = False
        if not allowed:
            abort(403)
        conn.execute("UPDATE chat_messages SET is_deleted = 1 WHERE id = ?", (msg_id,))
    return "OK", 200

@app.route("/chat/clear", methods=["POST"])
@login_required
def clear_chat_screen():
    global CHAT_BASELINE_ID
    user_rec = get_current_user_record()
    user_perms = set([p for p in (user_rec["permissions"] or "").split(",") if p])
    if not is_super_admin() and "chat_manage" not in user_perms and user_rec["role"] != "admin":
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT MAX(id) AS max_id FROM chat_messages").fetchone()
        CHAT_BASELINE_ID = row["max_id"] or CHAT_BASELINE_ID
    return "OK", 200

@app.route("/chat/export", methods=["GET"])
@login_required
def export_chat():
    user_rec = get_current_user_record()
    user_perms = set([p for p in (user_rec["permissions"] or "").split(",") if p])
    if not is_super_admin() and "chat_manage" not in user_perms and user_rec["role"] != "admin":
        abort(403)
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, username, content, created_at FROM chat_messages WHERE is_deleted = 0 ORDER BY id ASC"
        ).fetchall()
    lines = []
    for row in rows:
        time_str = str(row["created_at"])
        lines.append(f"[{time_str}] {row['username']}: {row['content']}")
    data = "\n".join(lines).encode("utf-8")
    memory_file = io.BytesIO(data)
    memory_file.seek(0)
    return send_file(memory_file, as_attachment=True, download_name="chat_history.txt", mimetype="text/plain; charset=utf-8")

@app.route("/get_file_acl", methods=["GET"])
@login_required
def get_file_acl():
    path = request.args.get("path")
    username = session.get("user")
    if "manage" not in get_file_permissions(path, username): abort(403)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        acl = conn.execute("SELECT * FROM file_acl WHERE path = ?", (path,)).fetchone()
        users = conn.execute("SELECT username, role FROM users").fetchall()
    current_role = session.get("role", "user")
    owner_name = acl["owner"] if acl else "Unknown"
    result_users = []
    for u in users:
        can_edit = True
        if not is_super_admin():
            if u["username"] == owner_name:
                can_edit = False
            elif current_role == "admin" and u["role"] == "admin":
                can_edit = False
        result_users.append({"username": u["username"], "role": u["role"], "can_edit": can_edit})
        
    return jsonify({
        "owner": owner_name,
        "shared_with": acl["shared_with"] if acl else "",
        "all_users": result_users
    })

@app.route("/update_file_acl", methods=["POST"])
@login_required
def update_file_acl():
    data = request.get_json()
    path, shared_with = data.get("path"), data.get("shared_with")
    if "manage" not in get_file_permissions(path, session.get("user")): abort(403)
    
    editor = session.get("user")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        acl = conn.execute("SELECT * FROM file_acl WHERE path = ?", (path,)).fetchone()
        owner_name = acl["owner"] if acl else None
        raw = acl["shared_with"] if acl else ""
        current_map = {}
        if raw:
            for entry in raw.split(";"):
                if ":" in entry:
                    u, p = entry.split(":", 1)
                    current_map[u] = set([i for i in p.split(",") if i])
        new_map = {}
        if shared_with:
            for entry in shared_with.split(";"):
                if ":" in entry:
                    u, p = entry.split(":", 1)
                    new_map[u] = set([i for i in p.split(",") if i])
        is_super = is_super_admin()
        can_edit_manage = False
        if is_super:
            can_edit_manage = True
        elif owner_name and editor == owner_name:
            can_edit_manage = True
        if can_edit_manage:
            final_map = new_map
        else:
            final_map = {}
            for user, perms in new_map.items():
                base = current_map.get(user, set())
                merged = set(perms)
                if "manage" in base:
                    merged.add("manage")
                else:
                    merged.discard("manage")
                final_map[user] = merged
        parts = []
        for user, perms in final_map.items():
            if perms:
                parts.append(user + ":" + ",".join(sorted(perms)))
        stored = ";".join(parts)
        conn.execute("UPDATE file_acl SET shared_with = ? WHERE path = ?", (stored, path))
    return "OK", 200

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    username = session.get("user")
    subpath = request.form.get("path", "")
    if "upload" not in get_file_permissions(subpath, username): abort(403)
    file = request.files["file"]
    rel_name = request.form.get("webkitRelativePath", "") or file.filename
    target_path = safe_join(SHARED_FOLDER, subpath, rel_name)
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    file.save(target_path)
    rel_db_path = os.path.relpath(target_path, SHARED_FOLDER).replace("\\", "/")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("INSERT OR REPLACE INTO file_acl (path, owner) VALUES (?, ?)", (rel_db_path, username))
    return "OK", 200

@app.route("/download/<path:filename>", methods=["GET"])
@login_required
def download_item(filename):
    if "download" not in get_file_permissions(filename, session.get("user")): abort(403)
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
    username = session.get("user")
    for path in request.get_json().get("paths", []):
        if "manage" in get_file_permissions(path, username):
            full_path = safe_join(SHARED_FOLDER, path)
            if os.path.exists(full_path):
                if os.path.isdir(full_path): shutil.rmtree(full_path)
                else: os.remove(full_path)
                with sqlite3.connect(DB_PATH) as conn: conn.execute("DELETE FROM file_acl WHERE path = ?", (path,))
    return "OK", 200

@app.route("/fs_op", methods=["POST"])
@login_required
def file_system_operation():
    username = session.get("user")
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
                    src, dest_rel = safe_join(SHARED_FOLDER, path), os.path.join(dest_dir, os.path.basename(path)).replace("\\", "/")
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
    username = session.get("user")
    data = request.get_json()
    parent = data.get("path", "")
    if "upload" not in get_file_permissions(parent, username): abort(403)
    new_dir_rel = os.path.join(parent, data.get("dirname", "")).replace("\\", "/")
    os.makedirs(safe_join(SHARED_FOLDER, new_dir_rel), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn: conn.execute("INSERT OR REPLACE INTO file_acl (path, owner) VALUES (?, ?)", (new_dir_rel, username))
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
    user_id, new_role = data.get("id"), data.get("role")
    perms_list = data.get("permissions", [])
    filtered = []
    for p in perms_list:
        if p in ("upload", "chat", "chat_manage"):
            filtered.append(p)
    new_perms = ",".join(filtered)
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
