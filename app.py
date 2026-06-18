import base64, hashlib, hmac, os, secrets, sqlite3, time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

APP_DIR = Path(__file__).parent
DB = APP_DIR / "privmsg.sqlite3"
SESSION_TTL = 60 * 60 * 24 * 7
DEFAULT_ADMIN_PASSWORD = os.environ.get("PRIVMSG_ADMIN_PASSWORD", "change-this-admin-password")

app = FastAPI(title="Wurzen Secure")

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 250_000)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_b64, dk_b64 = stored.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 250_000)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def init_db():
    con = db()
    con.executescript('''
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      approved INTEGER NOT NULL DEFAULT 0,
      disabled INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS invites (
      code TEXT PRIMARY KEY,
      created_by INTEGER,
      used_by INTEGER,
      created_at INTEGER NOT NULL,
      used_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      created_by INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (conversation_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_id INTEGER,
      action TEXT NOT NULL,
      detail TEXT,
      created_at INTEGER NOT NULL
    );
    ''')
    cur = con.execute("SELECT id FROM users WHERE username='admin'")
    if cur.fetchone() is None:
        con.execute("INSERT INTO users(username, display_name, password_hash, role, approved, created_at) VALUES(?,?,?,?,?,?)",
                    ("admin", "Administrator", hash_password(DEFAULT_ADMIN_PASSWORD), "admin", 1, int(time.time())))
    con.commit(); con.close()

init_db()

class Login(BaseModel):
    username: str
    password: str

class Register(BaseModel):
    invite_code: str
    username: str
    display_name: str
    password: str

class ConversationCreate(BaseModel):
    title: str
    member_usernames: list[str]

class MessageCreate(BaseModel):
    conversation_id: int
    ciphertext: str
    iv: str
    salt: str


def get_user(request: Request):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "Missing session")
    con = db()
    row = con.execute('''SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
                         WHERE s.token=? AND s.expires_at>? AND u.disabled=0''', (token, int(time.time()))).fetchone()
    con.close()
    if not row:
        raise HTTPException(401, "Invalid or expired session")
    return dict(row)


def require_admin(user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return user


def audit(actor_id, action, detail=""):
    con = db(); con.execute("INSERT INTO audit_log(actor_id, action, detail, created_at) VALUES(?,?,?,?)", (actor_id, action, detail, int(time.time()))); con.commit(); con.close()

@app.get("/")
def index():
    return FileResponse(APP_DIR / "static" / "index.html")

@app.post("/api/register")
def register(payload: Register):
    con = db()
    inv = con.execute("SELECT * FROM invites WHERE code=? AND used_at IS NULL", (payload.invite_code,)).fetchone()
    if not inv:
        raise HTTPException(400, "Invalid or used invite code")
    if len(payload.password) < 10:
        raise HTTPException(400, "Password must be at least 10 characters")
    try:
        cur = con.execute("INSERT INTO users(username, display_name, password_hash, approved, created_at) VALUES(?,?,?,?,?)",
                          (payload.username.lower().strip(), payload.display_name.strip(), hash_password(payload.password), 0, int(time.time())))
        user_id = cur.lastrowid
        con.execute("UPDATE invites SET used_by=?, used_at=? WHERE code=?", (user_id, int(time.time()), payload.invite_code))
        con.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username already exists")
    finally:
        con.close()
    audit(user_id, "registered", payload.username)
    return {"ok": True, "message": "Account created. Admin approval required before login."}

@app.post("/api/login")
def login(payload: Login):
    con = db()
    u = con.execute("SELECT * FROM users WHERE username=?", (payload.username.lower().strip(),)).fetchone()
    if not u or not verify_password(payload.password, u["password_hash"]):
        raise HTTPException(401, "Bad username or password")
    if not u["approved"] or u["disabled"]:
        raise HTTPException(403, "Account not approved or disabled")
    token = secrets.token_urlsafe(32)
    con.execute("INSERT INTO sessions(token, user_id, expires_at) VALUES(?,?,?)", (token, u["id"], int(time.time()) + SESSION_TTL))
    con.commit(); con.close()
    audit(u["id"], "login", payload.username)
    return {"token": token, "user": {"username": u["username"], "display_name": u["display_name"], "role": u["role"]}}

@app.post("/api/logout")
def logout(request: Request, user=Depends(get_user)):
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    con = db(); con.execute("DELETE FROM sessions WHERE token=?", (token,)); con.commit(); con.close()
    audit(user["id"], "logout", user["username"])
    return {"ok": True}

@app.get("/api/me")
def me(user=Depends(get_user)):
    return {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}

@app.post("/api/admin/invites")
def create_invite(user=Depends(require_admin)):
    code = "WS-" + secrets.token_urlsafe(12)
    con = db(); con.execute("INSERT INTO invites(code, created_by, created_at) VALUES(?,?,?)", (code, user["id"], int(time.time()))); con.commit(); con.close()
    audit(user["id"], "invite_created", code)
    return {"code": code}

@app.get("/api/admin/users")
def admin_users(user=Depends(require_admin)):
    con = db(); rows = con.execute("SELECT id, username, display_name, role, approved, disabled, created_at FROM users ORDER BY created_at DESC").fetchall(); con.close()
    return [dict(r) for r in rows]

@app.post("/api/admin/users/{user_id}/approve")
def approve_user(user_id: int, user=Depends(require_admin)):
    con = db(); con.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,)); con.commit(); con.close()
    audit(user["id"], "user_approved", str(user_id)); return {"ok": True}

@app.post("/api/admin/users/{user_id}/disable")
def disable_user(user_id: int, user=Depends(require_admin)):
    con = db(); con.execute("UPDATE users SET disabled=1 WHERE id=? AND role!='admin'", (user_id,)); con.commit(); con.close()
    audit(user["id"], "user_disabled", str(user_id)); return {"ok": True}

@app.get("/api/users")
def approved_users(user=Depends(get_user)):
    con = db(); rows = con.execute("SELECT username, display_name FROM users WHERE approved=1 AND disabled=0 ORDER BY display_name").fetchall(); con.close()
    return [dict(r) for r in rows]

@app.post("/api/conversations")
def create_conversation(payload: ConversationCreate, user=Depends(get_user)):
    if len(payload.title.strip()) > 80:
        raise HTTPException(400, "Chat title is too long")
    clean_members = [n.lower().strip() for n in payload.member_usernames if n.strip()]
    if len(clean_members) > 25:
        raise HTTPException(400, "Maximum 25 members per chat in this MVP")
    names = set(clean_members + [user["username"]])
    con = db()
    rows = con.execute(f"SELECT id, username FROM users WHERE approved=1 AND disabled=0 AND username IN ({','.join(['?']*len(names))})", tuple(names)).fetchall()
    if len(rows) != len(names):
        raise HTTPException(400, "One or more users are not approved")
    cur = con.execute("INSERT INTO conversations(title, created_by, created_at) VALUES(?,?,?)", (payload.title.strip() or "Private chat", user["id"], int(time.time())))
    cid = cur.lastrowid
    for r in rows:
        con.execute("INSERT INTO conversation_members(conversation_id, user_id) VALUES(?,?)", (cid, r["id"]))
    con.commit(); con.close(); audit(user["id"], "conversation_created", str(cid))
    return {"id": cid}

@app.get("/api/conversations")
def list_conversations(user=Depends(get_user)):
    con = db(); rows = con.execute('''SELECT c.id, c.title, c.created_at FROM conversations c
      JOIN conversation_members m ON m.conversation_id=c.id WHERE m.user_id=? ORDER BY c.created_at DESC''', (user["id"],)).fetchall(); con.close()
    return [dict(r) for r in rows]

@app.get("/api/conversations/{conversation_id}/messages")
def get_messages(conversation_id: int, user=Depends(get_user)):
    con = db()
    member = con.execute("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?", (conversation_id, user["id"])).fetchone()
    if not member: raise HTTPException(403, "Not a member")
    rows = con.execute('''SELECT m.id, m.ciphertext, m.iv, m.salt, m.created_at, u.display_name AS sender, u.username AS sender_username
      FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=? ORDER BY m.id ASC''', (conversation_id,)).fetchall(); con.close()
    return [dict(r) for r in rows]

@app.post("/api/messages")
def send_message(payload: MessageCreate, user=Depends(get_user)):
    if not payload.ciphertext or not payload.iv or not payload.salt:
        raise HTTPException(400, "Invalid encrypted payload")
    if len(payload.ciphertext) > 20000:
        raise HTTPException(400, "Message is too large for this MVP")
    con = db()
    member = con.execute("SELECT 1 FROM conversation_members WHERE conversation_id=? AND user_id=?", (payload.conversation_id, user["id"])).fetchone()
    if not member: raise HTTPException(403, "Not a member")
    con.execute("INSERT INTO messages(conversation_id, sender_id, ciphertext, iv, salt, created_at) VALUES(?,?,?,?,?,?)",
                (payload.conversation_id, user["id"], payload.ciphertext, payload.iv, payload.salt, int(time.time())))
    con.commit(); con.close()
    return {"ok": True}

@app.get("/api/audit")
def get_audit(user=Depends(require_admin)):
    con = db(); rows = con.execute('''SELECT a.action, a.detail, a.created_at, u.username AS actor FROM audit_log a
      LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 100''').fetchall(); con.close()
    return [dict(r) for r in rows]
