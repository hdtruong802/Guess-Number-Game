from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
import sqlite3, bcrypt, random, jwt, time, threading, os
from fastapi.middleware.cors import CORSMiddleware
from email.message import EmailMessage
import smtplib
from typing import Optional

# ---------------------------
# Configuration
# ---------------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-please-change")
REFRESH_SECRET = os.getenv("REFRESH_SECRET", "dev-refresh-secret-please-change")
ACCESS_EXPIRE_SECONDS = int(os.getenv("ACCESS_EXPIRE_SECONDS", str(60 * 15)))   # 15 min
REFRESH_EXPIRE_SECONDS = int(os.getenv("REFRESH_EXPIRE_SECONDS", str(60 * 60 * 24 * 7)))  # 7 days

# Rate limiting
RATE_WINDOW = 60 * 5   # 5 minutes
MAX_REQUESTS_PER_WINDOW = 200

# Login brute-force
MAX_LOGIN_FAIL = 5
LOCK_SECONDS = 300  # 5 minutes

# SMTP
GMAIL_USER = os.getenv("GMAIL_USER", "your@gmail.com")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD", "your_token")

DB_FILE = os.getenv("DB_FILE", "server_database.db")

# ---------------------------
# Helpers: DB
# ---------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    return conn, conn.cursor()

# Initialize DB tables
conn, cur = get_db()
cur.executescript("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    scores INTEGER DEFAULT 0,
    turns INTEGER DEFAULT 5,
    login_fail INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
""")
conn.commit()
conn.close()

# ---------------------------
# Email sending
# ---------------------------
def send_email(to_email: str, subject: str, body: str):
    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = GMAIL_USER
    msg['To'] = to_email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        print("send_email error:", e)

# ---------------------------
# JWT helpers
# ---------------------------
def create_access_token(username: str):
    now = int(time.time())
    exp = now + ACCESS_EXPIRE_SECONDS
    # jti for blacklist
    jti = os.urandom(8).hex()
    payload = {"username": username, "exp": exp, "iat": now, "jti": jti}
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, jti, exp

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token expired")
    except jwt.DecodeError:
        raise HTTPException(status_code=401, detail="Access token invalid")
    except Exception:
        raise HTTPException(status_code=401, detail="Access token invalid")

def create_refresh_token(username: str):
    now = int(time.time())
    exp = now + REFRESH_EXPIRE_SECONDS
    token = os.urandom(32).hex()  # opaque refresh token
    return token, exp

# Persist refresh token
def save_refresh_token(token: str, username: str, expires_at: int):
    conn, cur = get_db()
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("INSERT OR REPLACE INTO refresh_tokens (token, username, expires_at) VALUES (?, ?, ?)",
                    (token, username, expires_at))
        conn.commit()
    finally:
        conn.close()

def revoke_refresh_token(token: str):
    conn, cur = get_db()
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("DELETE FROM refresh_tokens WHERE token=?", (token,))
        conn.commit()
    finally:
        conn.close()

def is_refresh_token_valid(token: str) -> Optional[str]:
    conn, cur = get_db()
    try:
        cur.execute("SELECT username, expires_at FROM refresh_tokens WHERE token=?", (token,))
        row = cur.fetchone()
        if not row:
            return None
        username, expires_at = row
        if expires_at < int(time.time()):
            # expired: remove
            conn2, cur2 = get_db()
            cur2.execute("DELETE FROM refresh_tokens WHERE token=?", (token,))
            conn2.commit()
            conn2.close()
            return None
        return username
    finally:
        conn.close()

# Blacklist jti
def blacklist_jti(jti: str, expires_at: int):
    conn, cur = get_db()
    try:
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("INSERT OR REPLACE INTO token_blacklist (jti, expires_at) VALUES (?, ?)", (jti, expires_at))
        conn.commit()
    finally:
        conn.close()

def is_jti_blacklisted(jti: str) -> bool:
    conn, cur = get_db()
    try:
        cur.execute("SELECT 1 FROM token_blacklist WHERE jti=? AND expires_at>?", (jti, int(time.time())))
        return cur.fetchone() is not None
    finally:
        conn.close()

# ---------------------------
# Rate-limit (in-memory)
# ---------------------------
RATE_STORE = {}  # ip -> [timestamps]

def check_rate_limit(ip: str):
    now = int(time.time())
    window = RATE_WINDOW
    logs = [t for t in RATE_STORE.get(ip, []) if now - t < window]
    logs.append(now)
    RATE_STORE[ip] = logs
    if len(logs) > MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(status_code=429, detail="Too many requests from this IP. Try later.")

# ---------------------------
# Per-user lock to avoid race
# ---------------------------
_user_locks = {}
_user_locks_lock = threading.Lock()

def get_user_lock(username: str):
    with _user_locks_lock:
        lock = _user_locks.get(username)
        if not lock:
            lock = threading.Lock()
            _user_locks[username] = lock
        return lock


# ---------------------------
# Pydantic models
# ---------------------------
class RegisterModel(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginModel(BaseModel):
    username: str
    password: str

class GuessModel(BaseModel):
    guess: int

class RefreshModel(BaseModel):
    refresh_token: str

class DeleteModel(BaseModel):
    password: str

# ---------------------------
# FastAPI app + exception handler
# ---------------------------
app = FastAPI(title="Secure Guess Game API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # Return JSON for any unhandled exception
    msg = str(exc)
    return JSONResponse(status_code=500, content={"detail": f"Internal server error: {msg}"})

# ---------------------------
# Auth dependency
# ---------------------------
def get_current_username(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = authorization.split(" ", 1)[1].strip()
    payload = decode_access_token(token)
    jti = payload.get("jti")
    if is_jti_blacklisted(jti):
        raise HTTPException(status_code=401, detail="Token revoked")
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Token missing username")
    return username

# ---------------------------
# Endpoints
# ---------------------------

@app.post("/register")
def register(user: RegisterModel, background_tasks: BackgroundTasks):
    conn, cur = get_db()
    try:
        password_hash = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("INSERT INTO users (username, email, password_hash, scores, turns) VALUES (?, ?, ?, 0, 5)",
                        (user.username, user.email, password_hash))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            raise HTTPException(status_code=400, detail="Username already exists")
        # send welcome email async
        background_tasks.add_task(send_email, user.email, "Successfully registered an account", f"Welcome {user.username} to Guess Number Game!")
        return {"status": "ok"}
    finally:
        conn.close()

@app.post("/login")
def login(data: LoginModel, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)

    conn, cur = get_db()
    try:
        cur.execute("SELECT password_hash, login_fail, locked_until FROM users WHERE username=?", (data.username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=400, detail="User not found")
        stored_hash, fail_count, locked_until = row
        now = int(time.time())
        if locked_until and locked_until > now:
            raise HTTPException(status_code=403, detail=f"Account locked. Try again later.")

        if bcrypt.checkpw(data.password.encode(), stored_hash.encode()):
            # reset fail counters
            cur.execute("UPDATE users SET login_fail=0, locked_until=0 WHERE username=?", (data.username,))
            conn.commit()
            access_token, jti, exp = create_access_token(data.username)
            refresh_token, refresh_exp = create_refresh_token(data.username)
            save_refresh_token(refresh_token, data.username, refresh_exp)
            return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
        else:
            fail_count = (fail_count or 0) + 1
            if fail_count >= MAX_LOGIN_FAIL:
                locked_until = int(time.time()) + LOCK_SECONDS
                cur.execute("UPDATE users SET login_fail=?, locked_until=? WHERE username=?", (fail_count, locked_until, data.username))
                conn.commit()
                raise HTTPException(status_code=403, detail="Account locked due to too many failed attempts")
            else:
                cur.execute("UPDATE users SET login_fail=? WHERE username=?", (fail_count, data.username))
                conn.commit()
                raise HTTPException(status_code=401, detail=f"Incorrect password ({fail_count}/{MAX_LOGIN_FAIL})")
    finally:
        conn.close()

@app.post("/token/refresh")
def refresh_token(data: RefreshModel):
    username = is_refresh_token_valid(data.refresh_token)
    if not username:
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")
    # create new access token
    access_token, jti, exp = create_access_token(username)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout")
def logout(data: RefreshModel, authorization: Optional[str] = Header(None)):
    # revoke refresh token and blacklist access jti if present
    if authorization and authorization.startswith("Bearer "):
        access_token = authorization.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=["HS256"])
            jti = payload.get("jti")
            exp = payload.get("exp", int(time.time()))
            if jti:
                blacklist_jti(jti, exp)
        except Exception:
            pass
    # revoke refresh token
    revoke_refresh_token(data.refresh_token)
    return {"status": "ok"}

@app.get("/user")
def get_user_data(username: str = Depends(get_current_username)):
    conn, cur = get_db()
    try:
        cur.execute("SELECT scores, turns FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        scores, turns = row
        return {"scores": scores, "turns": turns}
    finally:
        conn.close()

@app.post("/guess")
def guess_endpoint(data: GuessModel, background_tasks: BackgroundTasks, username: str = Depends(get_current_username)):
    if not (1 <= data.guess <= 5):
        raise HTTPException(status_code=400, detail="Guess must be between 1 and 5")

    user_lock = get_user_lock(username)
    acquired = user_lock.acquire(timeout=2.0)
    if not acquired:
        raise HTTPException(status_code=429, detail="Too many concurrent requests for this user")

    conn = None
    try:
        conn, cur = get_db()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT scores, turns, email FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="User not found")
        scores, turns, email = row
        if turns <= 0:
            conn.rollback()
            return {"result": "No turns left", "scores": scores, "turns": turns, "system": None}

        turns -= 1

        # Win rate 5%
        if random.random() < 0.05:      # ~5% 
            system_num = data.guess     # User win
        else:
            # 95% user lose
            system_num = random.randint(1, 5)
            while system_num == data.guess:
                system_num = random.randint(1, 5)

        # Result
        if data.guess == system_num:
            scores += 1
            result_status = "Correct"
        else:
            result_status = "Wrong"

        cur.execute("UPDATE users SET scores=?, turns=? WHERE username=?", (scores, turns, username))
        conn.commit()

        # notify (async)
        background_tasks.add_task(send_email, email, "Guess result", f"Hi {username}, score: {scores}, turns: {turns}")

        return {"result": result_status, "scores": scores, "turns": turns, "system": system_num}
    except sqlite3.OperationalError as e:
        if conn:
            try:
                conn.rollback()
            except:
                pass
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        if conn:
            conn.close()
        user_lock.release()

@app.post("/buy-turns")
def buy_turns(background_tasks: BackgroundTasks, username: str = Depends(get_current_username)):
    user_lock = get_user_lock(username)
    acquired = user_lock.acquire(timeout=2.0)
    if not acquired:
        raise HTTPException(status_code=429, detail="Too many concurrent requests for this user")

    conn = None
    try:
        conn, cur = get_db()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT email, scores, turns FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="User not found")
        email, scores, turns = row
        turns += 5
        cur.execute("UPDATE users SET turns=? WHERE username=?", (turns, username))
        conn.commit()
        background_tasks.add_task(send_email, email, "Purchase successful", f"Hi {username}, turns: {turns}")
        return {"scores": scores, "turns": turns}
    finally:
        if conn:
            conn.close()
        user_lock.release()

@app.delete("/delete")
def delete_account(data: DeleteModel, username: str = Depends(get_current_username)):
    user_lock = get_user_lock(username)
    acquired = user_lock.acquire(timeout=2.0)
    if not acquired:
        raise HTTPException(status_code=429, detail="Too many concurrent requests for this user")

    conn = None
    try:
        conn, cur = get_db()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="User not found")
        stored_hash = row[0]
        if not bcrypt.checkpw(data.password.encode(), stored_hash.encode()):
            conn.rollback()
            raise HTTPException(status_code=401, detail="Incorrect password")
        cur.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
        return {"status": "deleted"}
    finally:
        if conn:
            conn.close()
        user_lock.release()

@app.get("/leaderboard")
def leaderboard():
    conn, cur = get_db()
    try:
        cur.execute("SELECT username, scores FROM users ORDER BY scores DESC LIMIT 10")
        rows = cur.fetchall()
        return [{"username": r[0], "scores": r[1]} for r in rows]
    finally:
        conn.close()
