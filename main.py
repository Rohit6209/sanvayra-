import os, re, json, math, time, hmac, uuid, hashlib, secrets, sqlite3, urllib.request
from collections import Counter
import jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Header, Body
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE = os.path.dirname(os.path.abspath(__file__))
DB, UP, STATIC = os.path.join(BASE, "sanvyra.db"), os.path.join(BASE, "uploads"), os.path.join(BASE, "static")
SECRET = os.getenv("SECRET", "change-this-secret")
GK, GM = os.getenv("GEMINI_API_KEY", ""), os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
os.makedirs(UP, exist_ok=True)
app = FastAPI(title="Sanvyra")

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def q(sql, a=(), one=False):
    c = db()
    try:
        r = [dict(x) for x in c.execute(sql, a).fetchall()]
    finally: c.close()
    return (r[0] if r else None) if one else r
def ex(sql, a=()):
    c = db()
    try:
        cur = c.execute(sql, a); c.commit(); return cur.lastrowid
    finally: c.close()

def init():
    c = db()
    c.executescript("""
    create table if not exists users(id integer primary key autoincrement,name text,email text unique,password text,
      role text,branch text,year integer,semester integer,employee_id text,enrollment_no text,is_active integer default 1,
      reset_token text,created_at text default current_timestamp);
    create table if not exists subjects(id integer primary key autoincrement,subject_name text,subject_code text unique,
      branch text,semester integer,created_by integer,created_at text default current_timestamp);
    create table if not exists teacher_subjects(id integer primary key autoincrement,teacher_id integer references users(id) on delete cascade,
      subject_id integer references subjects(id) on delete cascade,assigned_at text default current_timestamp,unique(teacher_id,subject_id));
    create table if not exists documents(id integer primary key autoincrement,title text,description text,file_path text,file_type text,
      document_type text,subject_id integer references subjects(id) on delete set null,branch text,semester integer,uploaded_by integer,
      created_at text default current_timestamp);
    create table if not exists chunks(id integer primary key autoincrement,doc_id integer references documents(id) on delete cascade,
      title text,page integer,branch text,semester integer,text text);
    create table if not exists chat_history(id integer primary key autoincrement,user_id integer,question text,answer text,sources text,
      created_at text default current_timestamp);""")
    c.commit(); c.close()
    if not q("select 1 from users where role='hod'"):
        ex("insert into users(name,email,password,role) values(?,?,?,'hod')",
           ("HOD", os.getenv("HOD_EMAIL", "hod@sanvyra.com"), hp(os.getenv("HOD_PASSWORD", "admin123"))))

def hp(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100000).hex()
def vp(p, h): return hmac.compare_digest(hp(p, h.split("$")[0]), h)
init()

def me(authorization: str = Header(None)):
    try: d = jwt.decode((authorization or "").replace("Bearer ", ""), SECRET, algorithms=["HS256"])
    except Exception: raise HTTPException(401, "Login required")
    u = q("select * from users where id=?", (int(d["sub"]),), one=True)
    if not u or not u["is_active"]: raise HTTPException(401, "Account inactive or missing")
    return u
def need(*roles):
    def f(u=Depends(me)):
        if u["role"] not in roles: raise HTTPException(403, "Not allowed")
        return u
    return f
def pub(u): return {k: u[k] for k in ("id", "name", "email", "role", "branch", "year", "semester", "employee_id", "enrollment_no", "is_active")}
def need_fields(d, *f):
    for k in f:
        if not str(d.get(k) or "").strip(): raise HTTPException(400, f"{k} is required")

# ---------- auth ----------
@app.post("/api/register")
def register(d: dict = Body(...)):
    need_fields(d, "name", "email", "password", "branch", "year", "semester")
    if q("select 1 from users where email=?", (d["email"].lower(),)): raise HTTPException(400, "Email already registered")
    ex("insert into users(name,email,password,role,branch,year,semester,enrollment_no) values(?,?,?,'student',?,?,?,?)",
       (d["name"], d["email"].lower(), hp(d["password"]), d["branch"], int(d["year"]), int(d["semester"]), d.get("enrollment_no")))
    return {"ok": True}
@app.post("/api/login")
def login(d: dict = Body(...)):
    u = q("select * from users where email=?", ((d.get("email") or "").lower(),), one=True)
    if not u or not vp(d.get("password") or "", u["password"]): raise HTTPException(401, "Wrong email or password")
    if not u["is_active"]: raise HTTPException(403, "Account blocked")
    return {"token": jwt.encode({"sub": str(u["id"]), "exp": time.time() + 3 * 86400}, SECRET, "HS256"), "user": pub(u)}
@app.post("/api/forgot-password")
def forgot(d: dict = Body(...)):
    u = q("select id from users where email=?", ((d.get("email") or "").lower(),), one=True)
    if u:
        t = secrets.token_urlsafe(8); ex("update users set reset_token=? where id=?", (t, u["id"]))
        print(f"[RESET TOKEN for {d['email']}]: {t}")  # plug email/SMS sending here
    return {"message": "If the email exists, a reset token was generated (see server console)."}
@app.post("/api/reset-password")
def reset(d: dict = Body(...)):
    need_fields(d, "token", "new_password")
    u = q("select id from users where reset_token=?", (d["token"],), one=True)
    if not u: raise HTTPException(400, "Invalid token")
    ex("update users set password=?,reset_token=null where id=?", (hp(d["new_password"]), u["id"])); return {"ok": True}
@app.get("/api/me")
def get_me(u=Depends(me)): return pub(u)
@app.put("/api/me")
def upd_me(d: dict = Body(...), u=Depends(me)):
    if d.get("name"): ex("update users set name=? where id=?", (d["name"], u["id"]))
    if d.get("password"): ex("update users set password=? where id=?", (hp(d["password"]), u["id"]))
    return pub(q("select * from users where id=?", (u["id"],), one=True))

@app.get("/api/stats")
def stats(u=Depends(me)):
    n = lambda s, a=(): q(s, a, one=True)["n"]
    if u["role"] == "hod":
        return {"teachers": n("select count(*) n from users where role='teacher'"), "students": n("select count(*) n from users where role='student'"),
                "documents": n("select count(*) n from documents"), "subjects": n("select count(*) n from subjects")}
    if u["role"] == "teacher":
        return {"my subjects": n("select count(*) n from teacher_subjects where teacher_id=?", (u["id"],)),
                "my uploads": n("select count(*) n from documents where uploaded_by=?", (u["id"],))}
    return {"materials": n("select count(*) n from documents where branch=? and semester=?", (u["branch"], u["semester"]))}

# ---------- HOD: teachers / subjects / students ----------
def set_subs(tid, ids):
    ex("delete from teacher_subjects where teacher_id=?", (tid,))
    for s in ids or []: ex("insert or ignore into teacher_subjects(teacher_id,subject_id) values(?,?)", (tid, int(s)))
@app.get("/api/teachers")
def teachers(u=Depends(need("hod"))):
    t = q("select id,name,email,employee_id,is_active from users where role='teacher' order by id desc")
    for x in t:
        s = q("select s.id,s.subject_name from subjects s join teacher_subjects ts on ts.subject_id=s.id where ts.teacher_id=?", (x["id"],))
        x["subject_ids"] = [i["id"] for i in s]; x["subjects"] = ", ".join(i["subject_name"] for i in s)
    return t
@app.post("/api/teachers")
def add_teacher(d: dict = Body(...), u=Depends(need("hod"))):
    need_fields(d, "name", "email", "password")
    if q("select 1 from users where email=?", (d["email"].lower(),)): raise HTTPException(400, "Email already exists")
    tid = ex("insert into users(name,email,password,role,employee_id) values(?,?,?,'teacher',?)", (d["name"], d["email"].lower(), hp(d["password"]), d.get("employee_id")))
    set_subs(tid, d.get("subject_ids")); return {"id": tid}
@app.put("/api/teachers/{tid}")
def edit_teacher(tid: int, d: dict = Body(...), u=Depends(need("hod"))):
    ex("update users set name=?,email=?,employee_id=? where id=? and role='teacher'", (d.get("name"), (d.get("email") or "").lower(), d.get("employee_id"), tid))
    if d.get("password"): ex("update users set password=? where id=?", (hp(d["password"]), tid))
    set_subs(tid, d.get("subject_ids")); return {"ok": True}
@app.delete("/api/teachers/{tid}")
def del_teacher(tid: int, u=Depends(need("hod"))):
    ex("delete from users where id=? and role='teacher'", (tid,)); return {"ok": True}

@app.get("/api/subjects")
def subjects(u=Depends(me)):
    if u["role"] == "hod": return q("select * from subjects order by branch,semester,subject_name")
    if u["role"] == "teacher":
        return q("select s.* from subjects s join teacher_subjects ts on ts.subject_id=s.id where ts.teacher_id=?", (u["id"],))
    return q("select * from subjects where branch=? and semester=?", (u["branch"], u["semester"]))
@app.post("/api/subjects")
def add_subject(d: dict = Body(...), u=Depends(need("hod"))):
    need_fields(d, "subject_name", "subject_code", "branch", "semester")
    try: i = ex("insert into subjects(subject_name,subject_code,branch,semester,created_by) values(?,?,?,?,?)",
                (d["subject_name"], d["subject_code"], d["branch"], int(d["semester"]), u["id"]))
    except sqlite3.IntegrityError: raise HTTPException(400, "Subject code already exists")
    return {"id": i}
@app.put("/api/subjects/{sid}")
def edit_subject(sid: int, d: dict = Body(...), u=Depends(need("hod"))):
    ex("update subjects set subject_name=?,subject_code=?,branch=?,semester=? where id=?", (d.get("subject_name"), d.get("subject_code"), d.get("branch"), int(d.get("semester") or 1), sid))
    return {"ok": True}
@app.delete("/api/subjects/{sid}")
def del_subject(sid: int, u=Depends(need("hod"))):
    ex("delete from subjects where id=?", (sid,)); return {"ok": True}

@app.get("/api/students")
def students(u=Depends(need("hod"))):
    return q("select id,name,email,branch,year,semester,enrollment_no,is_active from users where role='student' order by id desc")
@app.post("/api/students/{sid}/status")
def student_status(sid: int, d: dict = Body(...), u=Depends(need("hod"))):
    ex("update users set is_active=? where id=? and role='student'", (1 if d.get("is_active") else 0, sid)); return {"ok": True}

# ---------- documents + RAG indexing ----------
def extract(path, ext):
    try:
        if ext == "pdf":
            from pypdf import PdfReader
            return [(i + 1, p.extract_text() or "") for i, p in enumerate(PdfReader(path).pages)]
        if ext == "docx":
            import docx
            return [(1, "\n".join(p.text for p in docx.Document(path).paragraphs))]
        if ext == "pptx":
            from pptx import Presentation
            return [(i + 1, " ".join(sh.text_frame.text for sh in s.shapes if sh.has_text_frame)) for i, s in enumerate(Presentation(path).slides)]
        if ext in ("txt", "md", "csv"): return [(1, open(path, errors="ignore").read())]
    except Exception as e: print("extract error:", e)
    return []
def chunk(t, n=700, o=100):
    t = re.sub(r"\s+", " ", t).strip()
    return [t[i:i + n] for i in range(0, len(t), n - o)] if t else []
def index(did, path, ext, title, branch, sem):
    c = db()
    try:
        for pg, txt in extract(path, ext):
            for ch in chunk(txt): c.execute("insert into chunks(doc_id,title,page,branch,semester,text) values(?,?,?,?,?,?)", (did, title, pg, branch, sem, ch))
        c.commit()
    finally: c.close()

@app.post("/api/documents")
async def upload(title: str = Form(...), document_type: str = Form(...), description: str = Form(""), subject_id: int = Form(None),
                 branch: str = Form(None), semester: int = Form(None), file: UploadFile = File(...), u=Depends(need("hod", "teacher"))):
    if u["role"] == "teacher":
        if document_type in ("syllabus", "timetable"): raise HTTPException(403, "Only HOD can upload syllabus/timetable")
        if not subject_id or not q("select 1 from teacher_subjects where teacher_id=? and subject_id=?", (u["id"], subject_id)):
            raise HTTPException(403, "You can upload only for your assigned subjects")
    if subject_id:
        s = q("select * from subjects where id=?", (subject_id,), one=True)
        if not s: raise HTTPException(400, "Subject not found")
        branch, semester = s["branch"], s["semester"]
    if not (branch and semester): raise HTTPException(400, "Branch and semester required")
    ext = (file.filename.rsplit(".", 1)[-1] if "." in file.filename else "bin").lower()
    path = os.path.join(UP, uuid.uuid4().hex + "." + ext)
    with open(path, "wb") as f: f.write(await file.read())
    did = ex("insert into documents(title,description,file_path,file_type,document_type,subject_id,branch,semester,uploaded_by) values(?,?,?,?,?,?,?,?,?)",
             (title, description, path, ext, document_type, subject_id, branch, semester, u["id"]))
    index(did, path, ext, title, branch, semester); return {"id": did}
@app.get("/api/documents")
def documents(document_type: str = None, subject_id: int = None, mine: int = 0, limit: int = 500, u=Depends(me)):
    sql = ("select d.id,d.title,d.description,d.file_type,d.document_type,d.branch,d.semester,d.created_at,s.subject_name,x.name uploader "
           "from documents d left join subjects s on s.id=d.subject_id left join users x on x.id=d.uploaded_by where 1=1"); a = []
    if u["role"] == "student": sql += " and d.branch=? and d.semester=?"; a += [u["branch"], u["semester"]]
    if mine or u["role"] == "teacher" and mine: sql += " and d.uploaded_by=?"; a.append(u["id"])
    if document_type: sql += " and d.document_type=?"; a.append(document_type)
    if subject_id: sql += " and d.subject_id=?"; a.append(subject_id)
    return q(sql + " order by d.id desc limit ?", a + [limit])
def can_see(u, d): return u["role"] != "student" or (d["branch"] == u["branch"] and d["semester"] == u["semester"])
@app.get("/api/documents/{did}/download")
def download(did: int, u=Depends(me)):
    d = q("select * from documents where id=?", (did,), one=True)
    if not d or not can_see(u, d): raise HTTPException(404, "Not found")
    return FileResponse(d["file_path"], filename=f"{d['title']}.{d['file_type']}")
@app.delete("/api/documents/{did}")
def del_doc(did: int, u=Depends(need("hod", "teacher"))):
    d = q("select * from documents where id=?", (did,), one=True)
    if not d: raise HTTPException(404, "Not found")
    if u["role"] == "teacher" and d["uploaded_by"] != u["id"]: raise HTTPException(403, "Only your own documents")
    ex("delete from chunks where doc_id=?", (did,)); ex("delete from documents where id=?", (did,))
    try: os.remove(d["file_path"])
    except OSError: pass
    return {"ok": True}

# ---------- RAG chatbot ----------
def tok(s): return re.findall(r"\w+", s.lower())
def retrieve(question, rows, k=5):
    qt, N, df, toks = set(tok(question)), len(rows) or 1, Counter(), []
    for r in rows: t = tok(r["text"]); toks.append(t); df.update(set(t))
    sc = []
    for r, t in zip(rows, toks):
        c = Counter(t); s = sum(math.log(1 + N / df[w]) * c[w] / (c[w] + 1.5) for w in qt if w in c)
        if s > 0: sc.append((s, r))
    return [r for s, r in sorted(sc, key=lambda x: -x[0])[:k]]
def gemini(prompt):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GM}:generateContent?key={GK}"
    req = urllib.request.Request(url, json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=60))["candidates"][0]["content"]["parts"][0]["text"]
@app.post("/api/chat")
def chat(d: dict = Body(...), u=Depends(me)):
    qn = (d.get("question") or "").strip()
    if not qn: raise HTTPException(400, "Question required")
    rows = q("select * from chunks where branch=? and semester=?", (u["branch"], u["semester"])) if u["role"] == "student" else q("select * from chunks")
    top = retrieve(qn, rows)
    if not top: ans, src = "Sorry, I could not find this in the uploaded documents.", []
    else:
        src = list({(r["title"], r["page"]): {"document": r["title"], "page": r["page"]} for r in top}.values())
        ctx = "\n\n".join(f"[{r['title']} p.{r['page']}] {r['text']}" for r in top)
        try:
            if not GK: raise RuntimeError("no key")
            ans = gemini("You are Sanvyra, a college department assistant. Answer ONLY from the context below. If the answer is not there, say so.\n\n"
                         f"Context:\n{ctx}\n\nQuestion: {qn}\nAnswer clearly:")
        except Exception:
            ans = "Most relevant excerpts from documents" + ("" if GK else " (set GEMINI_API_KEY for AI-written answers)") + ":\n\n" + "\n\n".join(f"• {r['text']}" for r in top[:3])
    ex("insert into chat_history(user_id,question,answer,sources) values(?,?,?,?)", (u["id"], qn, ans, json.dumps(src)))
    return {"answer": ans, "sources": src}
@app.get("/api/chat/history")
def history(u=Depends(me)):
    h = q("select question,answer,sources,created_at from chat_history where user_id=? order by id desc limit 30", (u["id"],))
    for x in h: x["sources"] = json.loads(x["sources"] or "[]")
    return h[::-1]

@app.get("/api/stats/chart")
def stats_chart(u=Depends(me)):
    sql, a = "select document_type k,count(*) n from documents", []
    if u["role"] == "student": sql += " where branch=? and semester=?"; a = [u["branch"], u["semester"]]
    elif u["role"] == "teacher": sql += " where uploaded_by=?"; a = [u["id"]]
    return q(sql + " group by document_type", a)

app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
