# app/main.py
import os
import uuid
import shutil
import subprocess
import zipfile
import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple
import ssl
import certifi
import httpx

import fitz  # PyMuPDF
from PIL import Image
from PyPDF2 import PdfReader, PdfWriter

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from passlib.context import CryptContext
from itsdangerous import URLSafeSerializer, URLSafeTimedSerializer, BadSignature, SignatureExpired

import aiosmtplib
from email.message import EmailMessage


# ----------------------------
# Paths
# ----------------------------
BASE_DIR = Path(__file__).resolve().parent  # .../app
STATIC_DIR = BASE_DIR / "static"

PROJECT_ROOT = BASE_DIR.parent  # repo root
UPLOAD_DIR = PROJECT_ROOT / "uploads"
OUTPUT_DIR = PROJECT_ROOT / "outputs"
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "users.db"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------
# App
# ----------------------------
app = FastAPI(title="PDF Tools")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

ALLOWED_OFFICE_EXT = {".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx"}  # NOTE: .key not supported on Railway
ALLOWED_IMAGE_EXT = {".jpg", ".jpeg", ".png", ".webp"}

# ✅ Railway-safe upload limit
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "25"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024


# ----------------------------
# AUTH (Python 3.13 safe)
# ----------------------------
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-change-me")
COOKIE_NAME = "session"  # matches your frontend logic

session_serializer = URLSafeSerializer(SECRET_KEY, salt="pdf-tools-session")
reset_serializer = URLSafeTimedSerializer(SECRET_KEY, salt="pdf-tools-reset")

RESET_TOKEN_MAX_AGE_SECONDS = 30 * 60  # 30 minutes

# ✅ cookie secure flag (Railway is HTTPS)
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
# Tip: set COOKIE_SECURE=true in Railway Variables


# ----------------------------
# SMTP (Gmail)
# ----------------------------
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@example.com")

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")

async def send_email(to_email: str, subject: str, html: str, text: Optional[str] = None) -> None:
    if not BREVO_API_KEY:
        raise RuntimeError("BREVO_API_KEY not set")

    if text is None:
        text = "Open this email in an HTML-capable client to view the message."

    # Parse "Name <email>" from SMTP_FROM
    from_name = "PDF Tools"
    from_email = SMTP_FROM
    if "<" in SMTP_FROM and ">" in SMTP_FROM:
        from_name = SMTP_FROM.split("<", 1)[0].strip()
        from_email = SMTP_FROM.split("<", 1)[1].split(">", 1)[0].strip()

    payload = {
        "sender": {"name": from_name, "email": from_email},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html,
        "textContent": text,
    }

    headers = {
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
        "accept": "application/json",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post("https://api.brevo.com/v3/smtp/email", json=payload, headers=headers)

    if r.status_code >= 400:
        raise RuntimeError(f"Brevo API error {r.status_code}: {r.text}")


# ----------------------------
# DB
# ----------------------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()
    conn.close()


@app.on_event("startup")
def on_startup():
    init_db()


# ----------------------------
# Auth helpers
# ----------------------------
def validate_password(password: str):
    if not password or len(password) < 6:
        raise HTTPException(400, "Password must be at least 6 characters")
    if len(password) > 200:
        raise HTTPException(400, "Password too long (max 200 characters)")


def hash_password(password: str) -> str:
    validate_password(password)
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_session(email: str) -> str:
    return session_serializer.dumps({"email": email})


def read_session(token: str) -> Optional[str]:
    try:
        data = session_serializer.loads(token)
        return data.get("email")
    except BadSignature:
        return None


def get_current_user_email(request: Request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return read_session(token)


def create_reset_token(email: str) -> str:
    return reset_serializer.dumps({"email": email})


def read_reset_token(token: str, max_age_seconds: int = RESET_TOKEN_MAX_AGE_SECONDS) -> Optional[str]:
    try:
        data = reset_serializer.loads(token, max_age=max_age_seconds)
        return data.get("email")
    except (BadSignature, SignatureExpired):
        return None


# ----------------------------
# Static HTML serving
# ----------------------------
def serve_static_html(filename: str):
    p = STATIC_DIR / filename
    if not p.exists():
        return JSONResponse(status_code=404, content={"error": f"{filename} not found"})
    return FileResponse(str(p), media_type="text/html")


# ----------------------------
# Health
# ----------------------------
@app.get("/health")
def health():
    return {"ok": True, "max_upload_mb": MAX_UPLOAD_MB}


# ----------------------------
# UI Routes
# ----------------------------
@app.get("/")
def home():
    return serve_static_html("index.html")


@app.get("/tool/office-to-pdf")
def office_page():
    return serve_static_html("office.html")


@app.get("/tool/jpg-to-pdf")
def jpg_page():
    return serve_static_html("jpg.html")


@app.get("/tool/compress-pdf")
def compress_page():
    return serve_static_html("compress.html")


@app.get("/tool/to-png")
def to_png_page():
    return serve_static_html("png.html")


@app.get("/tool/merge-pdf")
def merge_page():
    return serve_static_html("merge.html")


@app.get("/tool/split-pdf")
def split_page():
    return serve_static_html("split.html")


# ----------------------------
# AUTH UI Routes
# ----------------------------
@app.get("/auth/login")
def login_page():
    return serve_static_html("login.html")


@app.get("/auth/signup")
def signup_page():
    return serve_static_html("signup.html")


@app.get("/auth/forgot")
def forgot_page():
    return serve_static_html("forgot.html")


@app.get("/auth/reset")
def reset_page():
    return serve_static_html("reset.html")


# Support GET and POST logout (your index uses POST)
@app.get("/auth/logout")
@app.post("/auth/logout")
def logout():
    res = RedirectResponse("/", status_code=302)
    res.delete_cookie(COOKIE_NAME, path="/")
    return res


# Frontend checks login state here
@app.get("/auth/me")
def auth_me(request: Request):
    email = get_current_user_email(request)
    return {"logged_in": bool(email), "email": email}


@app.get("/dashboard")
def dashboard(request: Request):
    email = get_current_user_email(request)
    if not email:
        return RedirectResponse("/auth/login", status_code=302)

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <title>Dashboard</title>
      <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen bg-gradient-to-br from-indigo-600 via-purple-600 to-fuchsia-600 text-white">
      <div class="max-w-3xl mx-auto p-6">
        <div class="bg-white/10 border border-white/20 backdrop-blur-xl rounded-3xl p-6 shadow-2xl">
          <div class="flex items-center justify-between">
            <h1 class="text-2xl font-black">Dashboard</h1>
            <form action="/auth/logout" method="post">
              <button class="px-4 py-2 rounded-xl bg-white/20 border border-white/20 font-semibold">Logout</button>
            </form>
          </div>
          <p class="mt-4 text-white/80">Signed in as:</p>
          <p class="text-lg font-extrabold">{email}</p>
          <div class="mt-6">
            <a href="/" class="underline text-white/90">← Back to tools</a>
          </div>
        </div>
      </div>
    </body>
    </html>
    """
    return HTMLResponse(html)


# ----------------------------
# AUTH APIs
# ----------------------------
@app.post("/auth/signup")
def signup(email: str = Form(...), password: str = Form(...)):
    email = (email or "").strip().lower()
    validate_password(password)

    conn = db()
    try:
        conn.execute(
            "INSERT INTO users(email, password_hash) VALUES (?, ?)",
            (email, hash_password(password)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Email already exists")
    finally:
        conn.close()

    token = create_session(email)
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return res


@app.post("/auth/login")
def login(email: str = Form(...), password: str = Form(...)):
    email = (email or "").strip().lower()

    conn = db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if not row or not verify_password(password, row["password_hash"]):
        raise HTTPException(400, "Invalid email or password")

    token = create_session(email)
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return res


@app.post("/auth/forgot")
async def forgot_password(email: str = Form(...), request: Request = None):
    """
    Sends a reset email if the user exists.
    Always returns ok message (no email enumeration).
    """
    email = (email or "").strip().lower()

    conn = db()
    row = conn.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone()
    conn.close()

    if row:
        token = create_reset_token(email)
        base = str(request.base_url).rstrip("/") if request else ""
        reset_link = f"{base}/auth/reset?token={token}" if base else f"/auth/reset?token={token}"

        subject = "Reset your PDF Tools password"
        html = f"""
        <div style="font-family:Arial,sans-serif;line-height:1.6">
          <h2>Reset your password</h2>
          <p>We received a request to reset your password.</p>
          <p>
            <a href="{reset_link}" style="display:inline-block;padding:10px 14px;background:#111827;color:#fff;text-decoration:none;border-radius:10px">
              Reset Password
            </a>
          </p>
          <p style="color:#6b7280;font-size:12px">This link expires in 30 minutes.</p>
          <p style="color:#6b7280;font-size:12px">If you didn't request this, you can ignore this email.</p>
        </div>
        """
        text = f"Reset your password (expires in 30 minutes): {reset_link}"

        try:
            await send_email(email, subject, html, text=text)
        except Exception as e:
            print("EMAIL_SEND_FAILED:", repr(e))

    return JSONResponse({"ok": True, "message": "If this email exists, a reset link has been sent."})


@app.post("/auth/reset")
def reset_password(token: str = Form(...), password: str = Form(...)):
    validate_password(password)

    email = read_reset_token(token, max_age_seconds=RESET_TOKEN_MAX_AGE_SECONDS)
    if not email:
        raise HTTPException(400, "Reset link is invalid or expired")

    conn = db()
    row = conn.execute("SELECT email FROM users WHERE email=?", (email,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(400, "Reset link is invalid or expired")

    conn.execute(
        "UPDATE users SET password_hash=? WHERE email=?",
        (hash_password(password), email),
    )
    conn.commit()
    conn.close()

    return JSONResponse({"ok": True, "message": "Password updated. You can sign in now."})


# ----------------------------
# Upload limit helpers (✅ 25MB enforced)
# ----------------------------
def _http_413(msg: str):
    raise HTTPException(status_code=413, detail=msg)


async def save_upload_limited(file: UploadFile, dst: Path, max_bytes: int) -> int:
    """
    Streams UploadFile to disk and enforces max size while writing.
    Returns written byte count.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    try:
        with dst.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB chunks
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    try:
                        out.close()
                    except Exception:
                        pass
                    try:
                        if dst.exists():
                            dst.unlink()
                    except Exception:
                        pass
                    _http_413(f"File too large. Max allowed is {MAX_UPLOAD_MB}MB.")
                out.write(chunk)
    finally:
        try:
            await file.close()
        except Exception:
            pass

    return total


def ensure_total_under_limit(current_total: int, add_bytes: int, max_bytes: int):
    if current_total + add_bytes > max_bytes:
        _http_413(f"Total upload too large. Max allowed is {MAX_UPLOAD_MB}MB.")


# ----------------------------
# Tool Helpers
# ----------------------------
def convert_office_to_pdf(input_path: Path, out_dir: Path) -> Path:
    input_path = input_path.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "soffice",
        "--headless",
        "--nologo",
        "--nolockcheck",
        "--nodefault",
        "--nofirststartwizard",
        "--convert-to", "pdf",
        "--outdir", str(out_dir),
        str(input_path),
    ]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or p.stdout or "LibreOffice conversion failed")

    expected = out_dir / f"{input_path.stem}.pdf"
    if expected.exists():
        return expected

    pdfs = sorted(out_dir.glob("*.pdf"), key=lambda x: x.stat().st_mtime, reverse=True)
    if not pdfs:
        raise RuntimeError("No PDF produced by LibreOffice")
    return pdfs[0]


def images_to_pdf(image_paths: List[Path], out_pdf: Path) -> Path:
    if not image_paths:
        raise RuntimeError("No images to convert")

    out_pdf.parent.mkdir(parents=True, exist_ok=True)

    pil_images = []
    for p in image_paths:
        img = Image.open(p)
        if img.mode in ("RGBA", "P", "LA"):
            img = img.convert("RGB")
        elif img.mode != "RGB":
            img = img.convert("RGB")
        pil_images.append(img)

    first, rest = pil_images[0], pil_images[1:]
    first.save(out_pdf, "PDF", save_all=True, append_images=rest)

    for im in pil_images:
        try:
            im.close()
        except Exception:
            pass

    if not out_pdf.exists():
        raise RuntimeError("Failed to create PDF")
    return out_pdf


def compress_pdf_gs(input_pdf: Path, out_pdf: Path, preset: str = "ebook") -> Path:
    input_pdf = input_pdf.resolve()
    out_pdf = out_pdf.resolve()
    out_pdf.parent.mkdir(parents=True, exist_ok=True)

    preset_map = {
        "screen": "/screen",
        "ebook": "/ebook",
        "printer": "/printer",
        "prepress": "/prepress",
    }
    gs_preset = preset_map.get(preset, "/ebook")

    cmd = [
        "gs",
        "-sDEVICE=pdfwrite",
        "-dCompatibilityLevel=1.4",
        f"-dPDFSETTINGS={gs_preset}",
        "-dNOPAUSE",
        "-dBATCH",
        "-dQUIET",
        f"-sOutputFile={str(out_pdf)}",
        str(input_pdf),
    ]
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr or p.stdout or "Ghostscript compression failed")

    if not out_pdf.exists():
        raise RuntimeError("Compressed PDF not produced")
    return out_pdf


def _safe_pdf_name(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in ("-", "_", " ")).strip() or "output"


def _parse_ranges(rng: str, total_pages: int) -> List[int]:
    rng = (rng or "").replace(" ", "")
    if not rng:
        raise ValueError("Range is empty")

    out = set()
    for part in rng.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a <= 0 or b <= 0:
                raise ValueError("Pages start from 1")
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                out.add(p - 1)
        else:
            p = int(part)
            if p <= 0:
                raise ValueError("Pages start from 1")
            out.add(p - 1)

    pages = sorted(x for x in out if 0 <= x < total_pages)
    if not pages:
        raise ValueError("No valid pages selected")
    return pages


# ----------------------------
# Conversion APIs
# ----------------------------
@app.post("/convert/office-to-pdf")
async def office_to_pdf(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_OFFICE_EXT:
        raise HTTPException(400, f"Unsupported file type: {ext}")

    job_id = str(uuid.uuid4())
    in_path = UPLOAD_DIR / f"{job_id}{ext}"

    await save_upload_limited(file, in_path, MAX_UPLOAD_BYTES)

    job_out_dir = OUTPUT_DIR / job_id
    try:
        pdf_path = convert_office_to_pdf(in_path, job_out_dir)
    except Exception as e:
        raise HTTPException(500, f"Conversion failed: {e}")

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"{Path(file.filename).stem}.pdf",
    )


@app.post("/convert/jpg-to-pdf")
async def jpg_to_pdf(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(400, "No files uploaded")

    job_id = str(uuid.uuid4())
    job_dir = UPLOAD_DIR / job_id
    out_dir = OUTPUT_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    saved_paths: List[Path] = []
    first_name = None

    total_written = 0

    for i, f in enumerate(files):
        if not f.filename:
            continue
        if first_name is None:
            first_name = f.filename

        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_IMAGE_EXT:
            raise HTTPException(400, f"Unsupported image type: {ext}")

        dst = job_dir / f"{i:03d}{ext}"

        # enforce TOTAL limit across multiple files
        # (we stream each file and keep total_written under MAX_UPLOAD_BYTES)
        # Save file with per-file max remaining budget
        remaining = max(0, MAX_UPLOAD_BYTES - total_written)
        if remaining <= 0:
            _http_413(f"Total upload too large. Max allowed is {MAX_UPLOAD_MB}MB.")
        written = await save_upload_limited(f, dst, remaining)
        total_written += written

        saved_paths.append(dst)

    if not saved_paths:
        raise HTTPException(400, "No valid images found")

    out_pdf = out_dir / "images.pdf"
    try:
        pdf_path = images_to_pdf(saved_paths, out_pdf)
    except Exception as e:
        raise HTTPException(500, f"Conversion failed: {e}")

    base = Path(first_name or "images").stem
    return FileResponse(path=str(pdf_path), media_type="application/pdf", filename=f"{base}.pdf")


@app.post("/convert/compress-pdf")
async def compress_pdf(file: UploadFile = File(...), preset: str = Form("ebook")):
    if not file.filename:
        raise HTTPException(400, "No filename provided")
    if Path(file.filename).suffix.lower() != ".pdf":
        raise HTTPException(400, "Only PDF files are supported for compression")

    job_id = str(uuid.uuid4())
    in_path = UPLOAD_DIR / f"{job_id}.pdf"

    orig_bytes = await save_upload_limited(file, in_path, MAX_UPLOAD_BYTES)

    job_out_dir = OUTPUT_DIR / job_id
    job_out_dir.mkdir(parents=True, exist_ok=True)
    out_pdf = job_out_dir / "compressed.pdf"

    try:
        pdf_path = compress_pdf_gs(in_path, out_pdf, preset=preset)
    except Exception as e:
        raise HTTPException(500, f"Compression failed: {e}")

    out_bytes = 0
    try:
        out_bytes = pdf_path.stat().st_size
    except Exception:
        pass

    base = Path(file.filename).stem
    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"{base}-compressed.pdf",
        headers={
            "X-Original-Bytes": str(orig_bytes),
            "X-Output-Bytes": str(out_bytes),
        },
    )


@app.post("/convert/to-png")
async def convert_to_png(file: UploadFile = File(...), dpi: int = Form(144)):
    if not file.filename:
        raise HTTPException(400, "No filename provided")

    dpi = max(72, min(int(dpi), 300))

    ext = Path(file.filename).suffix.lower()
    if ext not in {".pdf", ".jpg", ".jpeg", ".png", ".webp"}:
        raise HTTPException(400, "Supported: PDF, JPG, JPEG, PNG, WEBP")

    job_id = str(uuid.uuid4())
    job_out_dir = OUTPUT_DIR / job_id
    job_out_dir.mkdir(parents=True, exist_ok=True)

    in_path = UPLOAD_DIR / f"{job_id}{ext}"
    await save_upload_limited(file, in_path, MAX_UPLOAD_BYTES)

    base = Path(file.filename).stem

    if ext == ".pdf":
        try:
            doc = fitz.open(str(in_path))
        except Exception as e:
            raise HTTPException(500, f"Failed to open PDF: {e}")

        if doc.page_count == 0:
            raise HTTPException(400, "PDF has 0 pages")

        zoom = dpi / 72.0
        mat = fitz.Matrix(zoom, zoom)

        png_paths: List[Path] = []
        for i in range(doc.page_count):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            out_png = job_out_dir / f"{base}-page-{i+1}.png"
            pix.save(str(out_png))
            png_paths.append(out_png)

        doc.close()

        if len(png_paths) == 1:
            return FileResponse(path=str(png_paths[0]), media_type="image/png", filename=f"{base}.png")

        zip_path = job_out_dir / f"{base}-png.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for p in png_paths:
                z.write(p, arcname=p.name)

        return FileResponse(path=str(zip_path), media_type="application/zip", filename=f"{base}-png.zip")

    try:
        img = Image.open(in_path)
        if img.mode in ("RGBA", "LA", "P"):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")
        out_png = job_out_dir / f"{base}.png"
        img.save(out_png, format="PNG")
        try:
            img.close()
        except Exception:
            pass
    except Exception as e:
        raise HTTPException(500, f"Image conversion failed: {e}")

    return FileResponse(path=str(out_png), media_type="image/png", filename=f"{base}.png")


@app.post("/convert/merge-pdf")
async def merge_pdf(files: List[UploadFile] = File(...)):
    if not files or len(files) < 2:
        raise HTTPException(400, "Upload at least 2 PDF files")

    job_id = str(uuid.uuid4())
    job_dir = UPLOAD_DIR / job_id
    out_dir = OUTPUT_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    saved: List[Path] = []
    total_written = 0

    for i, f in enumerate(files):
        if not f.filename:
            continue
        if Path(f.filename).suffix.lower() != ".pdf":
            raise HTTPException(400, "Only PDF allowed")
        dst = job_dir / f"{i:03d}.pdf"

        remaining = max(0, MAX_UPLOAD_BYTES - total_written)
        if remaining <= 0:
            _http_413(f"Total upload too large. Max allowed is {MAX_UPLOAD_MB}MB.")
        written = await save_upload_limited(f, dst, remaining)
        total_written += written

        saved.append(dst)

    if len(saved) < 2:
        raise HTTPException(400, "Need at least 2 valid PDFs")

    writer = PdfWriter()
    try:
        for p in saved:
            reader = PdfReader(str(p))
            for page in reader.pages:
                writer.add_page(page)

        out_pdf = out_dir / "merged.pdf"
        with out_pdf.open("wb") as fp:
            writer.write(fp)
    except Exception as e:
        raise HTTPException(500, f"Merge failed: {e}")

    base = _safe_pdf_name(Path(files[0].filename).stem)
    return FileResponse(path=str(out_pdf), media_type="application/pdf", filename=f"{base}-merged.pdf")


@app.post("/convert/split-pdf")
async def split_pdf(file: UploadFile = File(...), mode: str = Form("range"), page_range: str = Form("1-1")):
    if not file.filename:
        raise HTTPException(400, "No filename provided")
    if Path(file.filename).suffix.lower() != ".pdf":
        raise HTTPException(400, "Only PDF allowed")

    job_id = str(uuid.uuid4())
    in_path = UPLOAD_DIR / f"{job_id}.pdf"
    await save_upload_limited(file, in_path, MAX_UPLOAD_BYTES)

    out_dir = OUTPUT_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        reader = PdfReader(str(in_path))
        total = len(reader.pages)
        if total == 0:
            raise HTTPException(400, "PDF has 0 pages")

        base = _safe_pdf_name(Path(in_path).stem)

        if mode == "each":
            zip_path = out_dir / f"{base}-split.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                for i in range(total):
                    w = PdfWriter()
                    w.add_page(reader.pages[i])
                    one_path = out_dir / f"{base}-page-{i+1}.pdf"
                    with one_path.open("wb") as fp:
                        w.write(fp)
                    z.write(one_path, arcname=one_path.name)

            return FileResponse(path=str(zip_path), media_type="application/zip", filename=f"{base}-split.zip")

        pages = _parse_ranges(page_range, total)
        w = PdfWriter()
        for idx in pages:
            w.add_page(reader.pages[idx])

        out_pdf = out_dir / f"{base}-range.pdf"
        with out_pdf.open("wb") as fp:
            w.write(fp)

        return FileResponse(path=str(out_pdf), media_type="application/pdf", filename=f"{base}-split.pdf")

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Split failed: {e}")