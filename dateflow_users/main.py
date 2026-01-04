# dataflow_users/main.py

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict

import stripe
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

# Middleware for handling proxy headers (Essential for Heroku/Render)
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from users.database import init_db, close_db_connection
from users.routes import router as user_router
from users.auth import router as auth_router

# ======================================================
# CONFIGURATION
# ======================================================

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("uvicorn")

# Path Configuration
# BASE_DIR is the directory containing this main.py file
BASE_DIR = Path(__file__).resolve().parent

# FRONTEND_DIR is the sibling folder "frontend" inside the same directory
FRONTEND_DIR = (BASE_DIR / "frontend").resolve()

# Stripe Configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Environment Settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# ======================================================
# WEBSOCKET MANAGER (Real-Time Chat)
# ======================================================

class ConnectionManager:
    """
    Manages active WebSocket connections for chat functionality.
    Groups connections by 'match_id'.
    """
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, match_id: int):
        await websocket.accept()
        if match_id not in self.active_connections:
            self.active_connections[match_id] = []
        self.active_connections[match_id].append(websocket)
        logger.info(f"Socket connected: Match {match_id}")

    def disconnect(self, websocket: WebSocket, match_id: int):
        if match_id in self.active_connections:
            if websocket in self.active_connections[match_id]:
                self.active_connections[match_id].remove(websocket)
            if not self.active_connections[match_id]:
                del self.active_connections[match_id]
        logger.info(f"Socket disconnected: Match {match_id}")

    async def broadcast(self, message: dict, match_id: int):
        if match_id in self.active_connections:
            for connection in self.active_connections[match_id][:]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending message: {e}")

ws_manager = ConnectionManager()

# ======================================================
# LIFESPAN (Startup/Shutdown)
# ======================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles database initialization, connection cleanup, and production safety checks.
    """
    logger.info("🚀 DataFlow API Starting up...")
    
    # DEBUG: Print path information on startup
    logger.info(f"📂 BASE_DIR: {BASE_DIR}")
    logger.info(f"📂 FRONTEND_DIR: {FRONTEND_DIR}")
    if not FRONTEND_DIR.exists():
        logger.error("❌ CRITICAL: Frontend directory not found! Check your folder structure.")

    # 1. Critical Production Checks
    if ENVIRONMENT == "production":
        missing_vars = []
        
        if not os.getenv("STRIPE_SECRET_KEY"):
            missing_vars.append("STRIPE_SECRET_KEY")
        if not os.getenv("STRIPE_WEBHOOK_SECRET"):
            missing_vars.append("STRIPE_WEBHOOK_SECRET")
        if not os.getenv("VONAGE_API_KEY"):
            missing_vars.append("VONAGE_API_KEY")
        if not os.getenv("VONAGE_API_SECRET"):
            missing_vars.append("VONAGE_API_SECRET")
            
        if missing_vars:
            error_msg = f"❌ CRITICAL: Missing required production env vars: {', '.join(missing_vars)}"
            logger.critical(error_msg)
            raise RuntimeError(error_msg)

    # 2. Database Initialization
    try:
        await init_db()
        logger.info("✅ Database initialized.")
    except Exception as e:
        logger.critical(f"❌ Database initialization failed: {e}")
        if ENVIRONMENT == "production":
            raise RuntimeError(f"Database connection failed: {e}")
    
    yield
    
    logger.info("🛑 Shutting down...")
    await close_db_connection()

# ======================================================
# APP INITIALIZATION
# ======================================================

app = FastAPI(
    title="DataFlow Dating API",
    version="1.3.2",
    lifespan=lifespan,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url=None
)

# ======================================================
# MIDDLEWARE
# ======================================================

app.add_middleware(
    ProxyHeadersMiddleware,
    trusted_hosts="*" 
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======================================================
# ROUTER REGISTRATION
# ======================================================

app.include_router(auth_router)
app.include_router(user_router)

# ======================================================
# HELPER: HTML SERVING (FIXED)
# ======================================================

def serve_html(filename: str):
    """
    Securely serves HTML files directly from the frontend folder.
    Uses FileResponse for better performance and standard HTTP headers.
    """
    # Resolve absolute path to the requested file
    file_path = (FRONTEND_DIR / filename).resolve()
    
    # SECURITY CHECK: Prevent Path Traversal (e.g. asking for "../../etc/passwd")
    # We ensure the resolved file path starts with the resolved FRONTEND_DIR path
    if not str(file_path).startswith(str(FRONTEND_DIR)):
        logger.warning(f"⚠️ Security Alert: Attempted path traversal to {file_path}")
        return HTMLResponse("<h1>403 - Forbidden</h1>", status_code=403)

    if not file_path.exists():
        logger.warning(f"🔍 404 Not Found: {file_path}")
        
        # Try to serve custom 404 page
        error_page = FRONTEND_DIR / "404.html"
        if error_page.exists() and filename != "404.html":
            return FileResponse(error_page, status_code=404)
            
        return HTMLResponse("<h1>404 - Page Not Found</h1>", status_code=404)
        
    return FileResponse(file_path)

# ======================================================
# WEBSOCKET ENDPOINT
# ======================================================

@app.websocket("/ws/chat/{match_id}")
async def websocket_endpoint(websocket: WebSocket, match_id: int):
    await ws_manager.connect(websocket, match_id)
    try:
        while True:
            data = await websocket.receive_json()
            await ws_manager.broadcast(data, match_id)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, match_id)
    except Exception as e:
        logger.error(f"WebSocket Error: {e}")
        ws_manager.disconnect(websocket, match_id)

# ======================================================
# EXCEPTION HANDLERS
# ======================================================

@app.exception_handler(stripe.error.StripeError)
async def stripe_exception_handler(request: Request, exc: stripe.error.StripeError):
    logger.error(f"Stripe Error: {str(exc)}")
    return JSONResponse(
        status_code=400,
        content={"detail": "Payment provider error", "error_code": str(exc)}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # If API request fails, return JSON
    if request.url.path.startswith("/api"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    
    # If HTML request fails with 404, serve custom page
    if exc.status_code == 404:
        return serve_html("404.html")
        
    return HTMLResponse(f"<h1>{exc.status_code} - {exc.detail}</h1>", status_code=exc.status_code)

# ======================================================
# HTML ROUTES
# ======================================================

@app.get("/", response_class=FileResponse)
async def index():
    return serve_html("authentication.html")

@app.get("/authentication", response_class=FileResponse)
async def authentication():
    return serve_html("authentication.html")

@app.get("/profile", response_class=FileResponse)
async def profile():
    return serve_html("profile.html")

@app.get("/matches", response_class=FileResponse)
async def matches():
    return serve_html("matches.html")

@app.get("/messages", response_class=FileResponse)
async def messages():
    return serve_html("messages.html")

@app.get("/verification-pending", response_class=FileResponse)
async def verification_pending():
    return serve_html("verification_pending.html")

@app.get("/account-blocked", response_class=FileResponse)
async def account_blocked():
    return serve_html("account_blocked.html")

@app.get("/about", response_class=FileResponse)
async def about():
    return serve_html("about.html")

@app.get("/terms", response_class=FileResponse)
async def terms():
    return serve_html("terms.html")

@app.get("/privacy", response_class=FileResponse)
async def privacy():
    return serve_html("privacy.html")

# Catch-all for other static files (images, css, js if stored in frontend)
@app.get("/{path:path}", response_class=FileResponse)
async def catch_all(path: str):
    return serve_html(path)
