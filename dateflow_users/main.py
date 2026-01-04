# dataflow_users/backend/main.py

import os
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict

import stripe
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
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
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

# Path Configuration
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"

# Stripe Configuration
# Initialize API key globally
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

    # 1. Critical Production Checks
    # Ensures all external service credentials are present before traffic is accepted.
    if ENVIRONMENT == "production":
        missing_vars = []
        
        # Stripe Checks
        if not os.getenv("STRIPE_SECRET_KEY"):
            missing_vars.append("STRIPE_SECRET_KEY")
        if not os.getenv("STRIPE_WEBHOOK_SECRET"):
            missing_vars.append("STRIPE_WEBHOOK_SECRET")
            
        # Vonage SMS Checks (NEW)
        if not os.getenv("VONAGE_API_KEY"):
            missing_vars.append("VONAGE_API_KEY")
        if not os.getenv("VONAGE_API_SECRET"):
            missing_vars.append("VONAGE_API_SECRET")
            
        if missing_vars:
            error_msg = f"❌ CRITICAL: Missing required production env vars: {', '.join(missing_vars)}"
            logger.critical(error_msg)
            # Stop the app startup to prevent running in an unsafe state
            raise RuntimeError(error_msg)

    # 2. Database Initialization
    try:
        await init_db()
        logger.info("✅ Database initialized.")
    except Exception as e:
        logger.critical(f"❌ Database initialization failed: {e}")
        # In strict production, raising here prevents the app from starting without a DB connection
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
    version="1.3.1",
    lifespan=lifespan,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url=None
)

# ======================================================
# MIDDLEWARE
# ======================================================

# 1. Proxy Headers Middleware
# Vital for deployments on Render/Heroku/Nginx.
# Ensures the app knows it's running behind HTTPS, which is required for
# correct redirect URLs (Stripe) and cookie security.
app.add_middleware(
    ProxyHeadersMiddleware,
    trusted_hosts="*" # Trust the load balancer
)

# 2. CORS Middleware
# Allows frontend to communicate with backend.
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

# Note: The Stripe Webhook is contained within 'user_router' (/api/users/webhook/stripe).
# Since we use dependency injection (Depends) rather than global middleware for Auth,
# the webhook route is safe from being blocked by login requirements 
# as long as it does not declare a User dependency itself.

app.include_router(auth_router)
app.include_router(user_router)

# ======================================================
# HELPER: HTML SERVING
# ======================================================

def serve_html(filename: str) -> HTMLResponse:
    """
    Securely serves HTML files directly from the backend/frontend folder.
    """
    file_path = FRONTEND_DIR / filename
    
    if FRONTEND_DIR not in file_path.resolve().parents:
        return HTMLResponse("<h1>403 - Forbidden</h1>", status_code=403)

    if not file_path.exists():
        logger.warning(f"404 - File not found: {filename}")
        if (FRONTEND_DIR / "404.html").exists() and filename != "404.html":
            return serve_html("404.html")
        return HTMLResponse("<h1>404 - Page Not Found</h1>", status_code=404)
        
    return HTMLResponse(file_path.read_text(encoding="utf-8"))

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
    """
    Global handler for Stripe errors. 
    Returns a clean JSON response so Stripe webhooks don't just timeout.
    """
    logger.error(f"Stripe Error: {str(exc)}")
    return JSONResponse(
        status_code=400, # or 500 depending on severity, 400 stops retries often
        content={"detail": "Payment provider error", "error_code": str(exc)}
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    
    if exc.status_code == 404:
        return serve_html("404.html")
        
    return HTMLResponse(f"<h1>{exc.status_code} - {exc.detail}</h1>", status_code=exc.status_code)

# ======================================================
# HTML ROUTES (FRONTEND MONOLITH)
# ======================================================

@app.get("/", response_class=HTMLResponse)
async def index():
    return serve_html("authentication.html")

@app.get("/authentication", response_class=HTMLResponse)
async def authentication():
    return serve_html("authentication.html")

@app.get("/profile", response_class=HTMLResponse)
async def profile():
    return serve_html("profile.html")

@app.get("/matches", response_class=HTMLResponse)
async def matches():
    return serve_html("matches.html")

@app.get("/messages", response_class=HTMLResponse)
async def messages():
    return serve_html("messages.html")

@app.get("/verification-pending", response_class=HTMLResponse)
async def verification_pending():
    return serve_html("verification_pending.html")

@app.get("/account-blocked", response_class=HTMLResponse)
async def account_blocked():
    return serve_html("account_blocked.html")

@app.get("/about", response_class=HTMLResponse)
async def about():
    return serve_html("about.html")

@app.get("/terms", response_class=HTMLResponse)
async def terms():
    return serve_html("terms.html")

@app.get("/privacy", response_class=HTMLResponse)
async def privacy():
    return serve_html("privacy.html")

@app.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(path: str):
    return serve_html("404.html")