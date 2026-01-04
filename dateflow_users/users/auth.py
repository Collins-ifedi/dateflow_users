# dataflow_users/backend/users/auth.py

import os
import random
import jwt
import bcrypt  # Replaced passlib for Python 3.13 compatibility
from datetime import datetime, timedelta, timezone
from typing import Optional
import logging

import vonage  # Vonage SDK for SMS
from fastapi import APIRouter, Depends, HTTPException, status, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

from .database import get_db
from .models import User, Verification, VerificationType, UserRole

# ======================================================
# CONFIGURATION & LOGGING
# ======================================================

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

# Load Secrets
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS_IN_PRODUCTION_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60 * 24  # 24 hours
VERIFICATION_EXPIRE_HOURS = 1 # OTP expiry time

# ------------------------------------------------------
# EMAIL CONFIG (Brevo)
# ------------------------------------------------------
BREVO_API_KEY = os.getenv("BREVO_API_KEY")

if BREVO_API_KEY:
    brevo_config = sib_api_v3_sdk.Configuration()
    brevo_config.api_key['api-key'] = BREVO_API_KEY
else:
    logger.warning("⚠️ BREVO_API_KEY not found. Emails will not be sent.")

# ------------------------------------------------------
# SMS CONFIG (Vonage)
# ------------------------------------------------------
VONAGE_API_KEY = os.getenv("VONAGE_API_KEY")
VONAGE_API_SECRET = os.getenv("VONAGE_API_SECRET")
VONAGE_SENDER_NAME = os.getenv("VONAGE_SENDER_NAME", "DataFlow") 

sms_client = None

if VONAGE_API_KEY and VONAGE_API_SECRET:
    try:
        vonage_client = vonage.Client(key=VONAGE_API_KEY, secret=VONAGE_API_SECRET)
        sms_client = vonage.Sms(vonage_client)
        logger.info("✅ Vonage SMS client initialized.")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Vonage client: {e}")
else:
    logger.warning("⚠️ VONAGE credentials not found. SMS will not be sent.")

# ------------------------------------------------------
# OAUTH2 SCHEME
# ------------------------------------------------------
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# ======================================================
# SECURITY UTILITIES
# ======================================================

def hash_password(password: str) -> str:
    """
    Hashes a password using bcrypt directly.
    """
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifies a plain password against the bcrypt hash.
    """
    try:
        pwd_bytes = password.encode('utf-8')
        hash_bytes = password_hash.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def create_access_token(user_id: int) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> int:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ======================================================
# NOTIFICATION SERVICES
# ======================================================

def send_email_via_brevo(to_email: str, subject: str, html_content: str):
    if not BREVO_API_KEY:
        logger.error("Cannot send email: BREVO_API_KEY is missing.")
        return

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(brevo_config))
    send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": to_email}],
        sender={"name": "DataFlow Support", "email": "collins@glitchape.fun"}, # Updated sender
        subject=subject,
        html_content=html_content
    )

    try:
        api_instance.send_transac_email(send_smtp_email)
        logger.info(f"📧 Email sent successfully to {to_email}")
    except ApiException as e:
        logger.error(f"❌ Failed to send email to {to_email}: {e}")

def send_sms_via_vonage(to_phone: str, message_text: str):
    if not sms_client:
        logger.error("Cannot send SMS: Vonage client not initialized.")
        return

    try:
        response = sms_client.send_message({
            "from": VONAGE_SENDER_NAME,
            "to": to_phone,
            "text": message_text,
        })

        if response["messages"][0]["status"] == "0":
            logger.info(f"📲 SMS sent successfully to {to_phone}")
        else:
            error_text = response['messages'][0].get('error-text', 'Unknown Error')
            logger.error(f"❌ SMS failed to {to_phone}. Error: {error_text}")
            
    except Exception as e:
        logger.error(f"❌ Vonage Exception: {e}")

# ======================================================
# DEPENDENCIES
# ======================================================

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    user_id = decode_access_token(token)
    user = await db.get(User, user_id)

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if user.is_blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Your account has been blocked.")

    return user

async def require_verified_user(current_user: User = Depends(get_current_user)) -> User:
    if not (current_user.is_email_verified or current_user.is_phone_verified):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account verification required.")
    return current_user

# ======================================================
# VERIFICATION LOGIC
# ======================================================

async def create_verification(
    user_id: int,
    v_type: VerificationType,
    db: AsyncSession,
    background_tasks: BackgroundTasks
) -> Verification:
    """
    Generates OTP, saves to DB, and queues notification.
    """
    code = f"{random.randint(100000, 999999)}"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=VERIFICATION_EXPIRE_HOURS)
    
    verification = Verification(
        user_id=user_id,
        code=code,
        verification_type=v_type,
        expires_at=expires_at,
        is_verified=False
    )
    db.add(verification)
    await db.commit()
    await db.refresh(verification)

    user = await db.get(User, user_id)
    
    if v_type == VerificationType.EMAIL and user.email:
        html_content = f"""
        <html>
            <body>
                <h2>Verify your account</h2>
                <p>Your verification code is: <strong style="font-size: 18px;">{code}</strong></p>
                <p>This code expires in {VERIFICATION_EXPIRE_HOURS} hour(s).</p>
            </body>
        </html>
        """
        background_tasks.add_task(send_email_via_brevo, user.email, "Your Verification Code", html_content)

    elif v_type == VerificationType.PHONE and user.phone:
        msg_text = f"Your DataFlow verification code is: {code}. Expires in {VERIFICATION_EXPIRE_HOURS} hour."
        background_tasks.add_task(send_sms_via_vonage, user.phone, msg_text)

    return verification

# ======================================================
# AUTH ROUTES
# ======================================================

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(
    background_tasks: BackgroundTasks,
    email: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if not email and not phone:
        raise HTTPException(status_code=400, detail="Email or phone number is required.")

    # Check for existing user
    if email:
        exists_email = await db.execute(select(User).where(User.email == email))
        if exists_email.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already registered.")
            
    if phone:
        exists_phone = await db.execute(select(User).where(User.phone == phone))
        if exists_phone.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Phone already registered.")

    # Create User
    new_user = User(
        email=email,
        phone=phone,
        password_hash=hash_password(password),
        role=UserRole.USER,
        is_email_verified=False,
        is_phone_verified=False
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Trigger Verification
    v_type = VerificationType.EMAIL if email else VerificationType.PHONE
    
    # [FIX]: Capture the verification object
    verification = await create_verification(new_user.id, v_type, db, background_tasks)

    # [FIX]: Return verification_id to the frontend
    return {
        "access_token": create_access_token(new_user.id),
        "token_type": "bearer",
        "user_id": new_user.id,
        "verification_id": verification.id,  # <--- Crucial fix for 422 error
        "message": "User created. Verification code sent."
    }

# ------------------------------------------------------

@router.post("/login")
async def login(
    email: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    if not email and not phone:
        raise HTTPException(status_code=400, detail="Email or phone required")

    stmt = select(User).where(User.email == email if email else User.phone == phone)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if user.is_blocked:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been blocked.")

    return {
        "access_token": create_access_token(user.id),
        "token_type": "bearer",
        "user_id": user.id,
        "is_verified": user.is_email_verified or user.is_phone_verified
    }

# ------------------------------------------------------

@router.post("/verify")
async def verify_account(
    verification_id: int = Form(...),
    code: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    # Retrieve verification record
    verification = await db.get(Verification, verification_id)

    if not verification:
        raise HTTPException(status_code=404, detail="Verification request not found.")

    if datetime.now(timezone.utc) > verification.expires_at:
        raise HTTPException(status_code=400, detail="Verification code has expired.")

    if verification.code != code:
        raise HTTPException(status_code=400, detail="Invalid verification code.")
    
    # Mark user as verified
    user = await db.get(User, verification.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    verification.is_verified = True
    if verification.verification_type == VerificationType.EMAIL:
        user.is_email_verified = True
    else:
        user.is_phone_verified = True

    await db.commit()
    return {"detail": "Account successfully verified."}

# ------------------------------------------------------

@router.post("/password/recover")
async def recover_password(
    background_tasks: BackgroundTasks,
    email: Optional[str] = Form(None),
    phone: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).where(User.email == email if email else User.phone == phone)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Return 404 for clarity in this specific context
        raise HTTPException(status_code=404, detail="User not found")

    v_type = VerificationType.EMAIL if email else VerificationType.PHONE
    
    # Capture and return verification ID
    verification = await create_verification(user.id, v_type, db, background_tasks)

    return {
        "verification_id": verification.id,
        "detail": "Recovery code sent."
    }

# ------------------------------------------------------

@router.post("/password/reset")
async def reset_password(
    verification_id: int = Form(...),
    code: str = Form(...),
    new_password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    verification = await db.get(Verification, verification_id)

    if not verification:
        raise HTTPException(status_code=400, detail="Invalid request.")

    if verification.code != code:
        raise HTTPException(status_code=400, detail="Invalid recovery code.")
    
    if datetime.now(timezone.utc) > verification.expires_at:
        raise HTTPException(status_code=400, detail="Recovery code has expired.")

    user = await db.get(User, verification.user_id)
    user.password_hash = hash_password(new_password)

    await db.delete(verification)
    await db.commit()
    
    return {"detail": "Password reset successful. You can now login."}

# ------------------------------------------------------

@router.post("/password/change")
async def change_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect current password.")

    current_user.password_hash = hash_password(new_password)
    await db.commit()

    return {"detail": "Password changed successfully."}