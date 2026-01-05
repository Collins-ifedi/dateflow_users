# dataflow_users/backend/users/routes.py

import os
import logging
from datetime import datetime
from typing import Optional, List

import stripe
import cloudinary
import cloudinary.uploader
from fastapi import (
    APIRouter, Depends, HTTPException, UploadFile, 
    File, Form, status, Query, Request, Header
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, desc
from sqlalchemy.orm import selectinload

from .database import get_db
from .models import (
    User, Like, Match, Message, MessageType,
    Call, Report, Verification, ReportReason,
    Subscription, SubscriptionStatus
)
from .auth import get_current_user, require_verified_user

# ======================================================
# CONFIGURATION
# ======================================================

logger = logging.getLogger("uvicorn")
router = APIRouter(prefix="/api/users", tags=["User Interaction"])

# Stripe Configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
stripe.api_key = STRIPE_SECRET_KEY

# Cloudinary Configuration
# (Cloudinary auto-configures if 'CLOUDINARY_URL' is in env vars)

# ======================================================
# PROFILE ROUTES
# ======================================================

@router.get("/profile/me")
async def my_profile(
    current_user: User = Depends(require_verified_user)
):
    """Get the current logged-in user's profile."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "phone": current_user.phone,
        "bio": current_user.bio,
        "gender": current_user.gender,
        "preference": current_user.preference,
        "dob": current_user.dob,
        "location": current_user.location,
        "profile_picture": current_user.profile_picture,
        "cover_photo": current_user.cover_photo,
        "is_verified": current_user.is_email_verified or current_user.is_phone_verified,
        "stripe_customer_id": current_user.stripe_customer_id
    }

@router.post("/profile/update")
async def update_profile(
    username: Optional[str] = Form(None),
    bio: Optional[str] = Form(None),
    gender: Optional[str] = Form(None),
    preference: Optional[str] = Form(None),
    location: Optional[str] = Form(None),
    profile_picture: Optional[UploadFile] = File(None),
    cover_photo: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Update profile fields and upload images to Cloudinary.
    """
    # 1. Update Text Fields
    if username: current_user.username = username
    if bio: current_user.bio = bio
    if gender: current_user.gender = gender
    if preference: current_user.preference = preference
    if location: current_user.location = location

    # 2. Handle Profile Picture (Auto-Crop to Face)
    if profile_picture:
        try:
            upload_result = cloudinary.uploader.upload(
                profile_picture.file,
                folder="dating_app/profiles",
                transformation=[
                    {"width": 800, "height": 800, "crop": "thumb", "gravity": "face"}
                ]
            )
            current_user.profile_picture = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Cloudinary Upload Error: {e}")
            raise HTTPException(status_code=500, detail="Image upload failed")

    # 3. Handle Cover Photo
    if cover_photo:
        try:
            upload_result = cloudinary.uploader.upload(
                cover_photo.file,
                folder="dating_app/covers",
                transformation=[
                    {"width": 1200, "height": 600, "crop": "fill"}
                ]
            )
            current_user.cover_photo = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Cloudinary Upload Error: {e}")
            raise HTTPException(status_code=500, detail="Cover photo upload failed")

    await db.commit()
    return {"detail": "Profile updated successfully", "profile_picture": current_user.profile_picture}

@router.get("/profile/{user_id}")
async def view_other_profile(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """View another user's profile. Checks if blocked."""
    if user_id == current_user.id:
        return await my_profile(current_user)

    user = await db.get(User, user_id)

    if not user or user.is_blocked:
        raise HTTPException(status_code=404, detail="User not available")
    
    return {
        "id": user.id,
        "username": user.username,
        "bio": user.bio,
        "gender": user.gender,
        "location": user.location,
        "profile_picture": user.profile_picture,
        "cover_photo": user.cover_photo
    }

# ======================================================
# MATCHING LOGIC
# ======================================================

@router.post("/like/{user_id}")
async def like_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Likes a user. If they already liked you, creates a Match.
    """
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot like yourself")

    # 1. Check if already liked
    existing_like = await db.execute(
        select(Like).where(Like.liker_id == current_user.id, Like.liked_id == user_id)
    )
    if existing_like.scalar_one_or_none():
        return {"detail": "Already liked", "matched": False}

    # 2. Add Like
    new_like = Like(liker_id=current_user.id, liked_id=user_id)
    db.add(new_like)

    # 3. Check for Mutual Like (Match)
    reverse_like = await db.execute(
        select(Like).where(Like.liker_id == user_id, Like.liked_id == current_user.id)
    )
    
    match_data = None
    if reverse_like.scalar_one_or_none():
        # Create Match
        new_match = Match(user1_id=current_user.id, user2_id=user_id)
        db.add(new_match)
        match_data = {"matched": True}
    else:
        match_data = {"matched": False}

    await db.commit()
    
    if match_data["matched"]:
        await db.refresh(new_match)
        match_data["match_id"] = new_match.id

    return match_data

@router.get("/matches")
async def get_matches(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Optimized fetch of all matches. 
    Uses 'selectinload' to avoid N+1 query problems.
    """
    stmt = select(Match).options(
        selectinload(Match.user1),
        selectinload(Match.user2)
    ).where(
        or_(Match.user1_id == current_user.id, Match.user2_id == current_user.id)
    )
    
    result = await db.execute(stmt)
    matches_db = result.scalars().all()

    matches_list = []
    for m in matches_db:
        # Determine which user is the "other" person
        other_user = m.user2 if m.user1_id == current_user.id else m.user1
        
        matches_list.append({
            "match_id": m.id,
            "user_id": other_user.id,
            "username": other_user.username,
            "profile_picture": other_user.profile_picture,
            "matched_at": m.created_at
        })

    return matches_list

# ======================================================
# MESSAGING
# ======================================================

@router.post("/message/{match_id}")
async def send_message(
    match_id: int,
    message_type: MessageType = Form(MessageType.TEXT),
    content: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Send a message. Supports text and file uploads (images/voice).
    """
    # 1. Verify Match Participation
    match_check = await db.get(Match, match_id)
    if not match_check:
        raise HTTPException(status_code=404, detail="Match not found")
        
    if current_user.id not in [match_check.user1_id, match_check.user2_id]:
        raise HTTPException(status_code=403, detail="Not authorized to message this match")

    # 2. Handle File Upload (if any)
    file_url = None
    if file:
        resource_type = "video" if message_type in [MessageType.VIDEO, MessageType.AUDIO] else "image"
        try:
            upload_result = cloudinary.uploader.upload(
                file.file,
                resource_type=resource_type, 
                folder=f"dating_app/messages/{match_id}"
            )
            file_url = upload_result.get("secure_url")
        except Exception as e:
            logger.error(f"Message upload failed: {e}")
            raise HTTPException(status_code=500, detail="File upload failed")

    # 3. Save Message
    msg = Message(
        match_id=match_id,
        sender_id=current_user.id,
        content=content,
        content_url=file_url,
        content_type=message_type
    )
    db.add(msg)
    await db.commit()
    
    return {"detail": "Message sent", "message_id": msg.id}

@router.get("/messages/{match_id}")
async def get_messages(
    match_id: int,
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Get chat history with pagination.
    """
    match_check = await db.get(Match, match_id)
    if not match_check:
        raise HTTPException(status_code=404, detail="Match not found")
    
    if current_user.id not in [match_check.user1_id, match_check.user2_id]:
        raise HTTPException(status_code=403, detail="Access denied")

    stmt = select(Message).where(
        Message.match_id == match_id
    ).order_by(
        desc(Message.created_at)
    ).limit(limit).offset(skip)

    result = await db.execute(stmt)
    msgs = result.scalars().all()

    return [{
        "id": m.id,
        "sender_id": m.sender_id,
        "type": m.content_type.value,
        "content": m.content,
        "file_url": m.content_url,
        "created_at": m.created_at
    } for m in msgs]

# ======================================================
# REPORTING & BLOCKING
# ======================================================

@router.post("/report/{user_id}")
async def report_user(
    user_id: int,
    reason: ReportReason = Form(...),
    details: str = Form(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot report yourself")

    new_report = Report(
        reporter_id=current_user.id,
        reported_id=user_id,
        reason=reason.value,
        details=details
    )
    db.add(new_report)
    await db.commit()
    return {"detail": "Report submitted. Thank you for keeping our community safe."}

# ======================================================
# ACCOUNT MANAGEMENT
# ======================================================

@router.post("/account/deactivate")
async def deactivate_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    current_user.is_active = False
    await db.commit()
    return {"detail": "Account deactivated"}

@router.delete("/account/delete")
async def delete_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Permanently delete account. 
    """
    await db.delete(current_user)
    await db.commit()
    return {"detail": "Account permanently deleted"}

# ======================================================
# STRIPE SUBSCRIPTION & PAYMENTS
# ======================================================

@router.post("/subscribe", status_code=status.HTTP_200_OK)
async def create_checkout_session(
    price_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Creates a Stripe Checkout Session for a recurring subscription.
    Ensures the user has a Stripe Customer ID before proceeding.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Payment system not configured.")

    try:
        # 1. Ensure User has a Stripe Customer ID
        if not current_user.stripe_customer_id:
            customer = stripe.Customer.create(
                email=current_user.email,
                metadata={"user_id": current_user.id}
            )
            current_user.stripe_customer_id = customer.id
            await db.commit()
            logger.info(f"Created Stripe Customer {customer.id} for User {current_user.id}")

        # 2. Create Checkout Session
        checkout_session = stripe.checkout.Session.create(
            customer=current_user.stripe_customer_id,
            payment_method_types=["card"],
            mode="subscription",
            line_items=[
                {"price": price_id, "quantity": 1}
            ],
            success_url="https://yourdatingapp.com/settings?payment=success",
            cancel_url="https://yourdatingapp.com/settings?payment=canceled",
            metadata={"user_id": current_user.id, "plan_type": "premium"}
        )

        return {"checkout_url": checkout_session.url}

    except stripe.error.StripeError as e:
        logger.error(f"Stripe Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Subscription Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to initiate subscription.")


@router.post("/portal", status_code=status.HTTP_200_OK)
async def create_customer_portal(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_verified_user)
):
    """
    Generates a link to the Stripe Customer Portal where users can
    manage billing, update cards, or cancel subscriptions.
    """
    if not current_user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No billing account found.")

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url="https://yourdatingapp.com/profile"
        )
        return {"portal_url": portal_session.url}
    except stripe.error.StripeError as e:
        logger.error(f"Stripe Portal Error: {e}")
        raise HTTPException(status_code=400, detail="Could not access billing portal.")

# ======================================================
# STRIPE WEBHOOK HANDLER
# ======================================================

@router.post("/webhook/stripe", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Secure Webhook Handler for Stripe events.
    Handles:
    - checkout.session.completed (New subscription)
    - invoice.paid (Renewals)
    - customer.subscription.deleted (Cancellations)
    - customer.subscription.updated (Status changes)
    """
    if not STRIPE_WEBHOOK_SECRET:
        logger.error("Missing STRIPE_WEBHOOK_SECRET")
        raise HTTPException(status_code=500, detail="Webhook secret not configured.")

    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        logger.warning("⚠️ Invalid payload")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        logger.warning("⚠️ Invalid signature")
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data_object = event["data"]["object"]

    try:
        # ------------------------------------------------
        # 1. NEW SUBSCRIPTION (Checkout Completed)
        # ------------------------------------------------
        if event_type == "checkout.session.completed":
            # Only handle subscriptions
            if data_object.get("mode") == "subscription":
                stripe_customer_id = data_object.get("customer")
                stripe_subscription_id = data_object.get("subscription")
                
                # Fetch User
                stmt = select(User).where(User.stripe_customer_id == stripe_customer_id)
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()

                if user:
                    # Fetch Subscription Details from Stripe to get accurate dates/plans
                    sub_details = stripe.Subscription.retrieve(stripe_subscription_id)
                    price_id = sub_details["items"]["data"][0]["price"]["id"]
                    
                    new_sub = Subscription(
                        user_id=user.id,
                        stripe_subscription_id=stripe_subscription_id,
                        stripe_price_id=price_id,
                        plan_name="premium", # Logic can extend to map price_id -> name
                        status=SubscriptionStatus(sub_details["status"]),
                        current_period_start=datetime.fromtimestamp(sub_details["current_period_start"]),
                        current_period_end=datetime.fromtimestamp(sub_details["current_period_end"]),
                        is_active=sub_details["status"] in ["active", "trialing"]
                    )
                    db.add(new_sub)
                    await db.commit()
                    logger.info(f"✅ Subscription created for User {user.id}")

        # ------------------------------------------------
        # 2. SUBSCRIPTION UPDATED / RENEWED (Invoice Paid)
        # ------------------------------------------------
        elif event_type in ["customer.subscription.updated", "invoice.paid"]:
            # Note: invoice.paid object is an Invoice, sub.updated is a Subscription
            # We standardize by fetching the Subscription object if it's an invoice
            
            sub_id = data_object.get("subscription") if event_type == "invoice.paid" else data_object.get("id")
            
            # Fetch DB Record
            stmt = select(Subscription).where(Subscription.stripe_subscription_id == sub_id)
            result = await db.execute(stmt)
            subscription = result.scalar_one_or_none()

            if subscription:
                # Get fresh data from Stripe
                stripe_sub = stripe.Subscription.retrieve(sub_id)
                
                subscription.status = SubscriptionStatus(stripe_sub["status"])
                subscription.current_period_start = datetime.fromtimestamp(stripe_sub["current_period_start"])
                subscription.current_period_end = datetime.fromtimestamp(stripe_sub["current_period_end"])
                subscription.canceled_at = datetime.fromtimestamp(stripe_sub["canceled_at"]) if stripe_sub["canceled_at"] else None
                subscription.is_active = stripe_sub["status"] in ["active", "trialing"]
                
                await db.commit()
                logger.info(f"🔄 Subscription {sub_id} updated. Status: {subscription.status}")

        # ------------------------------------------------
        # 3. SUBSCRIPTION CANCELED / DELETED
        # ------------------------------------------------
        elif event_type == "customer.subscription.deleted":
            sub_id = data_object.get("id")
            
            stmt = select(Subscription).where(Subscription.stripe_subscription_id == sub_id)
            result = await db.execute(stmt)
            subscription = result.scalar_one_or_none()

            if subscription:
                subscription.status = SubscriptionStatus.CANCELED
                subscription.is_active = False
                subscription.canceled_at = datetime.utcnow()
                await db.commit()
                logger.info(f"❌ Subscription {sub_id} canceled.")

    except Exception as e:
        logger.error(f"Webhook Processing Error: {e}")
        # Return 200 to Stripe so it doesn't keep retrying a broken logic error forever,
        # unless it's a temporary DB connection issue.
        return {"status": "error", "detail": str(e)}

    return {"status": "success"}