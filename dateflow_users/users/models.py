# dataflow_users/backend/users/models.py

from sqlalchemy import (
    Column, Integer, String, Boolean, ForeignKey, 
    DateTime, Text, Enum, func
)
from sqlalchemy.orm import relationship, declarative_base
import enum
from datetime import datetime

Base = declarative_base()

# ======================================================
# ENUMS
# ======================================================

class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"

class MessageType(str, enum.Enum):
    TEXT = "text"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    FILE = "file"
    STICKER = "sticker"

class CallType(str, enum.Enum):
    AUDIO = "audio"
    VIDEO = "video"

class VerificationType(str, enum.Enum):
    EMAIL = "email"
    PHONE = "phone"
    PASSWORD_RESET = "password_reset"

class ReportReason(str, enum.Enum):
    SPAM = "spam"
    HARASSMENT = "harassment"
    INAPPROPRIATE = "inappropriate"
    FAKE = "fake"
    OTHER = "other"

class SubscriptionStatus(str, enum.Enum):
    """
    Maps directly to Stripe Subscription statuses.
    """
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    UNPAID = "unpaid"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    PAUSED = "paused"

# ======================================================
# MODELS
# ======================================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    
    # Auth Fields
    email = Column(String(255), unique=True, index=True, nullable=True)
    phone = Column(String(50), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    
    # Profile Fields
    username = Column(String(50), unique=True, index=True, nullable=True)
    bio = Column(Text, default="")
    gender = Column(String(20), nullable=True)
    preference = Column(String(20), nullable=True)
    dob = Column(DateTime, nullable=True)
    location = Column(String(255), nullable=True)
    
    # Media (Cloudinary URLs)
    profile_picture = Column(String(500), nullable=True)
    cover_photo = Column(String(500), nullable=True)
    
    # Status Flags
    is_active = Column(Boolean, default=True)  # Soft delete/Deactivation
    is_blocked = Column(Boolean, default=False)
    is_email_verified = Column(Boolean, default=False)
    is_phone_verified = Column(Boolean, default=False)

    # Stripe Customer Data
    # Used to link this user to their payment history in Stripe
    stripe_customer_id = Column(String(255), unique=True, index=True, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Relationships
    likes_sent = relationship("Like", back_populates="liker", foreign_keys="Like.liker_id", cascade="all, delete-orphan")
    likes_received = relationship("Like", back_populates="liked", foreign_keys="Like.liked_id", cascade="all, delete-orphan")
    
    matches1 = relationship("Match", back_populates="user1", foreign_keys="Match.user1_id", cascade="all, delete-orphan")
    matches2 = relationship("Match", back_populates="user2", foreign_keys="Match.user2_id", cascade="all, delete-orphan")
    
    messages_sent = relationship("Message", back_populates="sender", foreign_keys="Message.sender_id", cascade="all, delete-orphan")
    
    calls_made = relationship("Call", back_populates="caller", foreign_keys="Call.caller_id", cascade="all, delete-orphan")
    calls_received = relationship("Call", back_populates="receiver", foreign_keys="Call.receiver_id", cascade="all, delete-orphan")
    
    reports_made = relationship("Report", back_populates="reporter", foreign_keys="Report.reporter_id")
    reports_received = relationship("Report", back_populates="reported", foreign_keys="Report.reported_id")
    
    verifications = relationship("Verification", back_populates="user", cascade="all, delete-orphan")
    
    # One-to-Many: Users can technically have multiple records (e.g. old cancelled ones), 
    # but usually only one is 'active'.
    subscriptions = relationship("Subscription", back_populates="user", cascade="all, delete-orphan")


class Like(Base):
    __tablename__ = "likes"

    id = Column(Integer, primary_key=True, index=True)
    liker_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    liked_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    liker = relationship("User", back_populates="likes_sent", foreign_keys=[liker_id])
    liked = relationship("User", back_populates="likes_received", foreign_keys=[liked_id])


class Match(Base):
    __tablename__ = "matches"

    id = Column(Integer, primary_key=True, index=True)
    user1_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user2_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Metadata
    is_active = Column(Boolean, default=True) 
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user1 = relationship("User", back_populates="matches1", foreign_keys=[user1_id])
    user2 = relationship("User", back_populates="matches2", foreign_keys=[user2_id])
    
    messages = relationship("Message", back_populates="match", cascade="all, delete-orphan")


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    match_id = Column(Integer, ForeignKey("matches.id", ondelete="CASCADE"), nullable=False)
    sender_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    content = Column(Text, nullable=True)
    content_url = Column(String(500), nullable=True)
    content_type = Column(Enum(MessageType), default=MessageType.TEXT)
    
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    match = relationship("Match", back_populates="messages")
    sender = relationship("User", back_populates="messages_sent")


class Call(Base):
    __tablename__ = "calls"

    id = Column(Integer, primary_key=True, index=True)
    caller_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    call_type = Column(Enum(CallType), default=CallType.AUDIO)
    status = Column(String(20), default="initiated") # initiated, ongoing, ended, missed, rejected
    
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    ended_at = Column(DateTime(timezone=True), nullable=True)

    caller = relationship("User", back_populates="calls_made", foreign_keys=[caller_id])
    receiver = relationship("User", back_populates="calls_received", foreign_keys=[receiver_id])


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Stripe Data
    stripe_subscription_id = Column(String(255), unique=True, index=True, nullable=True)
    stripe_price_id = Column(String(255), nullable=True)  # e.g., price_1Hh1... (Connects to specific plan)
    
    # Plan Details
    plan_name = Column(String(50), nullable=False) # e.g. "gold", "platinum"
    
    # Lifecycle
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.INCOMPLETE)
    is_active = Column(Boolean, default=False) # Computed convenience field (True if status is active/trialing)
    
    # Periods
    current_period_start = Column(DateTime(timezone=True), nullable=True)
    current_period_end = Column(DateTime(timezone=True), nullable=True)
    canceled_at = Column(DateTime(timezone=True), nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="subscriptions")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reported_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    reason = Column(Enum(ReportReason), nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String(20), default="pending") # pending, reviewed, resolved
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    reporter = relationship("User", back_populates="reports_made", foreign_keys=[reporter_id])
    reported = relationship("User", back_populates="reports_received", foreign_keys=[reported_id])


class Verification(Base):
    __tablename__ = "verifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    code = Column(String(10), nullable=False)
    verification_type = Column(Enum(VerificationType), nullable=False)
    is_verified = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="verifications")