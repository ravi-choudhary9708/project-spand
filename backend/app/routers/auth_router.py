"""
Auth Router - Login and user management
"""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel, EmailStr
from typing import Optional
from app.database import get_db
from app.models.models import User, UserRole, AuditLog
from app.auth.auth import authenticate_user, create_access_token, get_password_hash, get_current_user
import uuid

router = APIRouter(prefix="/api/auth", tags=["auth"])


class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.SECURITY_ANALYST


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user.last_login = datetime.utcnow()

    # Audit log
    log = AuditLog(
        log_id=str(uuid.uuid4()),
        user_id=user.id,
        action="LOGIN",
        resource_type="session",
        details={"username": user.username},
    )
    db.add(log)
    db.commit()

    token = create_access_token(data={"sub": user.username, "role": user.role.value})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
        },
    }


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    log = AuditLog(
        log_id=str(uuid.uuid4()),
        user_id=current_user.id,
        action="LOGOUT",
        details={"username": current_user.username},
    )
    db.add(log)
    db.commit()
    return {"message": "Logged out successfully"}
