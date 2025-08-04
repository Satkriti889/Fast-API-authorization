# main.py

"""
FastAPI Authentication Application
Main application entry point with API endpoints.
"""
from datetime import timedelta
from typing import Dict, Any

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
import pymysql

from security import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    Token,
    User,
    UserCreate,
    UserRole,
    authenticate_user,
    create_access_token,
    create_user,
    get_current_active_user,
    get_db,
    has_role,
)

# Create FastAPI application instance
app = FastAPI(
    title="FastAPI Authentication System",
    description="A secure authentication system with role-based access control and user registration.",
    version="1.1.0",
)


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {"message": "FastAPI Authentication System is running!"}


@app.post("/users/register", response_model=User, status_code=status.HTTP_201_CREATED)
def register_user(
    user_in: UserCreate, 
    db: pymysql.connections.Connection = Depends(get_db)
) -> User:
    """
    Register a new user account.
    
    The password will be hashed automatically before storing.
    A new user is assigned the 'user' role by default.
    """
    return create_user(db=db, user=user_in)


@app.post("/auth/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: pymysql.connections.Connection = Depends(get_db)
) -> dict:
    """
    Login endpoint that accepts username and password.
    Returns JWT access token if credentials are valid.
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Protected endpoint to get current user information.
    Requires valid JWT token.
    """
    return current_user


@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: User = Depends(has_role(UserRole.ADMIN))
) -> Dict[str, str]:
    """
    Admin-only endpoint demonstrating role-based access control.
    Only users with 'admin' role can access this endpoint.
    """
    return {
        "message": f"Welcome to the admin dashboard, {current_user.full_name}!",
        "admin_info": "This is sensitive admin information.",
        "user_roles": ", ".join(current_user.roles)
    }


@app.get("/users/profile")
def get_user_profile(
    current_user: User = Depends(get_current_active_user)
) -> Dict[str, Any]:
    """
    Another protected endpoint to demonstrate user access.
    Available to any authenticated user.
    """
    return {
        "user_id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "roles": current_user.roles,
        "account_status": "active" if not current_user.disabled else "disabled"
    }

# NOTE: The 'if __name__ == "__main__":' block is intentionally removed.
# This is the standard way to structure a FastAPI app for deployment and development.