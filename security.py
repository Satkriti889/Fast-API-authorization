# security.py

"""
Security module for FastAPI authentication system.
Contains all security-related logic and utilities.
"""

import os
from datetime import datetime, timedelta
from typing import Optional, List
from enum import Enum

import pymysql
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from pydantic import BaseModel, ValidationError
from jose import JWTError, jwt
from dotenv import load_dotenv

load_dotenv()

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# --- Security Setup ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security_scheme = HTTPBearer()

# --- Pydantic Models ---
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    disabled: Optional[bool] = None
    roles: List[str]

class UserInDB(User):
    password: str

class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str

# --- Helper Functions ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def get_db():
    try:
        connection = pymysql.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME,
            charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor
        )
        yield connection
    except pymysql.MySQLError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database connection failed.")
    finally:
        if 'connection' in locals() and connection.open:
            connection.close()

# --- User Management ---
def get_user(db: pymysql.connections.Connection, username: str) -> Optional[UserInDB]:
    try:
        with db.cursor() as cursor:
            sql = "SELECT id, username, email, full_name, password, disabled, roles FROM users WHERE username = %s"
            cursor.execute(sql, (username,))
            user_data = cursor.fetchone()
            if user_data:
                roles = user_data['roles'].split(',') if user_data.get('roles') else []
                user_data['roles'] = roles
                return UserInDB(**user_data)
            return None
    except (pymysql.MySQLError, ValidationError):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error retrieving user data.")

def create_user(db: pymysql.connections.Connection, user: UserCreate) -> User:
    try:
        with db.cursor() as cursor:
            cursor.execute("SELECT id FROM users WHERE username = %s", (user.username,))
            if cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
            
            cursor.execute("SELECT id FROM users WHERE email = %s", (user.email,))
            if cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
            
            hashed_password = get_password_hash(user.password)
            default_roles = UserRole.USER.value
            
            sql = "INSERT INTO users (username, email, full_name, password, roles) VALUES (%s, %s, %s, %s, %s)"
            cursor.execute(sql, (user.username, user.email, user.full_name, hashed_password, default_roles))
            
            new_user_id = cursor.lastrowid
            db.commit()

            return User(id=new_user_id, username=user.username, email=user.email, full_name=user.full_name, disabled=False, roles=[default_roles])
    except pymysql.MySQLError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create user account.")

# --- Authentication & Authorization ---
def authenticate_user(db: pymysql.connections.Connection, username: str, password: str) -> Optional[UserInDB]:
    user = get_user(db, username)
    if not user or not verify_password(password, user.password):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire_time = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire_time})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(auth: HTTPAuthorizationCredentials = Depends(security_scheme), db: pymysql.connections.Connection = Depends(get_db)) -> User:
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    token = auth.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, username=username)
    if user is None: raise credentials_exception
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def has_role(required_role: UserRole):
    def role_checker(current_user: User = Depends(get_current_active_user)) -> User:
        if required_role.value not in current_user.roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Operation not permitted")
        return current_user
    return role_checker