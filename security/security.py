# security/security.py
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables for JWT settings
# Assuming .env is in the parent directory of 'security'
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(dotenv_path)

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

if not SECRET_KEY or not ALGORITHM:
    raise EnvironmentError("SECRET_KEY or ALGORITHM not found in environment variables.")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for token authentication
# tokenUrl should point to your login endpoint relative to the root path
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Dependency to get the current user from a token
# This will be used to protect routes
# Import User schema and crud functions later to avoid circular imports at module load time
# For now, we'll define the structure and import dynamically or type hint.

async def get_current_user(token: str = Depends(oauth2_scheme)):
    # We will need db session and user crud functions here.
    # This is a common pattern: security depends on crud, crud depends on models/db.
    # To avoid circular import errors at startup, we sometimes import within the function.
    from db.database import SessionLocal # Get a new session for this function
    from db import crud # Import crud functions
    from schema import schemas # Import Pydantic schemas

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception

    db = SessionLocal()
    try:
        user = crud.get_user_by_username(db, username=token_data.username)
        if user is None:
            raise credentials_exception
    finally:
        db.close()
    return user


async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    # Here, current_user is expected to be a SQLAlchemy model instance
    # or a dict/Pydantic model that has an 'is_active' attribute.
    # If get_current_user returns SQLAlchemy model, this is fine.
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user