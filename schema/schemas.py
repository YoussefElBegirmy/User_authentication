# schema/schemas.py
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# --- Token Schemas ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- UserPermission Schemas ---
class UserPermissionBase(BaseModel):
    module_name: str
    can_read: bool = False
    can_write: bool = False
    can_delete: bool = False

class UserPermissionCreate(UserPermissionBase):
    # role_id is implicitly handled when creating permissions as part of a role,
    # or could be explicit if permissions were managed independently of roles.
    # For now, let's assume permissions are defined for a role when creating/updating it.
    pass


class UserPermission(UserPermissionBase):
    id: int
    # role_id: int # Not strictly needed here if permissions are always viewed via a role

    class Config:
        orm_mode = True

# --- Role Schemas ---
class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleCreate(RoleBase):
    permissions: Optional[List[UserPermissionBase]] = [] # Allow defining permissions on role creation

class RoleUpdate(RoleBase):
    name: Optional[str] = None # Allow partial updates
    description: Optional[str] = None
    permissions: Optional[List[UserPermissionBase]] = []

class Role(RoleBase):
    id: int
    permissions: List[UserPermission] = []

    class Config:
        orm_mode = True

# --- User Schemas ---
class UserBase(BaseModel):
    username: str
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role_id: Optional[int] = None # Role can be assigned upon creation

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role_id: Optional[int] = None
    is_active: Optional[bool] = None
    # Password update would typically be a separate endpoint for security

class User(UserBase): # Schema for returning user data (excluding password)
    id: int
    is_active: bool
    last_login: Optional[datetime] = None
    role: Optional[Role] = None # Embed full role information

    class Config:
        orm_mode = True

class RoleUpdate(RoleBase): # Make sure this exists or is suitable
    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[UserPermissionBase]] = [] # Allow updating permissions

# ... (UserProfile is fine as is)
class UserProfile(User):
    pass