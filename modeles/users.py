# modeles/users.py
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func # For default timestamp

from db.database import Base # Corrected import path

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(Text, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True) # Role can be optional
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    # created_at = Column(DateTime(timezone=True), server_default=func.now()) # Example

    role = relationship("Role", back_populates="users")