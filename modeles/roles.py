# modeles/roles.py
from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.orm import relationship

# Assuming 'db' directory is a sibling to 'modeles' or accessible in PYTHONPATH
# If FAST_API_USER_MANAGEMENT is the root and in PYTHONPATH:
from db.database import Base # Corrected import path

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)

    users = relationship("User", back_populates="role")
    permissions = relationship("UserPermission", back_populates="role")