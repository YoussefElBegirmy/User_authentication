# modeles/__init__.py
from .users import User
from .roles import Role
from .user_permissions import UserPermission

# This file makes 'modeles' a package and allows easier imports.
# It also ensures that when 'modeles' package is imported,
# SQLAlchemy's Base knows about these models.