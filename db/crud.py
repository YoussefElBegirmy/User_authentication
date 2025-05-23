# db/crud.py
from sqlalchemy.orm import Session, joinedload, selectinload
from datetime import datetime, timezone

from modeles import users as model_users
from modeles import roles as model_roles
from modeles import user_permissions as model_user_permissions
from schema import schemas
from security import security

# --- User CRUD ---
def get_user(db: Session, user_id: int):
    return db.query(model_users.User).filter(model_users.User.id == user_id).first()

# NEW/MODIFIED CRUD function for getting user with detailed role and permissions
def get_user_with_role_and_permissions(db: Session, user_id: int):
    return db.query(model_users.User).options(
        joinedload(model_users.User.role).selectinload(model_roles.Role.permissions)
    ).filter(model_users.User.id == user_id).first()

# Also update get_user_by_username for get_current_user if you want 'me' to have full details
def get_user_by_username(db: Session, username: str):
    return db.query(model_users.User).options(
        joinedload(model_users.User.role).selectinload(model_roles.Role.permissions) # Eager load role and its permissions
    ).filter(model_users.User.username == username).first()


def get_user_by_email(db: Session, email: str):
    return db.query(model_users.User).filter(model_users.User.email == email).first()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    return db.query(model_users.User).offset(skip).limit(limit).all()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = security.get_password_hash(user.password)
    db_user = model_users.User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role_id=user.role_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def update_user_last_login(db: Session, user_id: int):
    db_user = get_user(db, user_id) # Use simple get_user here
    if db_user:
        db_user.last_login = datetime.now(timezone.utc)
        db.commit()
        db.refresh(db_user)
    return db_user

# --- Role CRUD ---
def get_role(db: Session, role_id: int):
    # Eager load permissions when fetching a single role
    return db.query(model_roles.Role).options(
        selectinload(model_roles.Role.permissions)
    ).filter(model_roles.Role.id == role_id).first()

def get_role_by_name(db: Session, name: str):
    return db.query(model_roles.Role).options(
        selectinload(model_roles.Role.permissions)
    ).filter(model_roles.Role.name == name).first()

def get_roles(db: Session, skip: int = 0, limit: int = 100):
    # Eager load permissions for list of roles
    return db.query(model_roles.Role).options(
        selectinload(model_roles.Role.permissions)
    ).offset(skip).limit(limit).all()

def create_role(db: Session, role: schemas.RoleCreate):
    db_role = model_roles.Role(name=role.name, description=role.description)
    db.add(db_role)
    db.commit() 

    if role.permissions:
        for perm_data in role.permissions:
            db_perm = model_user_permissions.UserPermission(
                role_id=db_role.id,
                **perm_data.dict()
            )
            db.add(db_perm)
        db.commit() 

    db.refresh(db_role)
    # Manually reload permissions if they weren't part of the initial db_role object
    # after adding them separately, or ensure your schema expects them to be loaded.
    # A simpler way is to fetch the role again after creation if needed.
    return get_role(db, db_role.id) # Fetch again to ensure permissions are loaded

def update_role(db: Session, role_id: int, role_update_data: schemas.RoleUpdate):
    db_role = get_role(db, role_id=role_id) # This get_role already eager loads permissions
    if not db_role:
        return None # Or raise error

    update_data = role_update_data.dict(exclude_unset=True) # Get only provided fields

    # Update basic fields
    if "name" in update_data:
        db_role.name = update_data["name"]
    if "description" in update_data:
        db_role.description = update_data["description"]

    # Handle permissions update: (This is a common strategy: delete old, add new)
    if "permissions" in update_data:
        # 1. Delete existing permissions for this role
        db.query(model_user_permissions.UserPermission).filter(
            model_user_permissions.UserPermission.role_id == role_id
        ).delete(synchronize_session=False) # synchronize_session='fetch' or False

        # 2. Add new permissions
        for perm_data in role_update_data.permissions:
            db_perm = model_user_permissions.UserPermission(
                role_id=role_id,
                module_name=perm_data.module_name,
                can_read=perm_data.can_read,
                can_write=perm_data.can_write,
                can_delete=perm_data.can_delete
            )
            db.add(db_perm)
    
    db.commit()
    db.refresh(db_role)
    return db_role


def delete_role(db: Session, role_id: int):
    db_role = get_role(db, role_id=role_id)
    if not db_role:
        return False # Or raise error
    
    # Permissions associated with the role will be deleted by cascade if set up in DB,
    # or you might need to delete them manually if not.
    # SQLAlchemy's default cascade for ForeignKey without specific cascade rules is usually "save-update, merge".
    # For deletes, you might need ondelete="CASCADE" in your ForeignKey definition in user_permissions.py
    # or delete them explicitly here:
    db.query(model_user_permissions.UserPermission).filter(
        model_user_permissions.UserPermission.role_id == role_id
    ).delete(synchronize_session=False)

    db.delete(db_role)
    db.commit()
    return True


# --- UserPermission CRUD ---
def create_role_permission(db: Session, permission: schemas.UserPermissionCreate, role_id: int):
    db_permission = model_user_permissions.UserPermission(**permission.dict(), role_id=role_id)
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    return db_permission

def get_permissions_for_role(db: Session, role_id: int):
    return db.query(model_user_permissions.UserPermission).filter(model_user_permissions.UserPermission.role_id == role_id).all()