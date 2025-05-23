# main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm # For login form
from sqlalchemy.orm import Session
from typing import List
from datetime import timedelta

# Database and ORM related imports
from db import crud, database
from modeles import users, roles, user_permissions # Import all models to ensure Base knows them
from schema import schemas
from security import security # For auth functions and token creation

# Create database tables
try:
    print("Attempting to create database tables...")
    database.Base.metadata.create_all(bind=database.engine)
    print("Database tables checked/created successfully.")
except Exception as e:
    print(f"Error creating database tables: {e}")


app = FastAPI(title="User Management API")

# Dependency to get DB session
def get_db_session():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Authentication & User Endpoints ---

@app.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db_session)):
    db_user_by_email = crud.get_user_by_email(db, email=user.email)
    if db_user_by_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    db_user_by_username = crud.get_user_by_username(db, username=user.username)
    if db_user_by_username:
        raise HTTPException(status_code=400, detail="Username already taken")
    
    if user.role_id:
        role = crud.get_role(db, role_id=user.role_id)
        if not role:
            raise HTTPException(status_code=404, detail=f"Role with id {user.role_id} not found")
            
    return crud.create_user(db=db, user=user)

@app.post("/login", response_model=schemas.Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db_session)
):
    user = crud.get_user_by_username(db, username=form_data.username)
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    access_token_expires = timedelta(minutes=security.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    crud.update_user_last_login(db, user_id=user.id)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.UserProfile)
async def read_users_me(current_user: schemas.User = Depends(security.get_current_active_user)):
    # The current_user object is already a SQLAlchemy model instance.
    # Pydantic's orm_mode will handle the conversion.
    # Ensure role and permissions are loaded if not by default (see crud.py update below)
    return current_user

# NEW ENDPOINT: Get User Profile by ID
@app.get("/users/{user_id}", response_model=schemas.UserProfile)
def view_user_profile(
    user_id: int, 
    db: Session = Depends(get_db_session),
    requesting_user: schemas.User = Depends(security.get_current_active_user) # Renamed for clarity
):
    # Permission Check Example:
    # Allow user to view their own profile, or allow admins to view any profile.
    # For simplicity, let's assume an admin role would have ID 1 or a specific name.
    # This is a basic example; a more robust system would check permissions from the role.
    
    # is_admin = False
    # if requesting_user.role and requesting_user.role.name == "Administrator": # Or check ID
    #     is_admin = True

    # if requesting_user.id != user_id and not is_admin:
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to view this profile")

    db_user = crud.get_user_with_role_and_permissions(db, user_id=user_id) # Using a new CRUD function
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return db_user

# --- Role Endpoints ---

@app.get("/roles", response_model=List[schemas.Role])
def list_roles(
    skip: int = 0, limit: int = 10, db: Session = Depends(get_db_session),
    current_user: schemas.User = Depends(security.get_current_active_user) 
):
    roles_list = crud.get_roles(db, skip=skip, limit=limit)
    return roles_list

@app.post("/roles", response_model=schemas.Role, status_code=status.HTTP_201_CREATED)
def add_role(
    role: schemas.RoleCreate, db: Session = Depends(get_db_session),
    current_user: schemas.User = Depends(security.get_current_active_user)
):
    db_role = crud.get_role_by_name(db, name=role.name)
    if db_role:
        raise HTTPException(status_code=400, detail="Role name already exists")
    return crud.create_role(db=db, role=role)


# --- Potentially other endpoints (PUT/DELETE for users/roles) would go here ---
# Example: Update a role
@app.put("/roles/{role_id}", response_model=schemas.Role)
def update_role(
    role_id: int,
    role_update_data: schemas.RoleUpdate,
    db: Session = Depends(get_db_session),
    current_user: schemas.User = Depends(security.get_current_active_user)
):
    # Permission check: Only admins should update roles.
    # if not current_user.role or current_user.role.name != "Administrator":
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to update roles")

    db_role = crud.get_role(db, role_id=role_id)
    if not db_role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

    # Check if new name conflicts (if name is being changed)
    if role_update_data.name and role_update_data.name != db_role.name:
        existing_role_with_new_name = crud.get_role_by_name(db, name=role_update_data.name)
        if existing_role_with_new_name:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Another role with this name already exists")
            
    updated_role = crud.update_role(db=db, role_id=role_id, role_update_data=role_update_data)
    return updated_role

# Example: Delete a role
@app.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    role_id: int,
    db: Session = Depends(get_db_session),
    current_user: schemas.User = Depends(security.get_current_active_user)
):
    # Permission check: Only admins should delete roles.
    # if not current_user.role or current_user.role.name != "Administrator":
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to delete roles")

    db_role = crud.get_role(db, role_id=role_id)
    if not db_role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    
    # Check if any users are assigned this role before deleting
    if db_role.users: # Accesses the 'users' relationship defined in modeles/roles.py
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete role: users are still assigned to it.")

    crud.delete_role(db=db, role_id=role_id)
    return # For 204 No Content, FastAPI handles sending no body


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)