# db/database.py
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables from .env file in the project root
# Assuming .env is in the parent directory of 'db'
dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
load_dotenv(dotenv_path)

SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")

if not SQLALCHEMY_DATABASE_URL:
    # Fallback if not set, though .env should provide it
    print("Warning: SQLALCHEMY_DATABASE_URL not set, using default sqlite:///./default_fallback.db")
    SQLALCHEMY_DATABASE_URL = "sqlite:///./default_fallback.db" # Stored in project root

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get a DB session for API endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

print(f"Database Engine Initialized with URL: {SQLALCHEMY_DATABASE_URL}")