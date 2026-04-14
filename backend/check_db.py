from app.database import SessionLocal
from app.models.models import User
import sys
import os

sys.path.append(os.path.join(os.getcwd(), "backend"))

def check_db():
    try:
        db = SessionLocal()
        user_count = db.query(User).count()
        print(f"Database connection successful! User count: {user_count}")
        db.close()
    except Exception as e:
        print(f"Database connection failed: {e}")

if __name__ == "__main__":
    check_db()
