from app.database import engine
from sqlalchemy import text

if __name__ == "__main__":
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS hndl_breakdown JSON DEFAULT '{}'::json;"))
            print("Migration successful")
        except Exception as e:
            print("Migration failed:", e)
