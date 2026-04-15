from app.database import engine
from sqlalchemy import text

if __name__ == "__main__":
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS hndl_breakdown JSON DEFAULT '{}'::json;"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS server_software VARCHAR(200);"))
            conn.execute(text("ALTER TABLE assets ADD COLUMN IF NOT EXISTS network_type VARCHAR(20) DEFAULT 'public';"))
            conn.execute(text("ALTER TABLE remediations ADD COLUMN IF NOT EXISTS detailed_report TEXT;"))
            print("Migration successful")
        except Exception as e:
            print("Migration failed:", e)
