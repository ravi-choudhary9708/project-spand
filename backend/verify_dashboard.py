import asyncio
from app.database import SessionLocal
from app.routers.dashboard_router import get_dashboard

async def main():
    db = SessionLocal()
    try:
        res = await get_dashboard(db=db, current_user=None)
        print("SUCCESS! Output keys:", list(res.keys()))
    except Exception as e:
        print("FAILED:", e)
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
