from fastapi import APIRouter
from app.api.scan import scan_router

api_router = APIRouter()

# Register sub-routers
api_router.include_router(scan_router)


@api_router.get("/health")
async def health_check():
    return {"status": "ok", "message": "AuthTrack Backend API is fully functional"}
