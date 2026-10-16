from fastapi import APIRouter

from app.api.v1 import auth, inventory, platform

router = APIRouter(prefix="/api/v1")
router.include_router(auth.router)
router.include_router(platform.router)
router.include_router(inventory.router)
