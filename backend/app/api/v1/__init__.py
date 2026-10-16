from fastapi import APIRouter

from app.api.v1 import auth, governance, inventory, platform, response

router = APIRouter(prefix="/api/v1")
router.include_router(auth.router)
router.include_router(platform.router)
router.include_router(inventory.router)
router.include_router(response.router)
router.include_router(governance.router)
