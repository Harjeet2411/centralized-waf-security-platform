from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.contract import BootstrapOut, PrincipalOut
from app.security import Principal, get_principal, require
from app.services.bootstrap_service import build_bootstrap

router = APIRouter(tags=["platform"])


@router.get("/me", response_model=PrincipalOut)
async def me(principal: Principal = Depends(get_principal)) -> PrincipalOut:
    return PrincipalOut(
        user_id=str(principal.user_id), email=principal.email, full_name=principal.full_name, role=principal.role,
        permissions=list(principal.permissions), scoped_account_ids=list(principal.scoped_account_ids),
        mfa=principal.mfa,
    )


@router.get("/bootstrap", response_model=BootstrapOut)
async def bootstrap(_: Principal = Depends(require("VIEW")), db: AsyncSession = Depends(get_db)) -> BootstrapOut:
    return await build_bootstrap(db)
