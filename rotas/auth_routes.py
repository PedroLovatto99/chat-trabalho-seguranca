from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from config.deps import get_current_user
from db.models import Usuario, UserRole
from db.schemas import TokenResponse, UserLogin, UserRegister
from security.auth import create_access_token, hash_password, verify_password

auth_router = APIRouter(prefix="/auth", tags=["autenticacao"])


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(data: UserRegister, db: AsyncSession = Depends(get_db)):
    existing = await db.scalar(select(Usuario).where(Usuario.username == data.username))
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "usuário já existe")

    usuario = Usuario(
        username=data.username,
        password_hash=hash_password(data.password),
        role=UserRole.CLIENTE.value,
    )
    db.add(usuario)
    await db.commit()
    return {"detail": "usuário criado"}


@auth_router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    usuario = await db.scalar(select(Usuario).where(Usuario.username == data.username))
    if usuario is None or not verify_password(data.password, usuario.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "usuário ou senha inválidos")

    token, jti = create_access_token(usuario.id, usuario.role)
    usuario.jti_ativo = jti
    await db.commit()
    return TokenResponse(access_token=token)


@auth_router.post("/logout")
async def logout(
    usuario: Usuario = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    usuario.jti_ativo = None
    await db.commit()
    return {"detail": "logout realizado"}
