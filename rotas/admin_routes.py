from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.deps import require_role
from db.database import get_db
from db.models import Usuario, UserRole
from db.schemas import AdminCreateRequest, UsuarioAdminView
from security.auth import hash_password

# `dependencies=[...]` no router aplica o require_role em toda rota daqui — nenhuma
# fica esquecida sem a checagem, mesmo se alguém adicionar uma rota nova depois.
admin_router = APIRouter(
    prefix="/admin",
    tags=["administracao"],
    dependencies=[Depends(require_role(UserRole.ADMINISTRADOR.value))],
)


@admin_router.get("/usuarios", response_model=list[UsuarioAdminView])
async def listar_usuarios(db: AsyncSession = Depends(get_db)):
    result = await db.scalars(select(Usuario).order_by(Usuario.id))
    return result.all()


@admin_router.post(
    "/usuarios", response_model=UsuarioAdminView, status_code=status.HTTP_201_CREATED
)
async def criar_admin(data: AdminCreateRequest, db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(Usuario).where(Usuario.username == data.username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "usuário já existe")
    if await db.scalar(select(Usuario).where(Usuario.email == data.email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "email já cadastrado")

    novo_admin = Usuario(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=UserRole.ADMINISTRADOR.value,
    )
    db.add(novo_admin)
    await db.commit()
    await db.refresh(novo_admin)
    return novo_admin


@admin_router.delete("/usuarios/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def excluir_usuario(user_id: int, db: AsyncSession = Depends(get_db)):
    usuario = await db.get(Usuario, user_id)
    if usuario is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "usuário não encontrado")
    if usuario.role == UserRole.ADMINISTRADOR.value:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "não é possível excluir contas administrador por aqui"
        )

    await db.delete(usuario)
    await db.commit()
