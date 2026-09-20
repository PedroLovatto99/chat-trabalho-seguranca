from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.deps import require_role
from db.database import get_db
from db.models import Usuario, UserRole
from db.schemas import AdminCreateRequest, UsuarioAdminView
from security.audit import registrar_auditoria
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
async def criar_admin(
    request: Request,
    data: AdminCreateRequest,
    db: AsyncSession = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(UserRole.ADMINISTRADOR.value)),
):
    ip = request.client.host if request.client else None

    if await db.scalar(select(Usuario).where(Usuario.username == data.username)):
        await registrar_auditoria(
            db, quem=admin_atual.username, acao="criacao_admin", resultado="falha",
            ip_origem=ip, detalhes=f"username já existe: {data.username}",
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "usuário já existe")
    if await db.scalar(select(Usuario).where(Usuario.email == data.email)):
        await registrar_auditoria(
            db, quem=admin_atual.username, acao="criacao_admin", resultado="falha",
            ip_origem=ip, detalhes=f"email já cadastrado: {data.email}",
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "email já cadastrado")

    novo_admin = Usuario(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=UserRole.ADMINISTRADOR.value,
    )
    db.add(novo_admin)
    await registrar_auditoria(
        db, quem=admin_atual.username, acao="criacao_admin", resultado="sucesso",
        ip_origem=ip, detalhes=f"novo admin: {data.username}",
    )
    await db.commit()
    await db.refresh(novo_admin)
    return novo_admin


@admin_router.delete("/usuarios/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def excluir_usuario(
    request: Request,
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin_atual: Usuario = Depends(require_role(UserRole.ADMINISTRADOR.value)),
):
    ip = request.client.host if request.client else None
    usuario = await db.get(Usuario, user_id)
    if usuario is None:
        await registrar_auditoria(
            db, quem=admin_atual.username, acao="remocao_usuario", resultado="falha",
            ip_origem=ip, detalhes=f"id {user_id} não encontrado",
        )
        await db.commit()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "usuário não encontrado")
    if usuario.role == UserRole.ADMINISTRADOR.value:
        await registrar_auditoria(
            db, quem=admin_atual.username, acao="remocao_usuario", resultado="falha",
            ip_origem=ip, detalhes=f"tentativa de excluir admin: {usuario.username}",
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "não é possível excluir contas administrador por aqui"
        )

    detalhes = f"usuário removido: {usuario.username}"
    await db.delete(usuario)
    await registrar_auditoria(
        db, quem=admin_atual.username, acao="remocao_usuario", resultado="sucesso",
        ip_origem=ip, detalhes=detalhes,
    )
    await db.commit()
