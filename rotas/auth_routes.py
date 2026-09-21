from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from config.deps import get_current_user
from db.models import Usuario, UserRole
from db.schemas import TokenResponse, TrocaSenhaRequest, UserLogin, UserRegister
from security.audit import registrar_auditoria
from security.auth import create_access_token, hash_password, verify_password
from security.rate_limit import limiter

auth_router = APIRouter(prefix="/auth", tags=["autenticacao"])


@auth_router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(request: Request, data: UserRegister, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else None

    if await db.scalar(select(Usuario).where(Usuario.username == data.username)):
        await registrar_auditoria(
            db, quem=data.email, acao="registro", resultado="falha",
            ip_origem=ip, detalhes="username já existe",
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "usuário já existe")
    if await db.scalar(select(Usuario).where(Usuario.email == data.email)):
        await registrar_auditoria(
            db, quem=data.email, acao="registro", resultado="falha",
            ip_origem=ip, detalhes="email já cadastrado",
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "email já cadastrado")

    usuario = Usuario(
        username=data.username,
        email=data.email,
        password_hash=hash_password(data.password),
        role=UserRole.CLIENTE.value,
    )
    db.add(usuario)
    await registrar_auditoria(db, quem=data.email, acao="registro", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return {"detail": "usuário criado"}


@auth_router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, data: UserLogin, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else None
    usuario = await db.scalar(select(Usuario).where(Usuario.email == data.email))
    if usuario is None or not verify_password(data.password, usuario.password_hash):
        await registrar_auditoria(db, quem=data.email, acao="login", resultado="falha", ip_origem=ip)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "email ou senha inválidos")

    token, jti = create_access_token(usuario.id, usuario.role)
    usuario.jti_ativo = jti
    await registrar_auditoria(db, quem=usuario.username, acao="login", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return TokenResponse(access_token=token, username=usuario.username)


@auth_router.post("/logout")
async def logout(
    usuario: Usuario = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    usuario.jti_ativo = None
    await db.commit()
    return {"detail": "logout realizado"}


@auth_router.patch("/senha")
async def trocar_senha(
    request: Request,
    data: TrocaSenhaRequest,
    usuario: Usuario = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else None

    if not verify_password(data.senha_atual, usuario.password_hash):
        await registrar_auditoria(
            db, quem=usuario.username, acao="troca_senha", resultado="falha",
            ip_origem=ip, detalhes="senha atual incorreta",
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "senha atual incorreta")

    usuario.password_hash = hash_password(data.senha_nova)
    # Invalida a sessão atual — força logar de novo com a senha nova, e derruba
    # qualquer outra sessão ativa (ex: se a conta foi comprometida, trocar a
    # senha já corta o acesso de quem estava usando o token antigo).
    usuario.jti_ativo = None
    await registrar_auditoria(db, quem=usuario.username, acao="troca_senha", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return {"detail": "senha alterada — faça login novamente"}
