from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from config.deps import get_current_user
from db.models import Usuario, UserRole
from db.schemas import (
    MfaConfirmarRequest,
    MfaDesativarRequest,
    TokenResponse,
    TrocaSenhaRequest,
    UserLogin,
    UserRegister,
)
from security.audit import registrar_auditoria
from security.auth import create_access_token, hash_password, verify_password
from security.mfa import gerar_totp_secret, totp_provisioning_uri, verificar_totp_code
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


@auth_router.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, data: UserLogin, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else None
    usuario = await db.scalar(select(Usuario).where(Usuario.email == data.email))
    if usuario is None or not verify_password(data.password, usuario.password_hash):
        await registrar_auditoria(db, quem=data.email, acao="login", resultado="falha", ip_origem=ip)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "email ou senha inválidos")

    # Administrador: dois fatores sempre obrigatório (já nasce com totp_secret).
    # Cliente: só se ele mesmo ativou e confirmou via /auth/mfa.
    precisa_mfa = usuario.role == UserRole.ADMINISTRADOR.value or usuario.mfa_confirmado
    if precisa_mfa:
        if usuario.totp_secret is None:
            # Caso de conta legada: o MFA passou a ser obrigatório (só acontece
            # com administrador — cliente só chega em precisa_mfa=True depois de
            # já ter confirmado um segredo) mas essa conta nunca configurou. Gera
            # agora e devolve pra configuração imediata, em vez de travar o login.
            secret = gerar_totp_secret()
            usuario.totp_secret = secret
            await registrar_auditoria(
                db, quem=usuario.username, acao="mfa_setup_automatico", resultado="sucesso",
                ip_origem=ip, detalhes="segredo gerado no primeiro login após MFA virar obrigatório",
            )
            await db.commit()
            return {
                "mfa_setup_required": True,
                "secret": secret,
                "otpauth_url": totp_provisioning_uri(secret, usuario.email),
            }
        if not data.totp_code:
            # senha certa, mas falta o segundo fator — não é erro (200), é o
            # cliente que decide pedir o código e chamar de novo já com ele.
            return {"mfa_required": True}
        if not verificar_totp_code(usuario.totp_secret, data.totp_code):
            await registrar_auditoria(
                db, quem=usuario.username, acao="login", resultado="falha",
                ip_origem=ip, detalhes="código de dois fatores inválido",
            )
            await db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "código de autenticação inválido")

    token, jti = create_access_token(usuario.id, usuario.role)
    usuario.jti_ativo = jti
    await registrar_auditoria(db, quem=usuario.username, acao="login", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return TokenResponse(access_token=token, username=usuario.username, mfa_ativo=precisa_mfa)


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


@auth_router.post("/mfa/ativar")
async def ativar_mfa(
    request: Request,
    usuario: Usuario = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Gera um segredo TOTP novo (não ativa nada ainda — só depois de confirmado
    com /auth/mfa/confirmar o login passa a exigir o código)."""
    ip = request.client.host if request.client else None
    if usuario.role == UserRole.ADMINISTRADOR.value:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "administrador já tem dois fatores obrigatório")

    secret = gerar_totp_secret()
    usuario.totp_secret = secret
    usuario.mfa_confirmado = False
    await registrar_auditoria(db, quem=usuario.username, acao="mfa_ativar", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return {
        "secret": secret,
        "otpauth_url": totp_provisioning_uri(secret, usuario.email),
        "detail": "digite a chave no Google Authenticator e confirme com /auth/mfa/confirmar",
    }


@auth_router.post("/mfa/confirmar")
async def confirmar_mfa(
    request: Request,
    data: MfaConfirmarRequest,
    usuario: Usuario = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else None
    if not usuario.totp_secret:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "nenhuma configuração pendente — use /auth/mfa/ativar primeiro"
        )

    if not verificar_totp_code(usuario.totp_secret, data.codigo):
        await registrar_auditoria(
            db, quem=usuario.username, acao="mfa_confirmar", resultado="falha",
            ip_origem=ip, detalhes="código inválido",
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "código inválido")

    usuario.mfa_confirmado = True
    await registrar_auditoria(db, quem=usuario.username, acao="mfa_confirmar", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return {"detail": "dois fatores ativado"}


@auth_router.post("/mfa/desativar")
async def desativar_mfa(
    request: Request,
    data: MfaDesativarRequest,
    usuario: Usuario = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    ip = request.client.host if request.client else None
    if usuario.role == UserRole.ADMINISTRADOR.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "administrador não pode desativar dois fatores")

    if not verify_password(data.senha, usuario.password_hash):
        await registrar_auditoria(
            db, quem=usuario.username, acao="mfa_desativar", resultado="falha",
            ip_origem=ip, detalhes="senha incorreta",
        )
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "senha incorreta")

    usuario.totp_secret = None
    usuario.mfa_confirmado = False
    await registrar_auditoria(db, quem=usuario.username, acao="mfa_desativar", resultado="sucesso", ip_origem=ip)
    await db.commit()
    return {"detail": "dois fatores desativado"}
