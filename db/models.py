import enum
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


class UserRole(str, enum.Enum):
    CLIENTE = "cliente"
    ADMINISTRADOR = "administrador"


class Usuario(Base):
    __tablename__ = "usuarios"
    __table_args__ = (
        CheckConstraint("role IN ('cliente', 'administrador')", name="ck_usuarios_role"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(
        String(20), default=UserRole.CLIENTE.value, server_default=UserRole.CLIENTE.value
    )
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    jti_ativo: Mapped[str | None] = mapped_column(String(36), nullable=True)
    totp_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Só tem efeito pra `cliente` (opt-in via /auth/mfa/ativar + /auth/mfa/confirmar).
    # Pra `administrador` o MFA é obrigatório sempre, checado pelo role no login,
    # independente deste campo — administrador já nasce com totp_secret preenchido.
    mfa_confirmado: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class AuditLog(Base):
    """Log de auditoria — apenas-inserção (a role de runtime da API tem
    UPDATE/DELETE revogados nessa tabela via migration, então nem um bug no
    código consegue alterar/apagar um registro já gravado).

    Os "5 W's": quem (quem fez/tentou), acao (o quê), quando (server_default,
    não é hora do cliente), ip_origem (de onde), resultado (sucesso/falha).
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    quem: Mapped[str] = mapped_column(String(255))
    acao: Mapped[str] = mapped_column(String(50))
    quando: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    ip_origem: Mapped[str | None] = mapped_column(String(45), nullable=True)
    resultado: Mapped[str] = mapped_column(String(10))
    detalhes: Mapped[str | None] = mapped_column(Text, nullable=True)
