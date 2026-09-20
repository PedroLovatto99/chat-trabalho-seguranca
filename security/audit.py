from sqlalchemy.ext.asyncio import AsyncSession

from db.models import AuditLog


async def registrar_auditoria(
    db: AsyncSession,
    *,
    quem: str,
    acao: str,
    resultado: str,
    ip_origem: str | None = None,
    detalhes: str | None = None,
) -> None:
    """Adiciona uma linha de auditoria à sessão (não comita sozinho — quem chama
    decide quando, geralmente junto do commit da ação principal, pra ficar tudo
    atômico: ou grava os dois, ou nenhum)."""
    db.add(
        AuditLog(
            quem=quem,
            acao=acao,
            resultado=resultado,
            ip_origem=ip_origem,
            detalhes=detalhes,
        )
    )
