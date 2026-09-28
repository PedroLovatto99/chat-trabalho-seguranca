"""encrypt totp secret and widen column

Revision ID: 006c191af262
Revises: 82891fd8733b
Create Date: 2026-09-28 00:17:30.750475

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '006c191af262'
down_revision: Union[str, Sequence[str], None] = '82891fd8733b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column('usuarios', 'totp_secret',
               existing_type=sa.VARCHAR(length=32),
               type_=sa.Text(),
               existing_nullable=True)

    # Dado que já existia como texto puro antes desta migration precisa ser
    # cifrado agora, senão o login quebra tentando decifrar um valor que nunca
    # foi cifrado.
    from security.mfa import cifrar_totp_secret

    conn = op.get_bind()
    linhas = conn.execute(
        sa.text("SELECT id, totp_secret FROM usuarios WHERE totp_secret IS NOT NULL")
    ).fetchall()
    for id_usuario, secret_atual in linhas:
        conn.execute(
            sa.text("UPDATE usuarios SET totp_secret = :novo WHERE id = :id"),
            {"novo": cifrar_totp_secret(secret_atual), "id": id_usuario},
        )


def downgrade() -> None:
    """Downgrade schema."""
    from security.mfa import decifrar_totp_secret

    conn = op.get_bind()
    linhas = conn.execute(
        sa.text("SELECT id, totp_secret FROM usuarios WHERE totp_secret IS NOT NULL")
    ).fetchall()
    for id_usuario, secret_cifrado in linhas:
        conn.execute(
            sa.text("UPDATE usuarios SET totp_secret = :antigo WHERE id = :id"),
            {"antigo": decifrar_totp_secret(secret_cifrado), "id": id_usuario},
        )

    op.alter_column('usuarios', 'totp_secret',
               existing_type=sa.Text(),
               type_=sa.VARCHAR(length=32),
               existing_nullable=True)
