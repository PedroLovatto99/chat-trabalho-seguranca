"""add audit_log table

Revision ID: 4d9167f7d404
Revises: 521aa2d95cdd
Create Date: 2026-09-20 02:39:47.306584

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from config.settings import settings


# revision identifiers, used by Alembic.
revision: str = '4d9167f7d404'
down_revision: Union[str, Sequence[str], None] = '521aa2d95cdd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('audit_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('quem', sa.String(length=255), nullable=False),
    sa.Column('acao', sa.String(length=50), nullable=False),
    sa.Column('quando', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('ip_origem', sa.String(length=45), nullable=True),
    sa.Column('resultado', sa.String(length=10), nullable=False),
    sa.Column('detalhes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_log_quando'), 'audit_log', ['quando'], unique=False)

    # Apenas-inserção: o `ALTER DEFAULT PRIVILEGES` do postgres-init libera
    # SELECT/INSERT/UPDATE/DELETE por padrão pra role de runtime da API em toda
    # tabela nova — aqui revogamos UPDATE/DELETE especificamente, então nem um
    # bug no código da API consegue alterar ou apagar um log já gravado (só a
    # role dona do schema poderia, e ela nunca é usada pela API).
    op.execute(f'REVOKE UPDATE, DELETE ON audit_log FROM "{settings.app_db_user}"')


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_audit_log_quando'), table_name='audit_log')
    op.drop_table('audit_log')
