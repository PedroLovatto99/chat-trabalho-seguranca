"""Cria a primeira conta administrador. Não é uma rota da API de propósito — só
roda manualmente (`docker compose run --rm seed-admin`), lendo credenciais de
variável de ambiente. Depois do primeiro admin existir, novos admins devem ser
criados por um admin já autenticado (rota administrativa), não por este script.
"""

import asyncio
import os
import sys

from sqlalchemy import select

from db.database import AsyncSessionLocal
from db.models import Usuario, UserRole
from security.auth import hash_password


async def main() -> None:
    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")

    if not username or not password:
        print("Defina ADMIN_USERNAME e ADMIN_PASSWORD no .env antes de rodar.", file=sys.stderr)
        sys.exit(1)

    async with AsyncSessionLocal() as db:
        existing = await db.scalar(select(Usuario).where(Usuario.username == username))
        if existing is not None:
            print(f"Usuário '{username}' já existe (role atual: {existing.role}) — nada a fazer.")
            return

        admin = Usuario(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMINISTRADOR.value,
        )
        db.add(admin)
        await db.commit()
        print(f"Administrador '{username}' criado com sucesso.")


if __name__ == "__main__":
    asyncio.run(main())
