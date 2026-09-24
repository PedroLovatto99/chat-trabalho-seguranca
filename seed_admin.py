"""Cria a primeira conta administrador. Não é uma rota da API de propósito — só
roda manualmente (`docker compose run --rm seed-admin`), lendo credenciais de
variável de ambiente. Depois do primeiro admin existir, novos admins devem ser
criados por um admin já autenticado (rota administrativa), não por este script.
"""

import asyncio
import os
import sys

from sqlalchemy import or_, select

from db.database import AsyncSessionLocal
from db.models import Usuario, UserRole
from security.auth import hash_password, validar_senha_forte
from security.mfa import gerar_totp_secret, print_qr_ascii, totp_provisioning_uri


async def main() -> None:
    username = os.environ.get("ADMIN_USERNAME")
    email = os.environ.get("ADMIN_EMAIL")
    password = os.environ.get("ADMIN_PASSWORD")

    if not username or not email or not password:
        print(
            "Defina ADMIN_USERNAME, ADMIN_EMAIL e ADMIN_PASSWORD no .env antes de rodar.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        validar_senha_forte(password)
    except ValueError as erro:
        print(f"ADMIN_PASSWORD inválida: {erro}", file=sys.stderr)
        sys.exit(1)

    async with AsyncSessionLocal() as db:
        existing = await db.scalar(
            select(Usuario).where(or_(Usuario.username == username, Usuario.email == email))
        )
        if existing is not None:
            print(
                f"Usuário '{existing.username}' (email {existing.email}) já existe "
                f"(role atual: {existing.role}) — nada a fazer."
            )
            return

        secret = gerar_totp_secret()
        admin = Usuario(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=UserRole.ADMINISTRADOR.value,
            totp_secret=secret,
        )
        db.add(admin)
        await db.commit()
        print(f"Administrador '{username}' criado com sucesso.")
        print(
            "\nDois fatores é obrigatório para administrador — configure agora no "
            "Google Authenticator (ou outro app TOTP compatível):"
        )
        uri = totp_provisioning_uri(secret, email)
        print(f"  Chave manual: {secret}")
        print(f"  URI (otpauth://): {uri}")
        print("\nOu escaneie o QR code abaixo:\n")
        print_qr_ascii(uri)


if __name__ == "__main__":
    asyncio.run(main())
