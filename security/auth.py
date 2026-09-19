import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from config.settings import settings


def validar_senha_forte(password: str) -> None:
    """Levanta ValueError se a senha não tiver ao menos 1 maiúscula e 1 número.
    Único lugar com essa regra — usado pelos schemas Pydantic (API) e pelo
    seed_admin.py (que não passa pela validação de request)."""
    if not any(c.isupper() for c in password):
        raise ValueError("a senha precisa ter pelo menos uma letra maiúscula")
    if not any(c.isdigit() for c in password):
        raise ValueError("a senha precisa ter pelo menos um número")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def create_access_token(user_id: int, role: str) -> tuple[str, str]:
    """Gera um JWT novo e o jti correspondente (a chamar guarda em jti_ativo)."""
    jti = str(uuid.uuid4())
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {"sub": str(user_id), "role": role, "jti": jti, "exp": expire}
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
