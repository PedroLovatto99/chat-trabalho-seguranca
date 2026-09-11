import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from db.models import Usuario
from security.auth import decode_access_token

bearer_scheme = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> Usuario:
    try:
        payload = decode_access_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token inválido ou expirado")

    user = await db.get(Usuario, int(payload["sub"]))
    if user is None or user.jti_ativo != payload.get("jti"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sessão inválida — faça login novamente")

    return user


def require_role(role: str):
    async def _checker(usuario: Usuario = Depends(get_current_user)) -> Usuario:
        if usuario.role != role:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "acesso negado para esse papel")
        return usuario

    return _checker
