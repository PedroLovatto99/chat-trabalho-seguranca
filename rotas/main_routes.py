import jwt
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from db.models import Usuario, UserRole
from security.auth import decode_access_token

from .connection import ConnectionManager

order_router = APIRouter()

manager = ConnectionManager()


async def _authenticate(websocket: WebSocket, db: AsyncSession) -> Usuario | None:
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    try:
        payload = decode_access_token(auth_header.removeprefix("Bearer "))
    except jwt.PyJWTError:
        return None

    usuario = await db.get(Usuario, int(payload["sub"]))
    if usuario is None or usuario.jti_ativo != payload.get("jti"):
        return None
    return usuario


@order_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    usuario = await _authenticate(websocket, db)
    if usuario is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="não autenticado")
        return
    if usuario.role != UserRole.CLIENTE.value:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="papel sem permissão de chat"
        )
        return

    user_id = usuario.username
    await manager.connect(user_id, websocket)

    register = await websocket.receive_json()
    manager.register_public_key(user_id, register["public_key"])
    await manager.broadcast_user_list()

    try:
        while True:
            data = await websocket.receive_json()
            to_user_id = data["to"]
            envelope = {"type": "message", "from": user_id, "ciphertext": data["ciphertext"]}
            if "encrypted_key" in data:
                envelope["encrypted_key"] = data["encrypted_key"]
            delivered = await manager.send_personal_message(envelope, to_user_id)
            if not delivered:
                await websocket.send_json(
                    {"type": "error", "detail": f"'{to_user_id}' não está online"}
                )
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        await manager.broadcast_user_list()
