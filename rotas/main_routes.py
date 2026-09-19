import asyncio
import json
import logging
import time

import jwt
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession

from db.database import get_db
from db.models import Usuario, UserRole
from security.auth import decode_access_token

from .connection import ConnectionManager

order_router = APIRouter()

manager = ConnectionManager()
logger = logging.getLogger("chat_seguro")

# Anti-DoS: sem isso, uma conexão já autenticada poderia mandar mensagens sem
# limite (esgotando CPU/banda) ou um payload gigante (esgotando memória).
MAX_MENSAGENS_POR_SEGUNDO = 5
MAX_PAYLOAD_BYTES = 64 * 1024  # 64 KB — sobra pra texto cifrado normal


async def _authenticate(websocket: WebSocket, db: AsyncSession) -> tuple[Usuario, int] | None:
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
    return usuario, payload["exp"]


async def _expirar_sessao(websocket: WebSocket, exp: int) -> None:
    """Derruba a conexão sozinha quando o JWT expira — sem isso, uma sessão de
    WebSocket já aberta ficaria válida indefinidamente, mesmo com token vencido
    (a checagem de expiração só rodava uma vez, no handshake)."""
    restante = exp - time.time()
    if restante > 0:
        await asyncio.sleep(restante)
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="sessão expirada")


@order_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, db: AsyncSession = Depends(get_db)):
    resultado = await _authenticate(websocket, db)
    if resultado is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="não autenticado")
        return
    usuario, exp = resultado
    if usuario.role != UserRole.CLIENTE.value:
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION, reason="papel sem permissão de chat"
        )
        return

    user_id = usuario.username
    await manager.connect(user_id, websocket)
    watchdog = asyncio.create_task(_expirar_sessao(websocket, exp))

    try:
        register = await websocket.receive_json()
        manager.register_public_key(user_id, register["public_key"])
        await manager.broadcast_user_list()

        janela_inicio = time.monotonic()
        mensagens_na_janela = 0

        while True:
            raw = await websocket.receive_text()

            if len(raw.encode("utf-8")) > MAX_PAYLOAD_BYTES:
                await websocket.send_json(
                    {"type": "error", "detail": "mensagem excede o tamanho máximo permitido"}
                )
                continue

            agora = time.monotonic()
            if agora - janela_inicio >= 1:
                janela_inicio = agora
                mensagens_na_janela = 0
            mensagens_na_janela += 1
            if mensagens_na_janela > MAX_MENSAGENS_POR_SEGUNDO:
                await websocket.send_json(
                    {"type": "error", "detail": "muitas mensagens em pouco tempo — aguarde um instante"}
                )
                continue

            try:
                data = json.loads(raw)
                to_user_id = data["to"]
                ciphertext = data["ciphertext"]
            except (json.JSONDecodeError, KeyError, TypeError):
                await websocket.send_json({"type": "error", "detail": "mensagem mal formada"})
                continue

            envelope = {"type": "message", "from": user_id, "ciphertext": ciphertext}
            if "encrypted_key" in data:
                envelope["encrypted_key"] = data["encrypted_key"]
            delivered = await manager.send_personal_message(envelope, to_user_id)
            if not delivered:
                await websocket.send_json(
                    {"type": "error", "detail": f"'{to_user_id}' não está online"}
                )
    except WebSocketDisconnect:
        pass
    except Exception:
        # Rede de segurança: um erro não previsto aqui não deve travar o
        # servidor nem vazar detalhes internos pro cliente — só fecha a conexão.
        logger.exception("erro não tratado na conexão WebSocket de '%s'", user_id)
        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="erro interno")
        except RuntimeError:
            pass  # conexão já estava fechada
    finally:
        watchdog.cancel()
        manager.disconnect(user_id)
        await manager.broadcast_user_list()
