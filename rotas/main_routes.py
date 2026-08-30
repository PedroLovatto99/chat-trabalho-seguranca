from fastapi import APIRouter
from fastapi import WebSocket, WebSocketDisconnect
from .connection import ConnectionManager

order_router = APIRouter()

manager = ConnectionManager()

@order_router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
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
