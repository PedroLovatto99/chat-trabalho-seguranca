
from fastapi import WebSocket, WebSocketDisconnect


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
        self.public_keys: dict[str, str] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def register_public_key(self, user_id: str, public_key: str):
        self.public_keys[user_id] = public_key

    def disconnect(self, user_id: str):
        self.active_connections.pop(user_id, None)
        self.public_keys.pop(user_id, None)

    async def send_personal_message(self, message: dict, to_user_id: str) -> bool:
        websocket = self.active_connections.get(to_user_id)
        if websocket is None:
            return False
        await websocket.send_json(message)
        return True

    async def broadcast_user_list(self):
        payload = {"type": "user_list", "users": self.public_keys}
        for connection in self.active_connections.values():
            await connection.send_json(payload)
