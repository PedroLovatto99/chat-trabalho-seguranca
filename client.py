import asyncio
import base64
import json

import websockets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SERVER_URL = "ws://localhost:8000/ws"


def generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_key, public_pem


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def encrypt_message(text: str, fernet_key: bytes) -> str:
    return Fernet(fernet_key).encrypt(text.encode()).decode()


def decrypt_message(ciphertext: str, fernet_key: bytes) -> str:
    return Fernet(fernet_key).decrypt(ciphertext.encode()).decode()


def wrap_key(fernet_key: bytes, recipient_public_key) -> str:
    encrypted = recipient_public_key.encrypt(fernet_key, oaep())
    return base64.b64encode(encrypted).decode()


def unwrap_key(encrypted_key_b64: str, private_key) -> bytes:
    encrypted = base64.b64decode(encrypted_key_b64)
    return private_key.decrypt(encrypted, oaep())


async def receiver(ws, known_users: dict, private_key, incoming_keys: dict, user_id: str):
    async for raw in ws:
        data = json.loads(raw)
        msg_type = data.get("type")

        if msg_type == "user_list":
            known_users.clear()
            for uid, pem in data["users"].items():
                known_users[uid] = serialization.load_pem_public_key(pem.encode())
            others = [u for u in known_users if u != user_id]
            print(f"\n[usuários online: {', '.join(others)}]\n> ", end="", flush=True)

        elif msg_type == "message":
            peer = data["from"]
            if "encrypted_key" in data:
                incoming_keys[peer] = unwrap_key(data["encrypted_key"], private_key)
            text = decrypt_message(data["ciphertext"], incoming_keys[peer])
            print(f"\n[{peer}] {text}\n> ", end="", flush=True)

        elif msg_type == "error":
            print(f"\n[erro] {data['detail']}\n> ", end="", flush=True)


async def sender(ws, known_users: dict, outgoing_keys: dict, user_id: str):
    loop = asyncio.get_event_loop()
    print("Formato: <usuario_destino> <mensagem>  |  /list")
    while True:
        line = (await loop.run_in_executor(None, input, "> ")).strip()
        if not line:
            continue
        if line == "/list":
            others = [u for u in known_users if u != user_id]
            print(f"[usuários online: {', '.join(others)}]")
            continue
        to_user, _, text = line.partition(" ")
        if not text:
            print("[erro] use: <usuario_destino> <mensagem>")
            continue
        if to_user == user_id:
            print("[erro] você não pode mandar mensagem pra si mesmo")
            continue
        if to_user not in known_users:
            print(f"[erro] usuário '{to_user}' desconhecido (use /list)")
            continue

        is_new_session = to_user not in outgoing_keys
        if is_new_session:
            outgoing_keys[to_user] = Fernet.generate_key()

        envelope = {"to": to_user, "ciphertext": encrypt_message(text, outgoing_keys[to_user])}
        if is_new_session:
            envelope["encrypted_key"] = wrap_key(outgoing_keys[to_user], known_users[to_user])

        await ws.send(json.dumps(envelope))


async def main():
    user_id = input("Seu nome de usuário: ").strip()
    private_key, public_pem = generate_keypair()
    known_users: dict[str, object] = {}
    outgoing_keys: dict[str, bytes] = {}
    incoming_keys: dict[str, bytes] = {}

    async with websockets.connect(f"{SERVER_URL}/{user_id}") as ws:
        await ws.send(json.dumps({"type": "register", "public_key": public_pem}))
        await asyncio.gather(
            receiver(ws, known_users, private_key, incoming_keys, user_id),
            sender(ws, known_users, outgoing_keys, user_id),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, websockets.exceptions.ConnectionClosed):
        print("\nDesconectado.")
