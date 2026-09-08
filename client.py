import asyncio
import base64
import getpass
import json

import httpx
import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatus
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_SERVER = "localhost:8000"


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


class LogoutRequested(Exception):
    """Sinaliza que o usuário pediu pra sair com /sair (logout limpo, sem Ctrl+C)."""


def _format_error(detail) -> str:
    """Formata o corpo de erro do FastAPI — tanto {"detail": "texto"} quanto os erros
    de validação do Pydantic ({"detail": [{"loc": [...], "msg": "..."}]})."""
    if isinstance(detail, list):
        partes = []
        for erro in detail:
            campo = erro.get("loc", ["?"])[-1]
            partes.append(f"{campo}: {erro.get('msg')}")
        return "; ".join(partes)
    return str(detail)


def register(base_url: str) -> tuple[str, str]:
    """Formulário próprio de criação de conta — campos independentes da tentativa
    de login que levou até aqui, para não reaproveitar usuário/senha silenciosamente."""
    while True:
        username = input("Novo usuário: ").strip()
        password = getpass.getpass("Nova senha (mín. 8 caracteres): ")

        reg = httpx.post(
            f"{base_url}/auth/register", json={"username": username, "password": password}
        )
        if reg.status_code == 201:
            return username, password

        print(f"[erro] não foi possível criar a conta: {_format_error(reg.json().get('detail'))}\n")


def login_or_register(base_url: str) -> tuple[str, str]:
    while True:
        username = input("Usuário: ").strip()
        password = getpass.getpass("Senha: ")

        resp = httpx.post(
            f"{base_url}/auth/login", json={"username": username, "password": password}
        )
        if resp.status_code == 200:
            return username, resp.json()["access_token"]

        if resp.status_code != 401:
            print(f"[erro] login falhou: {_format_error(resp.json().get('detail', resp.text))}\n")
            continue

        criar = input(
            "Usuário/senha não encontrados. Criar uma conta nova? [s/N] "
        ).strip().lower()
        if criar != "s":
            continue

        username, password = register(base_url)

        resp = httpx.post(
            f"{base_url}/auth/login", json={"username": username, "password": password}
        )
        resp.raise_for_status()
        return username, resp.json()["access_token"]


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
    print("Formato: <usuario_destino> <mensagem>  |  /list  |  /sair")
    while True:
        line = (await loop.run_in_executor(None, input, "> ")).strip()
        if not line:
            continue
        if line == "/sair":
            raise LogoutRequested()
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
    server = input(f"Endereço do servidor [{DEFAULT_SERVER}]: ").strip() or DEFAULT_SERVER
    base_url = f"http://{server}"
    ws_url = f"ws://{server}/ws"

    user_id, token = login_or_register(base_url)

    private_key, public_pem = generate_keypair()
    known_users: dict[str, object] = {}
    outgoing_keys: dict[str, bytes] = {}
    incoming_keys: dict[str, bytes] = {}

    try:
        async with websockets.connect(
            ws_url, additional_headers={"Authorization": f"Bearer {token}"}
        ) as ws:
            await ws.send(json.dumps({"type": "register", "public_key": public_pem}))
            await asyncio.gather(
                receiver(ws, known_users, private_key, incoming_keys, user_id),
                sender(ws, known_users, outgoing_keys, user_id),
            )
    except InvalidStatus:
        print("[erro] conexão recusada — verifique se sua conta é do tipo 'cliente'")
    except LogoutRequested:
        httpx.post(f"{base_url}/auth/logout", headers={"Authorization": f"Bearer {token}"})
        print("\nVocê saiu.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, ConnectionClosed):
        print("\nDesconectado.")
