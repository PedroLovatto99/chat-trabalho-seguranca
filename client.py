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


class SenhaAlterada(Exception):
    """Sinaliza que a senha foi trocada — o servidor já invalidou a sessão atual
    (POST /auth/senha zera o jti_ativo), então o programa encerra pedindo pra
    logar de novo com a senha nova, sem tentar chamar /auth/logout de novo."""


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
    de login que levou até aqui, para não reaproveitar usuário/senha silenciosamente.
    Retorna (email, password), usados em seguida pra logar de verdade."""
    while True:
        username = input("Novo usuário (nome exibido no chat): ").strip()
        email = input("Email: ").strip()
        password = getpass.getpass("Nova senha (mín. 8, com 1 maiúscula e 1 número): ")

        reg = httpx.post(
            f"{base_url}/auth/register",
            json={"username": username, "email": email, "password": password},
        )
        if reg.status_code == 201:
            return email, password

        print(f"[erro] não foi possível criar a conta: {_format_error(reg.json().get('detail'))}\n")


def login_or_register(base_url: str) -> tuple[str, str]:
    """Login é por email; o servidor devolve o username (usado como identidade no
    chat) junto do token, então o usuário não precisa saber/digitar o próprio
    username de novo depois de logar."""
    while True:
        email = input("Email: ").strip()
        password = getpass.getpass("Senha: ")

        resp = httpx.post(f"{base_url}/auth/login", json={"email": email, "password": password})
        if resp.status_code == 200:
            data = resp.json()
            return data["username"], data["access_token"]

        if resp.status_code != 401:
            print(f"[erro] login falhou: {_format_error(resp.json().get('detail', resp.text))}\n")
            continue

        criar = input(
            "Email/senha não encontrados. Criar uma conta nova? [s/N] "
        ).strip().lower()
        if criar != "s":
            continue

        email, password = register(base_url)

        resp = httpx.post(f"{base_url}/auth/login", json={"email": email, "password": password})
        resp.raise_for_status()
        data = resp.json()
        return data["username"], data["access_token"]


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


async def sender(ws, known_users: dict, outgoing_keys: dict, user_id: str, base_url: str, token: str):
    loop = asyncio.get_event_loop()
    print("Formato: <usuario_destino> <mensagem>  |  /list  |  /senha  |  /sair")
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
        if line == "/senha":
            senha_atual = await loop.run_in_executor(None, getpass.getpass, "Senha atual: ")
            senha_nova = await loop.run_in_executor(
                None, getpass.getpass, "Nova senha (mín. 8, com 1 maiúscula e 1 número): "
            )
            resp = await loop.run_in_executor(
                None,
                lambda: httpx.patch(
                    f"{base_url}/auth/senha",
                    json={"senha_atual": senha_atual, "senha_nova": senha_nova},
                    headers={"Authorization": f"Bearer {token}"},
                ),
            )
            if resp.status_code == 200:
                print("[ok] senha alterada — você vai ser desconectado, entre de novo com a senha nova")
                raise SenhaAlterada()
            print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}")
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
                sender(ws, known_users, outgoing_keys, user_id, base_url, token),
            )
    except InvalidStatus:
        print("[erro] conexão recusada — verifique se sua conta é do tipo 'cliente'")
    except LogoutRequested:
        httpx.post(f"{base_url}/auth/logout", headers={"Authorization": f"Bearer {token}"})
        print("\nVocê saiu.")
    except SenhaAlterada:
        print("\nSenha alterada. Rode o programa de novo pra entrar com a senha nova.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, ConnectionClosed):
        print("\nDesconectado.")
