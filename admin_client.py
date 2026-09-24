import getpass
import sys

import httpx
import qrcode

DEFAULT_SERVER = "localhost:8000"


def _print_qr(otpauth_url: str) -> None:
    """Desenha o QR code direto no terminal — o Google Authenticator escaneia
    isso na tela normalmente. Se o terminal não suportar (encoding antigo),
    não trava o fluxo — quem chama sempre mostra a chave manual também."""
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(otpauth_url)
        qr.make()
        qr.print_ascii(tty=sys.stdout.isatty())
    except (OSError, UnicodeEncodeError):
        print("(não foi possível desenhar o QR code neste terminal — use a chave manual abaixo)")


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


def _tentar_login(base_url: str, email: str, password: str) -> httpx.Response:
    """POST /auth/login. Administrador sempre exige dois fatores — cuida do
    segundo passo aqui mesmo (mostra a chave se for a primeira vez, pede o
    código, reenvia) antes de devolver a resposta final pro chamador."""
    resp = httpx.post(f"{base_url}/auth/login", json={"email": email, "password": password})
    if resp.status_code != 200:
        return resp

    data = resp.json()
    if data.get("mfa_setup_required"):
        print("\n[dois fatores obrigatório] configure agora no Google Authenticator:")
        _print_qr(data["otpauth_url"])
        print(f"  (ou digite a chave manual: {data['secret']})")
        codigo = input("Código gerado pelo app: ").strip()
        return httpx.post(
            f"{base_url}/auth/login",
            json={"email": email, "password": password, "totp_code": codigo},
        )
    if data.get("mfa_required"):
        codigo = input("Código do Google Authenticator: ").strip()
        return httpx.post(
            f"{base_url}/auth/login",
            json={"email": email, "password": password, "totp_code": codigo},
        )
    return resp


def login(base_url: str) -> str:
    """Só login — contas administrador não têm autocadastro (nem aqui)."""
    while True:
        email = input("Email (admin): ").strip()
        password = getpass.getpass("Senha: ")

        resp = _tentar_login(base_url, email, password)
        if resp.status_code == 200:
            return resp.json()["access_token"]

        print(f"[erro] login falhou: {_format_error(resp.json().get('detail', resp.text))}\n")


def listar_usuarios(base_url: str, token: str) -> None:
    resp = httpx.get(f"{base_url}/admin/usuarios", headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")
        return

    usuarios = resp.json()
    if not usuarios:
        print("(nenhum usuário cadastrado)\n")
        return

    print(f"\n{'id':<4} {'username':<20} {'email':<25} {'role':<15} password_hash")
    for u in usuarios:
        print(
            f"{u['id']:<4} {u['username']:<20} {u['email']:<25} {u['role']:<15} "
            f"{u['password_hash']}"
        )
    print()


def criar_admin(base_url: str, token: str) -> None:
    username = input("Usuário do novo admin: ").strip()
    email = input("Email do novo admin: ").strip()
    password = getpass.getpass("Senha (mín. 8, com 1 maiúscula e 1 número): ")

    resp = httpx.post(
        f"{base_url}/admin/usuarios",
        json={"username": username, "email": email, "password": password},
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 201:
        info = resp.json()
        print(f"[ok] administrador '{username}' criado.")
        print(
            "Dois fatores é obrigatório para administrador — a pessoa deve escanear esse QR "
            "code (ou digitar a chave manual) no Google Authenticator agora, não fica salvo "
            "em lugar nenhum depois:"
        )
        _print_qr(info["otpauth_url"])
        print(f"  (chave manual: {info['totp_secret']})\n")
    else:
        print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")


def trocar_senha(base_url: str, token: str) -> bool:
    """Retorna True se a senha foi trocada (a sessão atual foi invalidada no
    servidor, então quem chamou deve logar de novo)."""
    senha_atual = getpass.getpass("Senha atual: ")
    senha_nova = getpass.getpass("Nova senha (mín. 8, com 1 maiúscula e 1 número): ")

    resp = httpx.patch(
        f"{base_url}/auth/senha",
        json={"senha_atual": senha_atual, "senha_nova": senha_nova},
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 200:
        print("[ok] senha alterada — faça login de novo.\n")
        return True

    print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")
    return False


def excluir_usuario(base_url: str, token: str) -> None:
    resp = httpx.get(f"{base_url}/admin/usuarios", headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")
        return

    usuarios = resp.json()
    if not usuarios:
        print("(nenhum usuário cadastrado)\n")
        return

    print()
    for u in usuarios:
        print(f"  {u['id']:<4} {u['username']}")
    print()

    bruto = input("ID do usuário a excluir: ").strip()
    if not bruto.isdigit():
        print("[erro] ID inválido\n")
        return

    confirmar = input(f"Confirma exclusão do usuário {bruto}? [s/N] ").strip().lower()
    if confirmar != "s":
        print("Cancelado.\n")
        return

    resp = httpx.delete(
        f"{base_url}/admin/usuarios/{bruto}", headers={"Authorization": f"Bearer {token}"}
    )
    if resp.status_code == 204:
        print("[ok] usuário excluído.\n")
    else:
        print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")


def main() -> None:
    server = input(f"Endereço do servidor [{DEFAULT_SERVER}]: ").strip() or DEFAULT_SERVER
    base_url = f"http://{server}"

    token = login(base_url)
    print("\nLogin ok.")

    menu = (
        "\n1) Listar usuários"
        "\n2) Criar novo administrador"
        "\n3) Excluir usuário"
        "\n4) Trocar minha senha"
        "\n5) Sair\n"
    )
    while True:
        print(menu)
        escolha = input("> ").strip()
        if escolha == "1":
            listar_usuarios(base_url, token)
        elif escolha == "2":
            criar_admin(base_url, token)
        elif escolha == "3":
            excluir_usuario(base_url, token)
        elif escolha == "4":
            if trocar_senha(base_url, token):
                token = login(base_url)
                print("\nLogin ok.")
        elif escolha == "5":
            break
        else:
            print("[erro] opção inválida\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
