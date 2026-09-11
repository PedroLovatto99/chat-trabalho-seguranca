import getpass

import httpx

DEFAULT_SERVER = "localhost:8000"


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


def login(base_url: str) -> str:
    """Só login — contas administrador não têm autocadastro (nem aqui)."""
    while True:
        username = input("Usuário (admin): ").strip()
        password = getpass.getpass("Senha: ")

        resp = httpx.post(
            f"{base_url}/auth/login", json={"username": username, "password": password}
        )
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

    print(f"\n{'id':<4} {'username':<20} {'role':<15} password_hash")
    for u in usuarios:
        print(f"{u['id']:<4} {u['username']:<20} {u['role']:<15} {u['password_hash']}")
    print()


def criar_admin(base_url: str, token: str) -> None:
    username = input("Usuário do novo admin: ").strip()
    password = getpass.getpass("Senha (mín. 8 caracteres): ")

    resp = httpx.post(
        f"{base_url}/admin/usuarios",
        json={"username": username, "password": password},
        headers={"Authorization": f"Bearer {token}"},
    )
    if resp.status_code == 201:
        print(f"[ok] administrador '{username}' criado.\n")
    else:
        print(f"[erro] {_format_error(resp.json().get('detail', resp.text))}\n")


def excluir_usuario(base_url: str, token: str) -> None:
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
        "\n4) Sair\n"
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
            break
        else:
            print("[erro] opção inválida\n")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrado.")
