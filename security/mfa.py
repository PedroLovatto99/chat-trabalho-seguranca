import sys

import pyotp
import qrcode

ISSUER = "Chat Seguro"


def gerar_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, email: str) -> str:
    """URI otpauth:// — o Google Authenticator lê isso via QR code, ou o segredo
    (`secret`) pode ser digitado manualmente em "inserir chave de configuração"."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verificar_totp_code(secret: str, code: str) -> bool:
    # valid_window=1 tolera até 30s de diferença de relógio entre o celular e o
    # servidor pra um lado ou pro outro — sem isso, qualquer pequeno desajuste
    # de horário já rejeitaria códigos válidos.
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def print_qr_ascii(otpauth_url: str) -> None:
    """Desenha o QR code direto no terminal (sem precisar salvar imagem) — o
    Google Authenticator escaneia isso na tela normalmente. Se o terminal não
    suportar (encoding antigo, saída redirecionada), não trava o fluxo — quem
    chama sempre mostra a chave manual como alternativa."""
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(otpauth_url)
        qr.make()
        qr.print_ascii(tty=sys.stdout.isatty())
    except (OSError, UnicodeEncodeError):
        print("(não foi possível desenhar o QR code neste terminal — use a chave manual abaixo)")
