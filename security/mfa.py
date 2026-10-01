import sys

import pyotp
import qrcode
from cryptography.fernet import Fernet

from config.settings import settings

ISSUER = "Chat Seguro"

_fernet = Fernet(settings.totp_encryption_key.encode())


def gerar_totp_secret() -> str:
    return pyotp.random_base32()


def cifrar_totp_secret(secret: str) -> str:
    return _fernet.encrypt(secret.encode()).decode()


def decifrar_totp_secret(secret_cifrado: str) -> str:
    return _fernet.decrypt(secret_cifrado.encode()).decode()


def totp_provisioning_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=ISSUER)


def verificar_totp_code(secret: str, code: str) -> bool:
    # valid_window=1 tolera até 30s de diferença de relógio entre o celular e o
    # servidor pra um lado ou pro outro — sem isso, qualquer pequeno desajuste
    # de horário já rejeitaria códigos válidos.
    return pyotp.totp.TOTP(secret).verify(code, valid_window=1)


def print_qr_ascii(otpauth_url: str) -> None:
    try:
        qr = qrcode.QRCode(border=1)
        qr.add_data(otpauth_url)
        qr.make()
        qr.print_ascii(tty=sys.stdout.isatty())
    except (OSError, UnicodeEncodeError):
        print("(não foi possível desenhar o QR code neste terminal — use a chave manual abaixo)")
