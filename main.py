from fastapi import FastAPI
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

app = FastAPI()

from rotas.main_routes import order_router
#from rotas.auth_routes import auth_router

app.include_router(order_router)

