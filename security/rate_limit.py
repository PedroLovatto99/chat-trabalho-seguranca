from slowapi import Limiter
from slowapi.util import get_remote_address

# Instância única, importada tanto por main.py (registro do middleware/handler)
# quanto pelas rotas que usam @limiter.limit(...). Fica num módulo próprio pra
# evitar import circular entre main.py e rotas/*.py.
limiter = Limiter(key_func=get_remote_address)
