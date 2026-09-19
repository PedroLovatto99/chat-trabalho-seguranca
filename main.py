import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from security.rate_limit import limiter

logger = logging.getLogger("chat_seguro")

app = FastAPI()
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

from rotas.main_routes import order_router
from rotas.auth_routes import auth_router
from rotas.admin_routes import admin_router

app.include_router(order_router)
app.include_router(auth_router)
app.include_router(admin_router)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_exception_handler(request: Request, exc: RateLimitExceeded):
    """Resposta em português pro limite de requisições (slowapi já devolveria
    429, mas com mensagem em inglês por padrão)."""
    return JSONResponse(
        status_code=429,
        content={"detail": "muitas requisições em pouco tempo — aguarde um instante e tente de novo"},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Rede de segurança final: qualquer exceção não prevista (bug, erro de
    banco, etc.) cai aqui em vez de vazar traceback/detalhes internos pro
    cliente. O erro completo ainda é logado no servidor (`docker compose logs
    server`) pra debugar depois."""
    logger.exception("erro não tratado em %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "erro interno do servidor"})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Traduz os erros de validação do Pydantic para mensagens em português.
    O email-validator (usado pelo EmailStr) sempre responde em inglês por padrão
    ("value is not a valid email address..."), então trocamos essa mensagem
    específica aqui em vez de expor o texto original ao usuário."""
    detail = []
    for erro in exc.errors():
        campo = erro["loc"][-1]
        tipo = erro["type"]
        if campo == "email":
            msg = "email precisa seguir o formato de um endereço de email válido (ex: nome@dominio.com)"
        elif campo == "password" and tipo == "string_too_short":
            msg = "senha precisa ter pelo menos 8 caracteres"
        elif campo == "password" and tipo == "string_too_long":
            msg = "senha não pode ter mais que 72 caracteres"
        elif campo == "password" and tipo == "value_error":
            # erros do validar_senha_forte() já vêm em português, só remove o
            # prefixo padrão que o Pydantic adiciona ("Value error, ...")
            msg = erro["msg"].removeprefix("Value error, ")
        else:
            msg = erro["msg"]
        detail.append({"loc": erro["loc"], "msg": msg})
    return JSONResponse(status_code=422, content={"detail": detail})
