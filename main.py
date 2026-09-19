from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

app = FastAPI()

from rotas.main_routes import order_router
from rotas.auth_routes import auth_router
from rotas.admin_routes import admin_router

app.include_router(order_router)
app.include_router(auth_router)
app.include_router(admin_router)


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
