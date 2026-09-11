from fastapi import FastAPI

app = FastAPI()

from rotas.main_routes import order_router
from rotas.auth_routes import auth_router
from rotas.admin_routes import admin_router

app.include_router(order_router)
app.include_router(auth_router)
app.include_router(admin_router)
