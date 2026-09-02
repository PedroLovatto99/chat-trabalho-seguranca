from fastapi import FastAPI

app = FastAPI()

from rotas.main_routes import order_router
#from rotas.auth_routes import auth_router

app.include_router(order_router)

