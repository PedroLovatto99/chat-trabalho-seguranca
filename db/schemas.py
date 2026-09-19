from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from security.auth import validar_senha_forte


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def _senha_forte(cls, v: str) -> str:
        validar_senha_forte(v)
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class AdminCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)

    @field_validator("password")
    @classmethod
    def _senha_forte(cls, v: str) -> str:
        validar_senha_forte(v)
        return v


class UsuarioAdminView(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    role: str
    password_hash: str
    public_key: str | None
    created_at: datetime
    updated_at: datetime
