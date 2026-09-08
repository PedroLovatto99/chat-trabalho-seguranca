from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Role dona do schema — usada só pelo Alembic para rodar migrations.
    # Nunca é passada ao container do servidor (não faz parte do runtime da API).
    postgres_user: str | None = None
    postgres_password: str | None = None
    postgres_db: str
    postgres_host: str = "db"
    postgres_port: int = 5432

    # Role de privilégio mínimo — usada pela API (FastAPI) em runtime. Sem permissão
    # de criar/alterar tabelas, só CRUD nas tabelas liberadas via GRANT.
    app_db_user: str
    app_db_password: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 30

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def _url(self, user: str, password: str) -> str:
        return (
            f"postgresql+asyncpg://{user}:{password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def database_url(self) -> str:
        """URL usada pela API em runtime — role de privilégio mínimo."""
        return self._url(self.app_db_user, self.app_db_password)

    @property
    def migration_database_url(self) -> str:
        """URL usada só pelo Alembic — role dona do schema."""
        if not self.postgres_user or not self.postgres_password:
            raise RuntimeError(
                "POSTGRES_USER/POSTGRES_PASSWORD não configurados no .env — são "
                "necessários só para rodar migrations (role dona do schema)."
            )
        return self._url(self.postgres_user, self.postgres_password)


settings = Settings()
