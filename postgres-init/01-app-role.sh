#!/bin/bash
# Roda uma única vez, na primeira inicialização do container (volume vazio).
# Cria a role de privilégio mínimo usada pela API em runtime — sem permissão de
# criar/alterar tabelas, só CRUD nas tabelas que a role dona (POSTGRES_USER) criar
# via migrations do Alembic.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE "${APP_DB_USER}" LOGIN PASSWORD '${APP_DB_PASSWORD}';
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO "${APP_DB_USER}";
    GRANT USAGE ON SCHEMA public TO "${APP_DB_USER}";

    -- Toda tabela/sequence que a role dona criar depois (via migration) já nasce
    -- com esses privilégios liberados para a role da aplicação, sem precisar de
    -- GRANT manual a cada nova migration.
    ALTER DEFAULT PRIVILEGES FOR ROLE "${POSTGRES_USER}" IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${APP_DB_USER}";
    ALTER DEFAULT PRIVILEGES FOR ROLE "${POSTGRES_USER}" IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO "${APP_DB_USER}";
EOSQL
