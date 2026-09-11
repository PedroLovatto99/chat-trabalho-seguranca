# Chat Seguro

Chat em tempo real com mensagens ponta-a-ponta: o servidor (FastAPI + WebSocket + PostgreSQL)
autentica usuários e só repassa mensagens já criptografadas — nunca vê o conteúdo. Cada
cliente gera seu próprio par de chaves RSA, troca uma chave Fernet simétrica com o
destinatário (envelopada em RSA-OAEP) e usa essa chave para criptografar as mensagens.

## Pré-requisitos

- [Docker](https://www.docker.com/) — só na máquina que vai rodar o **servidor**. É tudo
  que essa máquina precisa: o Docker builda a imagem e instala as dependências sozinho, não
  precisa de Python nem `pip install` local pra rodar o servidor.
- Python 3.12+ — em toda máquina que vai rodar o **cliente** (`client.py`), incluindo a do
  servidor se você quiser testar localmente.

## 1. Subir o servidor

Sobe a API (porta `8000`) e o PostgreSQL (porta `55432`, só acessível pela própria máquina)
em containers.

```bash
docker compose up --build
```

Antes da primeira vez, copie `.env.example` para `.env` e ajuste as senhas/segredo do JWT.
Deixe o terminal aberto. Para derrubar: `docker compose down`.

### Rodando as migrations (primeira vez / após mudar o modelo)

Também roda dentro do Docker, sem precisar de Python local:

```bash
docker compose run --rm migrate
```

(esse serviço não sobe com `docker compose up` — só existe pra ser chamado assim, sob
demanda)

### Criando o primeiro administrador (opcional, uma vez só)

Contas `administrador` não têm cadastro público (só `/auth/register`, que cria `cliente`).
A primeira é criada por este script, lendo `ADMIN_USERNAME`/`ADMIN_PASSWORD` do `.env`:

```bash
docker compose run --rm seed-admin
```

Rodar de novo não duplica (se o usuário já existir, só avisa). Administradores seguintes
devem ser criados por um admin já logado, não por este script.

## 2. Rodar o cliente

O cliente é um script de terminal (`client.py`) — cada usuário roda sua própria instância,
em um terminal separado (ou em outro PC, veja a seção de rede abaixo). Diferente do
servidor, o cliente **não** roda em Docker (é um script de terminal interativo), então
precisa de Python + as dependências instaladas na máquina que for usá-lo:

```bash
pip install -r requirements-client.txt
```

(`requirements-client.txt` tem só o que o `client.py` usa — bem mais leve que o
`requirements.txt` do servidor, que carrega FastAPI/SQLAlchemy/etc. Útil pra instalar rápido
no PC de outra pessoa numa demonstração.)

### Executar

```bash
python client.py
```

O programa pede o endereço do servidor (Enter usa `localhost:8000`), depois usuário e senha
— faz login, ou oferece criar a conta na hora se ela não existir. Depois disso abre o chat.

## Rodando em máquinas diferentes (demonstração com mais de um PC)

Só o **servidor** roda com Docker; os clientes (em qualquer PC) só precisam do Python e do
`requirements-client.txt`.

1. Na máquina do servidor, descubra o IP na rede local (`ipconfig`, procure o "Endereço
   IPv4" da rede Wi-Fi/Ethernet — algo como `192.168.1.50`).
2. Garanta que o Firewall do Windows libera a porta `8000` para a rede (o Windows costuma
   perguntar isso na primeira vez que o Docker expõe a porta — vale testar com antecedência).
3. Nos outros PCs, rode `python client.py` e, no prompt "Endereço do servidor", digite o IP
   do passo 1 (ex: `192.168.1.50:8000`), não `localhost`.
4. Todos os PCs precisam estar na mesma rede local. Atenção: algumas redes (universidade,
   eventos) têm "isolamento de cliente" (AP isolation), que impede um dispositivo de falar
   com outro mesmo no mesmo Wi-Fi — teste com antecedência se for apresentar num lugar assim.

O banco de dados (porta `55432`) fica restrito à máquina do servidor o tempo todo — os
clientes remotos nunca acessam o Postgres diretamente, só a API.

## Usando o chat

Depois de logado:

- `/list` — lista os usuários online no momento.
- `/sair` — faz logout de verdade (invalida o token no servidor) e encerra o programa —
  prefira isso a fechar com Ctrl+C.
- `<usuario_destino> <mensagem>` — envia uma mensagem privada. Exemplo:
  ```
  > maria oi, tudo bem?
  ```

Mensagens chegam automaticamente na tela de quem estiver online; se o destinatário não
estiver conectado, você recebe um aviso de erro. Só contas do tipo `cliente` conseguem
entrar no chat (contas `administrador` são bloqueadas nessa parte).

## Gerenciando usuários (admin)

Contas `administrador` não usam o `client.py` do chat (são bloqueadas de propósito) — usam
um script próprio:

```bash
python admin_client.py
```

Pede usuário/senha de uma conta `administrador` já existente (a primeira vem do
`seed-admin`, veja acima) e abre um menu pra:

- Listar todos os usuários (incluindo o `password_hash`, pra conferir visualmente que está
  com hash e nunca em texto puro — sem precisar entrar no banco).
- Criar uma nova conta `administrador`.
- Excluir um usuário — contas `administrador` não podem ser excluídas por aqui de propósito.

## Inspecionando o banco de dados

Útil para conferir que senhas ficam com hash (bcrypt) e nunca em texto puro:

```bash
docker exec -it trabalhog1-segurana-db-1 psql -U chat_owner -d chat_seguro -c "SELECT id, username, password_hash, role FROM usuarios;"
```

Ou com um cliente psql/GUI (pgAdmin, DBeaver) local, apontando pra `localhost:55432` com as
credenciais do `.env`.

## Estrutura do projeto

```
main.py                  # app FastAPI
config/
  settings.py             # configurações (lidas do .env)
  deps.py                 # dependency de autenticação (get_current_user)
db/
  database.py             # engine/sessão SQLAlchemy
  models.py                # modelo Usuario
  schemas.py                # schemas Pydantic (register/login)
security/
  auth.py                  # hash de senha (bcrypt) e JWT
rotas/
  main_routes.py            # endpoint WebSocket autenticado (/ws)
  auth_routes.py             # /auth/register, /auth/login, /auth/logout
  admin_routes.py             # /admin/usuarios (listar/criar admin/excluir)
  connection.py                 # gerenciador de conexões ativas e chaves públicas
alembic/                       # migrations do banco
postgres-init/                  # script que cria a role de privilégio mínimo no Postgres
client.py                        # cliente de terminal do chat (login, criptografia, UI)
admin_client.py                   # cliente de terminal administrativo
seed_admin.py                      # cria o primeiro administrador (script, não rota)
docker-compose.yml                  # sobe servidor + banco em containers
Dockerfile
requirements.txt                     # dependências do servidor
requirements-client.txt               # dependências só do cliente (chat + admin)
PLANEJAMENTO_SEGURANCA.md              # checklist/decisões de arquitetura de segurança
```
