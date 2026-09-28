# Chat Seguro

Chat em tempo real com mensagens ponta-a-ponta: o servidor (FastAPI + WebSocket + PostgreSQL)
autentica usuários e só repassa mensagens já criptografadas — nunca vê o conteúdo. Cada
cliente gera seu próprio par de chaves RSA, troca uma chave Fernet simétrica com o
destinatário (envelopada em RSA-OAEP) e usa essa chave para criptografar as mensagens.

Este guia está dividido em duas partes: **Parte 1** é para quem vai hospedar o servidor
(via Docker); **Parte 2** é para quem vai só usar o chat ou administrar usuários (via
`client.py`/`admin_client.py`), sem precisar rodar nada em Docker.

---

## Parte 1 — Servidor (Docker)

Só quem vai **hospedar** a aplicação precisa desta parte.

### Pré-requisitos

- [Docker](https://www.docker.com/) — é tudo que essa máquina precisa: o Docker builda a
  imagem e instala as dependências sozinho, não precisa de Python nem `pip install` local.

### Subir o servidor

Sobe a API (porta `8000`) e o PostgreSQL (porta `55432`, só acessível pela própria máquina)
em containers.

```bash
docker compose up --build -d
```

Antes da primeira vez, copie `.env.example` para `.env` e ajuste as senhas/segredos (JWT e
TOTP). Para ver os logs: `docker compose logs -f server`. Para derrubar tudo: `docker compose down`.

### Rodando as migrations (primeira vez / após mudar o modelo)

Também roda dentro do Docker, sem precisar de Python local:

```bash
docker compose run --rm migrate
```

(esse serviço não sobe com `docker compose up` — só existe pra ser chamado assim, sob
demanda)

### Criando o primeiro administrador (opcional, uma vez só)

Contas `administrador` não têm cadastro público (só `/auth/register`, que cria `cliente`).
A primeira é criada por este script, lendo `ADMIN_USERNAME`/`ADMIN_EMAIL`/`ADMIN_PASSWORD`
do `.env` (a senha precisa ter 8+ caracteres, 1 maiúscula e 1 número):

```bash
docker compose run --rm seed-admin
```

Rodar de novo não duplica (se o usuário já existir, só avisa). Dois fatores é obrigatório
para administrador — o script já mostra o QR code (ou a chave manual) pra configurar no
Google Authenticator na hora. Administradores seguintes devem ser criados por um admin já
logado, via `admin_client.py` (Parte 2), não por este script.

### Rodando em rede local (demonstração com mais de um PC)

Só o **servidor** roda com Docker; os clientes (em qualquer PC) só precisam do Python (Parte 2).

1. Descubra o IP na rede local (`ipconfig`, procure o "Endereço IPv4" da rede Wi-Fi/Ethernet
   — algo como `192.168.1.50`) e repasse esse IP pra quem for usar o cliente.
2. Garanta que o Firewall do Windows libera a porta `8000` para a rede (o Windows costuma
   perguntar isso na primeira vez que o Docker expõe a porta — vale testar com antecedência).
3. Todos os PCs precisam estar na mesma rede local. Atenção: algumas redes (universidade,
   eventos) têm "isolamento de cliente" (AP isolation), que impede um dispositivo de falar
   com outro mesmo no mesmo Wi-Fi — teste com antecedência se for apresentar num lugar assim.

O banco de dados (porta `55432`) fica restrito à máquina do servidor o tempo todo — os
clientes remotos nunca acessam o Postgres diretamente, só a API.

### Inspecionando o banco de dados

Útil para conferir que senhas ficam com hash (bcrypt) e nunca em texto puro:

```bash
docker exec -it trabalhog1-segurana-db-1 psql -U chat_owner -d chat_seguro -c "SELECT id, username, email, password_hash, role FROM usuarios;"
```

Ou com um cliente psql/GUI (pgAdmin, DBeaver) local, apontando pra `localhost:55432` com as
credenciais do `.env`.

---

## Parte 2 — Cliente (chat e administração)

Para quem vai **usar o chat** ou **administrar usuários** — não precisa de Docker, só de Python.

### Pré-requisitos

- Python 3.12+ — em toda máquina que vai rodar o **cliente**, incluindo a do servidor se
  você quiser testar localmente.

### Instalar as dependências

```bash
pip install -r requirements-client.txt
```

(`requirements-client.txt` tem só o que `client.py`/`admin_client.py` usam — bem mais leve
que o `requirements.txt` do servidor. Útil pra instalar rápido no PC de outra pessoa numa
demonstração.)

### Rodar o chat (`client.py`)

```bash
python client.py
```

O programa pede o endereço do servidor (Enter usa `localhost:8000` — se o servidor estiver
em outro PC, digite o IP dele, ex: `192.168.1.50:8000`), depois **email** e senha — o login é
por email, mas o servidor devolve o `username` junto do token, que é o que aparece pra todo
mundo no chat (não precisa saber o email de quem quer conversar). Se a conta não existir,
oferece criar na hora (pede usuário, email e senha — senha precisa ter 8+ caracteres, 1
maiúscula e 1 número). Depois disso abre o chat.

Se a conta tiver dois fatores ativado (veja `/doisfatores` abaixo), depois da senha certa o
programa pede o código de 6 dígitos do Google Authenticator antes de liberar o login.

A sessão dura 15 minutos (`JWT_EXPIRE_MINUTES` no `.env` do servidor) — passado esse tempo,
o chat **desconecta sozinho**, não é só bloquear novas ações.

Depois de logado:

- `/list` — lista os usuários online no momento.
- `/senha` — troca sua senha (pede a senha atual + a nova). Isso invalida a sessão atual no
  servidor, então o programa encerra e pede pra entrar de novo com a senha nova.
- `/doisfatores` — ativa ou desativa o segundo fator (Google Authenticator) na sua conta.
  Ao ativar, mostra uma chave pra configurar no app e pede o código gerado antes de valer de
  verdade (assim não tem risco de travar a conta com uma chave digitada errada no app). Ao
  desativar, pede a senha atual de novo.
- `/sair` — faz logout de verdade (invalida o token no servidor) e encerra o programa —
  prefira isso a fechar com Ctrl+C.
- `<usuario_destino> <mensagem>` — envia uma mensagem privada. Exemplo:
  ```
  > maria oi, tudo bem?
  ```

Mensagens chegam automaticamente na tela de quem estiver online; se o destinatário não
estiver conectado, você recebe um aviso de erro. Só contas do tipo `cliente` conseguem
entrar no chat (contas `administrador` são bloqueadas nessa parte).

### Gerenciar usuários (`admin_client.py`)

Contas `administrador` não usam o `client.py` do chat (são bloqueadas de propósito) — usam
um script próprio:

```bash
python admin_client.py
```

Pede email/senha de uma conta `administrador` já existente (a primeira vem do `seed-admin`,
veja a Parte 1) e abre um menu pra:

- Listar todos os usuários (username, email, role e `password_hash`, pra conferir
  visualmente que está com hash e nunca em texto puro — sem precisar entrar no banco).
- Criar uma nova conta `administrador` (pede usuário, email e senha). Dois fatores é
  obrigatório pra administrador, então a chave TOTP do novo admin já vem pronta nessa
  resposta — repasse pra pessoa configurar no Google Authenticator, não fica salva em
  lugar nenhum depois desse momento.
- Excluir um usuário (mostra a lista de id + username antes de pedir o id) — contas
  `administrador` não podem ser excluídas por aqui de propósito.
- Trocar a própria senha (pede a senha atual + a nova, já pede login de novo em seguida).

Dois fatores é **sempre obrigatório** pra administrador (não tem como desativar, diferente
do `cliente` no `client.py`) — depois da senha certa, o login sempre pede o código do
Google Authenticator. Contas administrador antigas, criadas antes dessa exigência existir,
recebem a chave TOTP automaticamente no primeiro login depois da atualização.

---

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
  mfa.py                    # segredo/verificação TOTP (Google Authenticator)
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
```
