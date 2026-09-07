# Chat Seguro

Chat em tempo real com mensagens ponta-a-ponta: o servidor (FastAPI + WebSocket) só repassa
mensagens já criptografadas — cada cliente gera seu próprio par de chaves RSA, troca uma
chave Fernet simétrica com o destinatário (envelopada em RSA-OAEP) e usa essa chave para
criptografar o conteúdo das mensagens.

## Pré-requisitos

- [Docker](https://www.docker.com/) (para rodar o servidor)
- Python 3.12+ (para rodar o cliente)

## 1. Subir o servidor

O servidor roda em container e fica escutando em `ws://localhost:8000`.

```bash
docker compose up --build
```

Deixe esse terminal aberto. Para derrubar o servidor: `docker compose down`.

## 2. Rodar o cliente

O cliente é um script de terminal (`client.py`) — cada usuário roda sua própria instância,
em um terminal separado.

### Criar o ambiente virtual (primeira vez)

```bash
python -m venv env
```

**Ativar o ambiente virtual:**

- Windows (PowerShell):
  ```powershell
  env\Scripts\Activate.ps1
  ```
- Windows (cmd):
  ```cmd
  env\Scripts\activate.bat
  ```
- Linux/macOS:
  ```bash
  source env/bin/activate
  ```

### Instalar dependências

```bash
pip install -r requirements.txt
```

### Executar

```bash
python client.py
```

O programa vai pedir um nome de usuário e conectar ao servidor. Repita esse passo em
outro terminal (com outro nome de usuário) para simular uma segunda pessoa conversando.

## Usando o chat

Depois de conectado:

- `/list` — lista os usuários online no momento.
- `<usuario_destino> <mensagem>` — envia uma mensagem privada. Exemplo:
  ```
  > maria oi, tudo bem?
  ```

Mensagens chegam automaticamente na tela de quem estiver online; se o destinatário não
estiver conectado, você recebe um aviso de erro.

## Estrutura do projeto

```
main.py               # app FastAPI
rotas/
  main_routes.py       # endpoint WebSocket (/ws/{user_id})
  connection.py        # gerenciador de conexões ativas e chaves públicas
client.py              # cliente de terminal (criptografia e UI)
docker-compose.yml      # sobe o servidor em container
Dockerfile
requirements.txt
```
