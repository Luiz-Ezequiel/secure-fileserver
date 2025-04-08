## Estrutura do Projeto
Defini a estrutura de forma que o código se mantenha organizado, mas não tão complexo a ponto de dificultar a criação do projeto com complexidade desnecessária.

```
/
├── cmd/
│   ├── server/            # Main do servidor
│   └── client/            # Cliente CLI básico
├── internal/
│   ├── core/              # Núcleo do sistema
│   │   ├── crypto.go      # Toda criptografia
│   │   ├── auth.go        # Autenticação
│   │   └── storage.go     # Armazenamento
│   ├── protocol/          # Protocolos de comunicação
│   │   ├── socket.go      # Socket seguro
│   │   └── websocket.go   # WS opcional
│   └── api/               # Handlers
│       ├── files.go       # Upload/download
│       └── admin.go       # Admin/users
├── pkg/
│   ├── config/            # Configuração
│   └── models/            # Modelos de dados
├── scripts/               # Scripts essenciais
│   ├── certgen.sh         # Gerar certificados
│   └── deploy.sh          # Deploy simples
└── README.md              # Doc básica
```
