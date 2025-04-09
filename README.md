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

## Algoritmos de Criptografia Simétrica

Começo definindo uma interface de tratamento de criptografia (`EncryptionHandler`) que será a interface de todos os 3 algoritmos de criptografia. 

**Métodos:**

    - Encrypt: Criptografa dados brutos (plaintext) com uma chave.
    - Decrypy: Decriptografa dados criptografados (ciphertext) com a mesma chave.

### DES (Data Encryption Standard)
Considerado insecuro para aplicações modernas pois o tamanho da chave possui apenas 56 bits, fazendo com que ele seja suscetível a ataques de força-bruta, utilizado somente para didática. A chave deve ter 8 bytes e o IV deve ser aleatório e diferente a cada execução para garantir a segurança.

A estrutura DESHandler implementa a interface EncryptionHandler usando o algoritmo DES com as seguintes características:

    Tamanho fixo de bloco: 8 bytes (64 bits)

    Modo de operação: CBC (Cipher Block Chaining)

    Padding: PKCS#7