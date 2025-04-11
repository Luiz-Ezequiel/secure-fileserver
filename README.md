## Estrutura do Projeto
Defini a estrutura de forma que o código se mantenha organizado, mas não tão complexo a ponto de dificultar a criação do projeto com complexidade desnecessária.

```
/
├── cmd/
│   ├── server/            # Main do servidor
│   └── client/            # Cliente CLI básico
├── internal/
│   ├── core/              # Núcleo do sistema
│   │   ├── crypto/.go     # Toda criptografia
│   │   │   ├── handler.go # Interfaces e funções auxiliares
│   │   │   ├── aes.go     # Algoritmo Simétrico AES
│   │   │   ├── *.go       # Algoritmo Simétrico *
│   │   │   └── des.go     # Algoritmo Simétrico DES
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

O sistema é baseado em uma interface chamada `EncryptionHandler`, que define a estrutura comum para todos os algoritmos de criptografia simétrica utilizados no projeto.

### Interface: `EncryptionHandler` (definida em `handler.go`)
A interface garante que qualquer algoritmo implementado terá os seguintes métodos:

- `Encrypt(plaintext []byte, key []byte) ([]byte, error)`:  
  Criptografa dados brutos (plaintext) utilizando uma chave simétrica.
  
- `Decrypt(ciphertext []byte, key []byte) ([]byte, error)`:  
  Decriptografa os dados criptografados (ciphertext) usando a mesma chave.

Além disso, esse arquivo define funções auxiliares genéricas usado pelos algoritmos.

---

### DES (Data Encryption Standard) – `des.go`

> **Importante:** O DES é considerado inseguro para aplicações modernas, pois utiliza uma chave de apenas 56 bits, tornando-o vulnerável a ataques de força bruta. 

**Características da implementação:**

- **Tamanho do bloco:** 8 bytes (64 bits)  
- **Modo de operação:** CBC (Cipher Block Chaining)  
- **Padding:** PKCS#7  
- **IV (Vetor de Inicialização):** Gerado aleatoriamente a cada criptografia  
- **Tamanho da chave:** 8 bytes (64 bits)

**Resumo:**  
Cada mensagem é preenchida com padding para se adequar ao tamanho de bloco do DES, então criptografada usando o modo CBC. O IV é concatenado ao início do ciphertext para permitir a decriptação posterior.

---

### AES (Advanced Encryption Standard) – `aes.go`

> O AES é atualmente o padrão mais utilizado e recomendado para criptografia simétrica segura.

**Características da implementação:**

- **Tamanho do bloco:** 16 bytes (128 bits)  
- **Modo de operação:** GCM (Galois/Counter Mode) – fornece confidencialidade e integridade  
- **Padding:** **Não necessário** (modo GCM funciona como um stream cipher)  
- **Nonce (Número usado somente uma vez):** 12 bytes (96 bits), gerado aleatoriamente a cada execução (recomendado pelo NIST)  
- **Tamanho da chave:** geralmente 16, 24 ou 32 bytes (128, 192 ou 256 bits)

### ChaCha20 (com XChaCha20) - `chacha20.go`

> ChaCha20 é um algoritmo moderno de criptografia simétrica baseado em stream cipher, conhecido por sua performance, segurança e resistência a falhas de implementação, especialmente com relação à reutilização de nonces.

**Características da implementação:**

- **Tipo de cifra:** Stream cipher (não usa blocos fixos)  
- **Modo utilizado:** XChaCha20 (usa HChaCha20 + ChaCha20)
- **Padding:** **Não necessário** (como é um stream cipher, não exige preenchimento)
- **Nonce:** 24 bytes (192 bits), sendo:
  - Os primeiros 16 bytes usados para derivar uma subchave com `HChaCha20`
  - Os últimos 8 bytes usados como nonce final na cifra `ChaCha20`
- **Tamanho da chave:** 32 bytes (256 bits)

**Resumo:**  
É gerado um nonce aleatório de 24 bytes. Os primeiros 16 bytes são usados com a chave original para derivar uma subchave segura via HChaCha20. A cifra ChaCha20 então usa os últimos 8 bytes do nonce e essa subchave para encriptar o plaintext. O nonce completo é concatenado ao inicio do ciphertext para permitir a decriptação posterior.

---
