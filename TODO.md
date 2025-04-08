# TODO – Servidor de Arquivos Criptografado em Go

## Fase 1 – Estrutura Inicial
- [x] Criar estrutura básica do projeto
- [ ] Definir protocolo de comunicação
- [ ] Implementar cliente CLI

## Fase 2 – Criptografia
- [ ] Implementar AES ([Guia](https://gocloud.dev/howto/crypto/encrypt/))
- [ ] Implementar ChaCha20 ([Exemplo](https://pkg.go.dev/golang.org/x/crypto/chacha20))
- [ ] Implementar DES (ou outro algoritmo didático) ([DES em Go](https://golang.org/pkg/crypto/des/))
- [ ] Troca de chaves com DH ([RFC 3526](https://datatracker.ietf.org/doc/html/rfc3526))
- [ ] Troca de chaves com PKI ([Tutorial de RSA](https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-public-key-encryption/))

## Fase 3 – Funcionalidades Básicas
- [ ] Upload de arquivos
- [ ] Download de arquivos
- [ ] Listagem de arquivos
- [ ] Identificação do remetente
- [ ] Armazenamento local com metadados

## Fase 4 – Autenticação
- [ ] Registro de usuários
- [ ] Hash de senha com bcrypt ([bcrypt em Go](https://pkg.go.dev/golang.org/x/crypto/bcrypt))
- [ ] Validação de sessão/token

## Fase 5 – Segurança e Robustez
- [ ] Hash de integridade dos arquivos ([SHA256](https://pkg.go.dev/crypto/sha256))
- [ ] Logs de operações
- [ ] Timeout e validação de sessão

## Fase 6 – WebSocket (Opcional)
- [ ] Criar servidor WebSocket ([Gorilla WebSocket](https://github.com/gorilla/websocket))
- [ ] Adaptar cliente web
- [ ] Notificações em tempo real

## Fase 7 – Finalização
- [ ] Documentação final
- [ ] README completo
- [ ] Exemplos de uso
- [ ] Deploy para demonstração (opcional)

