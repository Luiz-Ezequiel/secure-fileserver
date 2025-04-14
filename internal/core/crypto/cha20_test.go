package crypto

import (
	"bytes"
	"testing"
)

func TestCha20_EncryptDecrypt_Success(t *testing.T) {
	handler := Cha20Handler{}
	keyGen := Cha20KeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave: %v", err)
	}

	original := []byte("mensagem secreta para teste com ChaCha20")
	cipher, err := handler.Encrypt(original, key)
	if err != nil {
		t.Fatalf("Erro ao criptografar: %v", err)
	}

	// Decrypt using the same key
	plain, err := handler.Decrypt(cipher, key)
	if err != nil {
		t.Fatalf("Erro ao descriptografar: %v", err)
	}

	if !bytes.Equal(original, plain) {
		t.Errorf("Texto descriptografado difere do original: %v != %v", original, plain)
	}
}


func TestCha20_Decrypt_InvalidCiphertext(t *testing.T) {
	handler := Cha20Handler{}
	keyGen := Cha20KeyGenerator{}
	key, _ := keyGen.Generate()

	// Menor que o tamanho do nonce (24 bytes)
	_, err := handler.Decrypt([]byte("short"), key)
	if err == nil {
		t.Errorf("Esperado erro para ciphertext curto")
	}
}

func TestCha20_KeyGeneration(t *testing.T) {
	keyGen := Cha20KeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Tamanho da chave inválido, esperado 32 bytes, obtido %d", len(key))
	}
}

func TestCha20_ConcurrentEncryption(t *testing.T) {
	handler := Cha20Handler{}
	keyGen := Cha20KeyGenerator{}
	key, _ := keyGen.Generate()
	message := []byte("concorrência segura com ChaCha20")

	t.Run("EncryptDecryptParallel", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 100; i++ {
			go func() {
				cipher, err := handler.Encrypt(message, key)
				if err != nil {
					t.Errorf("Erro ao criptografar em paralelo: %v", err)
					return
				}

				plain, err := handler.Decrypt(cipher, key)
				if err != nil {
					t.Errorf("Erro ao descriptografar em paralelo: %v", err)
					return
				}

				if !bytes.Equal(plain, message) {
					t.Errorf("Texto recuperado não bate: %v != %v", plain, message)
				}
			}()
		}
	})
}

func TestCha20_NonceGeneration(t *testing.T) {
	nonce, err := createNonce(24)
	if err != nil {
		t.Fatalf("Erro ao gerar nonce: %v", err)
	}

	// Nonce should be 24 bytes
	if len(nonce) != 24 {
		t.Errorf("Tamanho de nonce inválido, esperado 24 bytes, obtido %d", len(nonce))
	}
}
