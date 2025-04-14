package crypto

import (
	"bytes"
	"testing"
)

func TestAES_EncryptDecrypt_Success(t *testing.T) {
	handler := AESHandler{}
	keyGen := AESKeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave AES: %v", err)
	}

	original := []byte("mensagem muito importante para segurança")
	cipher, err := handler.Encrypt(original, key)
	if err != nil {
		t.Fatalf("Erro ao criptografar: %v", err)
	}

	plain, err := handler.Decrypt(cipher, key)
	if err != nil {
		t.Fatalf("Erro ao descriptografar: %v", err)
	}

	if !bytes.Equal(original, plain) {
		t.Errorf("Texto descriptografado diferente do original")
	}
}

func TestAES_Decrypt_InvalidCiphertext(t *testing.T) {
	handler := AESHandler{}
	keyGen := AESKeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave AES: %v", err)
	}

	_, err = handler.Decrypt([]byte("short"), key)
	if err == nil {
		t.Errorf("Esperado erro com ciphertext muito curto")
	}
}

func TestAES_Decrypt_InvalidPadding(t *testing.T) {
	handler := AESHandler{}
	keyGen := AESKeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave AES: %v", err)
	}

	cipher, _ := handler.Encrypt([]byte("mensagem com padding"), key)

	// Corrompe o último byte do padding
	cipher[len(cipher)-1] = 0x00

	_, err = handler.Decrypt(cipher, key)
	if err == nil {
		t.Errorf("Esperado erro para padding inválido")
	}
}

func TestAES_Encrypt_InvalidKey(t *testing.T) {
	handler := AESHandler{}
	invalidKey := []byte("curta")

	_, err := handler.Encrypt([]byte("mensagem"), invalidKey)
	if err == nil {
		t.Errorf("Esperado erro para chave inválida")
	}
}

func TestAES_KeyGeneration(t *testing.T) {
	keyGen := AESKeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave AES: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("Tamanho da chave inválido, esperado 32 bytes, obtido %d", len(key))
	}
}

func TestAES_ConcurrentEncryption(t *testing.T) {
	handler := AESHandler{}
	keyGen := AESKeyGenerator{}
	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave AES: %v", err)
	}
	message := []byte("teste concorrente seguro com AES")

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

				if !bytes.Equal(message, plain) {
					t.Errorf("Texto recuperado não bate: %v != %v", plain, message)
				}
			}()
		}
	})
}
