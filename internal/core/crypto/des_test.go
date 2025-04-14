package crypto

import (
	"bytes"
	"testing"
)

func TestDESHandler_EncryptDecrypt(t *testing.T) {
	handler := DESHandler{}
	keyGen := DESKeyGenerator{}

	key, err := keyGen.Generate()
	if err != nil {
		t.Fatalf("Erro ao gerar chave DES: %v", err)
	}

	original := []byte("Texto secreto que precisa ser criptografado")

	encrypted, err := handler.Encrypt(original, key)
	if err != nil {
		t.Fatalf("Erro ao criptografar: %v", err)
	}

	decrypted, err := handler.Decrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Erro ao descriptografar: %v", err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Errorf("Texto descriptografado diferente do original.\nOriginal: %s\nDescriptografado: %s", original, decrypted)
	}
}

func TestDESHandler_InvalidKeyLength(t *testing.T) {
	handler := DESHandler{}
	key := []byte("tooshort") // deve ter 8 bytes, mas a DES exige chave de 8 bytes — esse está OK.
	_, err := handler.Encrypt([]byte("teste"), key)
	if err != nil {
		t.Errorf("Não deveria falhar com chave de 8 bytes, mas falhou: %v", err)
	}

	// Chave inválida (muito curta)
	shortKey := []byte("123")
	_, err = handler.Encrypt([]byte("teste"), shortKey)
	if err == nil {
		t.Error("Esperava erro com chave muito curta, mas não ocorreu.")
	}
}

func TestDESHandler_CorruptedCiphertext(t *testing.T) {
	handler := DESHandler{}
	keyGen := DESKeyGenerator{}

	key, _ := keyGen.Generate()

	// Texto corrompido (menor que o tamanho do bloco)
	corrupted := []byte("1234567") // < 8
	_, err := handler.Decrypt(corrupted, key)
	if err == nil {
		t.Error("Esperava erro com ciphertext corrompido, mas não ocorreu.")
	}

	// Tamanho não múltiplo do bloco após o IV
	invalidCipher := make([]byte, 16) // 8 IV + 8 dados, vamos quebrar isso
	invalidCipher = append(invalidCipher, byte(1)) // agora tem 17 bytes
	_, err = handler.Decrypt(invalidCipher, key)
	if err == nil {
		t.Error("Esperava erro ao descriptografar ciphertext inválido.")
	}
}
