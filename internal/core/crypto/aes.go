package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

// AESHandler implementa EncryptionHandler usando AES no modo GCM.
type AESHandler struct {
}

func (crypt AESHandler) Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	// Cria um bloco de cifra com a chave fornecida
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Cria um encriptador no modo GCM
	aesgcm, err := cipher.NewGCM(block) 		
	if err != nil {
		return nil, err
	}

	// Cria um nonce(number used once). Num aleatório para criptografar, fazendo cada criptografia única 
	nonce, err := createNonce(12) // 12 bytes é o tamanho recomendado para GCM (96 bits) garante performance otimizada e está de acordo com os padrões do NIST
	if err != nil {
		return nil, err
	}
	
	// Executa a criptografia do texto
	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil

}

func (crypt AESHandler) Decrypt(ciphertext, key []byte) (plaintext []byte, err error){
	// Cria um bloco de cifra com a chave fornecida
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Cria um encriptador no modo GCM
	aesgcm, err := cipher.NewGCM(block)			
	if err != nil {
		return nil, err
	}

	// Separa o nonce do texto criptografado
	if len(ciphertext) < 12 {
		return nil, errors.New("ciphertext muito curto")
	}
	nonce := ciphertext[:12] 		 
	ciphertext = ciphertext[12:]

	// Executa a descriptografia do texto criptografado
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
