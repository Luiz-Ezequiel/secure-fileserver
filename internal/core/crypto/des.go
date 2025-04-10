package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
)

// DESHandler implementa EncryptionHandler usando DES no modo CBC.
type DESHandler struct {
}

func (crypt DESHandler) Encrypt(plaintext, key []byte) (ciphertext []byte, err error) {
	// Cria um bloco de cifra com a chave fornecida
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Aplica padding PKCS#7 para garantir que o tamanho do dado seja múltiplo do tamanho do bloco
	plaintext = pkcs7pad(plaintext, des.BlockSize)
	
	// Gera um vetor de inicialização (IV) aleatório
	iv := make([]byte, des.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	
	mode := cipher.NewCBCEncrypter(block, iv) 		// Cria um encriptador no modo CBC
	ciphertext = make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext) 		// Executa a criptografia em blocos
	
	return append(iv, ciphertext...), nil 			// Retorna o IV concatenado com o dado criptografado
}

func (crypt DESHandler) Decrypt(ciphertext, key []byte) (plaintext []byte, err error) {
	// Cria o bloco de cifra com a chave fornecida
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < des.BlockSize {
		return nil, errors.New("ciphertext muito curto")
	}

	// Separa o IV e o texto criptografado
	iv := ciphertext[:des.BlockSize] 
	ciphertext = ciphertext[des.BlockSize:]

	if len(ciphertext) % des.BlockSize != 0 {
		return nil, errors.New("ciphertext não é um múltiplo do tamanho do bloco")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)		// Executa a descriptografia em blocos

	return pkcs7Unpad(ciphertext, des.BlockSize)
}
