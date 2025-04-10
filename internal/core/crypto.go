package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"errors"
)

type EncryptionHandler interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
}

// Estrutura que implementa o algortimo DES
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

func (crypt DESHandler) Decrypt(ciphertext, key []byte) (text []byte, err error) {
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

// Função auxiliar para aplicar o padding PKCS#7
func pkcs7pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// Função auxiliar para remover o padding PKCS#7
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("Dado invalido.")
	} 

	// Lê o último byte dos dados, que indica o tamanho do padding
	paddingLen := int(data[len(data)-1])

	if paddingLen == 0 || paddingLen > blockSize {
		return nil, errors.New("Padding de tamanho inválido.")

	}

	// Verifica se todos os bytes finais realmente correspondem ao valor do padding
	for i := 0; i < paddingLen; i++ {
		if data[len(data)-1-i] != byte(paddingLen) {
			return nil, errors.New("invalid padding")
		}
	}
	
	return data[:len(data)-paddingLen], nil 		// Remove os bytes de padding e retorna os dados originais
}


type AESHandler struct {
}

func (crypt AESHandler) Encrypt(text, key []byte) (ciphertext []byte, err error) {
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
	nonce := make([]byte, 12)					// 12 bytes é o tamanho recomendado para GCM (96 bits) garante performance otimizada e está de acordo com os padrões do NIST
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	
	// Executa a criptografia do texto
	ciphertext = aesgcm.Seal(nil, nonce, text, nil)
	return append(nonce, ciphertext...), nil

}

func (crypt AESHandler) Decrypt(ciphertext, key []byte) (text []byte, err error){
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
	text, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return text, nil
}

// func main() {

// }
