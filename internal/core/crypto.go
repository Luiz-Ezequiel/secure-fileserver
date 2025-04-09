package main

import (
	"bytes"
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

func (crypt DESHandler) Encrypt(plaintext, key []byte) (ciphertext []byte, err error){
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
	
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext = make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext) 		// Executa a criptografia em blocos
	
	return append(iv, ciphertext...), nil 			// Retorna o IV concatenado com o dado criptografado
}

func (crypt DESHandler) Decrypt(ciphertext, key []byte) (text []byte, err error){
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

	if len(ciphertext)%des.BlockSize != 0 {
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


// type AESHandler struct {
// }

// func (crypt AESHandler) Encrypt(key, text []byte) (ciphertext []byte, err error){

// }

// func main() {

// }
