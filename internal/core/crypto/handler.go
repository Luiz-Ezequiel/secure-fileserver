package crypto

import (
	"bytes"
	"errors"
)

type EncryptionHandler interface {
	Encrypt(plaintext []byte, key []byte) ([]byte, error)
	Decrypt(ciphertext []byte, key []byte) ([]byte, error)
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
			return nil, errors.New("Padding invalido")
		}
	}
	
	return data[:len(data)-paddingLen], nil 		// Remove os bytes de padding e retorna os dados originais
}
