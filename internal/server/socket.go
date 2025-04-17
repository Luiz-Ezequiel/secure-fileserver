package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"secure-fileserver/internal/core/crypto"
)

type Message struct {
	from    string
	payload []byte
}

type Server struct {
	listenAddr string
	ln         net.Listener
	certPEM    []byte
	quitCh     chan struct{}
	msgCh      chan Message
}

func NewServer(listenAddr string) *Server {
	// Lê o certificado e envia para o cliente
	certPEM, err := os.ReadFile("certs/server.crt")
	if err != nil {
		log.Fatal("failed to load server cert: %w", err)
	}

	return &Server{
		listenAddr: listenAddr,
		certPEM:    certPEM,
		quitCh:     make(chan struct{}),
		msgCh:      make(chan Message, 10),
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	s.ln = ln

	go s.acceptLoop()

	<-s.quitCh
	close(s.msgCh)

	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}

		log.Println("New connection from", conn.RemoteAddr())
		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()

	sharedSecret, err := s.performHandshake(conn)
	if err != nil {
		log.Println("Handshake failed with", conn.RemoteAddr(), ":", err)
		return
	}

	log.Println("Secure connection established with", conn.RemoteAddr())

	s.handleClientComunication(conn, sharedSecret)
}

func (s *Server) performHandshake(conn net.Conn) ([]byte, error) {
	// Envia o certificado para o cliente
	if _, err := conn.Write(s.certPEM); err != nil {
		return nil, fmt.Errorf("failed to send cert: %w", err)
	}

	// Gera o par de chaves do servidor
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("Key generation failed: %w", err)
	}

	// Envia a chave publica do servidor
	serverPubBytes := crypto.MarshalPublicKey(keyPair.Public)
	if _, err := conn.Write(serverPubBytes); err != nil {
		return nil, fmt.Errorf("Error sending public key to client: %w", err)
	}

	// Recebe a chave publica do cliente
	clientPubBytes := make([]byte, 65)
	if _, err := io.ReadFull(conn, clientPubBytes); err != nil {
		return nil, fmt.Errorf("Error reading client's public key: %w", err)
	}

	clientPubKey, err := crypto.UnmarshalPublicKey(clientPubBytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid client public key: %w", err)
	}

	// Deriva o secredo compartilhado
	sharedSecret, err := crypto.DeriveSharedSecret(keyPair.Private, clientPubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to derive shared secret: %w", err)
	}

	return sharedSecret, nil
}


func (s *Server) handleClientComunication(conn net.Conn, sharedSecret []byte) {
	var handler crypto.EncryptionHandler = crypto.AESHandler{}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Println("Client", conn.RemoteAddr(), "disconnected.")
				break
			}
			fmt.Println("Read error:", err)
			continue
		}

		plaintext, err := handler.Decrypt(buf[:n], sharedSecret)
		if err != nil {
			log.Println("Decryption failed:", err)
			continue
		}

		s.msgCh <- Message{
			from:    conn.RemoteAddr().String(),
			payload: plaintext,
		}

		response := []byte("Thanks for sending stuff\n")
		ciphertext, err := handler.Encrypt(response, sharedSecret)
		if err != nil {
			log.Println("Encryption failed:", err)
			continue
		}

		conn.Write(ciphertext)
	}
}
