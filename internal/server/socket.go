package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"secure-fileserver/internal/core/crypto"
)

type Message struct {
	from    string
	payload []byte
}

type Server struct {
	listenAddr string
	ln         net.Listener
	quitCh     chan struct{}
	msgCh      chan Message
}

func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
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
			fmt.Println("accept error:", err)
			continue
		}

		fmt.Println("New connection to the server", conn.RemoteAddr())

		go s.readLoop(conn)
	}
}

func (s *Server) readLoop(conn net.Conn) {
	defer conn.Close()

	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Println("Key generation failed:", err)
		return
	}
	
	serverPubBytes := crypto.MarshalPublicKey(keyPair.Public)
	if _, err := conn.Write(serverPubBytes); err != nil {
		log.Println("Error sending public key to client:", err)
		return
	}

	clientPubBytes := make([]byte, 65)
	if _, err := io.ReadFull(conn, clientPubBytes); err != nil {
		log.Println("Error receiving client's public key:", err)
		return
	}

	clientPubKey, err := crypto.UnmarshalPublicKey(clientPubBytes)
	if err != nil {
		log.Println("Invalid client public key:", err)
		return
	}

	sharedSecret, err := crypto.DeriveSharedSecret(keyPair.Private, clientPubKey)
	if err != nil {
		log.Println("Failed to derive shared secret:", err)
		return
	}
	log.Println("Secure connection established with", conn.RemoteAddr())

	var handler crypto.EncryptionHandler = crypto.AESHandler{}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("read error:", err)
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

func main() {
	server := NewServer(":3000")

	go func() {
		for msg := range server.msgCh {
			fmt.Printf("received message from connection (%s):%s\n", msg.from, string(msg.payload))
		}
	}()

	log.Fatal(server.Start())
}
