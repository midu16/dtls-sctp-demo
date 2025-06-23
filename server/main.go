package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/pion/dtls/v2"
)

func generateCertificate() tls.Certificate {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	return cert
}

func main() {
	laddr := &sctp.SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.ParseIP("0.0.0.0")}},
		Port:    5000,
	}
	listener, err := sctp.ListenSCTP("sctp", laddr)
	if err != nil {
		log.Fatalf("Failed to listen on SCTP: %v", err)
	}
	log.Println("SCTP server listening on 0.0.0.0:5000")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept SCTP connection: %v", err)
			continue
		}
		go handleDTLS(conn)
	}
}

func handleDTLS(sctpConn net.Conn) {
	cert := generateCertificate()
	dtlsConn, err := dtls.Server(sctpConn, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		log.Printf("DTLS handshake failed: %v", err)
		return
	}
	defer dtlsConn.Close()

	log.Printf("DTLS session established")

	buf := make([]byte, 1500)
	for {
		n, err := dtlsConn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}
		log.Printf("Received: %x", buf[:n])
	}
}
