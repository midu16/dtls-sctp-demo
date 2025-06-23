package main

import (
	"flag"
	"log"
	"net"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/pion/dtls/v2"
)

func main() {
	server := flag.String("server", "127.0.0.1:5000", "SCTP server address")
	flag.Parse()

	raddr, err := sctp.ResolveSCTPAddr("sctp", *server)
	if err != nil {
		log.Fatalf("Failed to resolve SCTP address: %v", err)
	}

	conn, err := sctp.DialSCTP("sctp", nil, raddr)
	if err != nil {
		log.Fatalf("Failed to connect SCTP: %v", err)
	}
	defer conn.Close()

	log.Printf("Connected to SCTP server at %s", *server)

	// Perform DTLS handshake over SCTP
	dtlsConn, err := dtls.Client(conn, &dtls.Config{
		InsecureSkipVerify:    true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		log.Fatalf("DTLS handshake failed: %v", err)
	}
	defer dtlsConn.Close()

	// Send packets
	for i := 0; ; i++ {
		msg := []byte{0xde, 0xad, 0xbe, 0xef, byte(i & 0xff)}
		_, err := dtlsConn.Write(msg)
		if err != nil {
			log.Printf("Write failed: %v", err)
			return
		}
		log.Printf("Sent message %d", i)
		time.Sleep(1 * time.Second)
	}
}
