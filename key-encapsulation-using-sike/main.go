// 1. Only server shares its public key to client
// 2. Client generate "shared secret" and encapsulate "cipher text" from server's public key with client's private key
// 3. Server receives only "cipher text" from the client
// 4. Now, server can decapsulate "shared secret" from the "cipher text" with its private key and public key

package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/cloudflare/circl/dh/sidh"
)

func main() {

	// Server generates key pair.
	privServer := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
	pubServer := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)

	if err := privServer.Generate(rand.Reader); err != nil {
		log.Fatal(err)
	}
	privServer.GeneratePublicKey(pubServer)

	// Assume server sends its public key to client.
	// Client generates "shared secret" and encapsulate "cipher text"
	// from server's public key with client's private key
	kemClient := sidh.NewSike503(rand.Reader)
	cipherText := make([]byte, kemClient.CiphertextSize())
	clientSS := make([]byte, kemClient.SharedSecretSize())

	if err := kemClient.Encapsulate(cipherText, clientSS, pubServer); err != nil {
		log.Fatal(err)
	}

	// Now, Client has "shared secret"
	// Assume client sends only "cipher text" to the server(MITM, has nothing to do with "cipher text")
	// Server can decapsulate "shared secret" from the "cipher text" with its private key and public key
	kemServer := sidh.NewSike503(rand.Reader)
	serverSS := make([]byte, kemServer.SharedSecretSize())
	if err := kemServer.Decapsulate(serverSS, privServer, pubServer, cipherText); err != nil {
		log.Fatal(err)
	}

	// Let's check if server and client have the same secret key
	fmt.Printf("secret key of client: %x\n", clientSS)
	fmt.Printf("secret key of server: %x\n", serverSS)
	fmt.Printf("server and client have the same secret key: %t\n", bytes.Equal(serverSS, clientSS))
}
