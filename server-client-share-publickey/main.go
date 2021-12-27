// Server and Client share their own public keys to each other
// Then they can generate the same secret
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"log"

	"github.com/cloudflare/circl/dh/sidh"
)

func main() {

	// Client generates key pair
	privClient := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSidhA)
	pubClient := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSidhA)

	if err := privClient.Generate(rand.Reader); err != nil {
		log.Fatal(err)
	}
	privClient.GeneratePublicKey(pubClient)

	// Server generates key pair
	privServer := sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSidhB)
	pubServer := sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSidhB)

	if err := privServer.Generate(rand.Reader); err != nil {
		log.Fatal(err)
	}
	privServer.GeneratePublicKey(pubServer)

	// Now, let's say, Client and Server shares their public key to each other
	// MITM can do nothing with the public key at all

	// Client makes shared secret key from the server's public key using client's private key
	clientSS := make([]byte, privClient.SharedSecretSize()) // Buffers storing shared secret
	privClient.DeriveSecret(clientSS, pubServer)

	// Server makes shared secret key from the client's public key using server's private key
	serverSS := make([]byte, privServer.SharedSecretSize()) // Buffers storing shared secret
	privServer.DeriveSecret(serverSS, pubClient)

	// Let's check if server and client have the same secret key
	fmt.Printf("part of secret key of client: %x\n", clientSS[:len(clientSS)/10])
	fmt.Printf("part of secret key of server: %x\n", serverSS[:len(serverSS)/10])
	fmt.Printf("server and client have the same secret key: %t\n", bytes.Equal(serverSS, clientSS))
}
