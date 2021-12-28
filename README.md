# Analysing Golang sidh package

## Overview

Current cryptographic algorithms like RSA or DH are based on mathmetical theories(facotrization, 
discrete logarithm) and we think `quantum computer` will crack them fast. 

Golang [sidh package](https://pkg.go.dev/github.com/cloudflare/circl@v1.1.0/dh/sidh) is implementation of the `SIDH` and `SIKE`. 
They are cryptographic algorithms for the `post-quantum computer` era. 

Assume that server and client wants to share `secret key` and
let's see how we can share the key with `SIDH` and `SIKE` using [sidh package](https://pkg.go.dev/github.com/cloudflare/circl@v1.1.0/dh/sidh)


## SIDH - key exchange by sharing public keys

1. Server and client generate their own key pairs of the private/public key
2. They share their public key to each other
3. Now, they can make `shared secret key` and they will use it for the further secure communication

## SIKE - key exchange by encapsulating secret key

1. Server only generates its key pairs of the private/public key
2. Server shares its public key to client
3. Client makes KEM(Key Encapsulation Mechanism) instance
4. Client makes `shared secret key` and `cipher text` with KEM using server's public key
5. Client sends `cipher text` to the server
6. Server can make the same `secret key` from the `cipher text` using KEM which server makes


## Reference

Supersingular Isogeny Key Exchange(SIDH): https://www.wikiwand.com/en/Supersingular_isogeny_key_exchange
```
Supersingular isogeny Diffie-Hellman key exchange(SIDH) is a post-quantum cryptographic algorithm 
used to establish a secret key between two parties over an otherwise insecure communications channel
```


Supersingular Isogeny Key Encapsulation(SIKE): https://sike.org/
```
SIKE is an isogeny-based key encapsulation suite based on pseudo-random walks in supersingular
isogeny graphs, that was submitted to the NIST standardization process on post-quantum cryptography. 
```