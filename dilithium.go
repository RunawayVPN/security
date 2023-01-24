package security

import (
	dili "github.com/acheong08/crystals-go/dilithium"
)

/// Dilithium functions

// DGenerateKeyPair generates a public and private key pair for Dilithium
func DGenerateKeyPair() ([]byte, []byte) {
	return dili.NewDilithium5().KeyGen(nil)
}

// DSign signs a message with a private key via Dilithium
func DSign(privkey []byte, message []byte) []byte {
	return dili.NewDilithium5().Sign(privkey, message)
}

// DVerify verifies a signature with a public key via Dilithium
func DVerify(pubkey []byte, message []byte, signature []byte) bool {
	return dili.NewDilithium5().Verify(pubkey, []byte(message), signature)
}
