package pqc

// KeyType identifies which PQC algorithm a key belongs to.
type KeyType int

const (
    MLDSA44  KeyType = iota // ML-DSA at NIST security level 2 (FIPS 204)
    MLDSA65                  // ML-DSA at NIST security level 3 (FIPS 204)
    FNDSA512                 // FN-DSA degree-512 (FIPS 206 / FALCON-512)
)

// PQCKey holds a post-quantum key pair or public key.
// PrivateKey is nil when only the public key is available.
type PQCKey struct {
    KeyType   KeyType
    PublicKey []byte
    PrivKey   []byte // nil for public-key-only instances
}

// Private returns true if this key contains a private component.
func (k *PQCKey) Private() bool {
    return len(k.PrivKey) > 0
}

// Public returns a copy of this key containing only the public component.
func (k *PQCKey) PublicOnly() *PQCKey {
    return &PQCKey{
        KeyType:   k.KeyType,
        PublicKey: k.PublicKey,
        PrivKey:   nil,
    }
}
