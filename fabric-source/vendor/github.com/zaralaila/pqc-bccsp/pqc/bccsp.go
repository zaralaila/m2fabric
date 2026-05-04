package pqc

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"hash"
)

// PQCBCCSP implements post-quantum cryptographic operations.
// It does not import Fabric directly — the Fabric factory bridges
// between this struct and the bccsp.BCCSP interface.
type PQCBCCSP struct {
	keyType KeyType
}

// New creates a new PQCBCCSP instance for the given algorithm.
// algName must be one of: "MLDSA44", "MLDSA65", "FNDSA512".
func New(algName string) (*PQCBCCSP, error) {
	switch algName {
	case "MLDSA44":
		return &PQCBCCSP{keyType: MLDSA44}, nil
	case "MLDSA65":
		return &PQCBCCSP{keyType: MLDSA65}, nil
	case "FNDSA512":
		return &PQCBCCSP{keyType: FNDSA512}, nil
	default:
		return nil, fmt.Errorf("unsupported PQC algorithm: %s", algName)
	}
}

// KeyGen generates a new PQC key pair and returns it as a PQCBCCSPKey.
func (b *PQCBCCSP) KeyGen() (*PQCBCCSPKey, error) {
	k, err := GenerateKey(b.keyType)
	if err != nil {
		return nil, fmt.Errorf("PQCBCCSP KeyGen failed: %w", err)
	}
	return &PQCBCCSPKey{key: k}, nil
}

// Sign signs digest using the private key.
func (b *PQCBCCSP) Sign(k *PQCBCCSPKey, digest []byte) ([]byte, error) {
	if !k.key.Private() {
		return nil, fmt.Errorf("cannot sign: key has no private component")
	}
	return Sign(k.key, digest)
}

// Verify verifies sig against digest using the public key.
func (b *PQCBCCSP) Verify(k *PQCBCCSPKey, sig, digest []byte) (bool, error) {
	return Verify(k.key, digest, sig)
}

// ImportKey imports raw key bytes.
func (b *PQCBCCSP) ImportKey(raw []byte, private bool) (*PQCBCCSPKey, error) {
	var k *PQCKey
	if private {
		k = &PQCKey{KeyType: b.keyType, PrivKey: raw}
	} else {
		k = &PQCKey{KeyType: b.keyType, PublicKey: raw}
	}
	return &PQCBCCSPKey{key: k}, nil
}

// Hash hashes msg using SHA-256.
func (b *PQCBCCSP) Hash(msg []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil), nil
}

// GetHash returns a new SHA-256 hash instance.
func (b *PQCBCCSP) GetHash() hash.Hash {
	return sha256.New()
}

// PQCBCCSPKey wraps a PQCKey with SKI computation.
type PQCBCCSPKey struct {
	key *PQCKey
}

func (k *PQCBCCSPKey) Bytes() ([]byte, error) {
	if k.key.Private() {
		return k.key.PrivKey, nil
	}
	return k.key.PublicKey, nil
}

func (k *PQCBCCSPKey) SKI() []byte {
	h := crypto.SHA256.New()
	h.Write(k.key.PublicKey)
	return h.Sum(nil)
}

func (k *PQCBCCSPKey) IsPrivate() bool { return k.key.Private() }

func (k *PQCBCCSPKey) PublicKeyBytes() []byte { return k.key.PublicKey }

// KeyTypeName returns the algorithm name string for this key.
func (k *PQCBCCSPKey) KeyTypeName() string {
	switch k.key.KeyType {
	case MLDSA44:
		return "MLDSA44"
	case MLDSA65:
		return "MLDSA65"
	case FNDSA512:
		return "FNDSA512"
	default:
		return "UNKNOWN"
	}
}

func (k *PQCBCCSPKey) PublicOnly() *PQCBCCSPKey {
	return &PQCBCCSPKey{key: k.key.PublicOnly()}
}

// PQCKeyImportOpts specifies options for importing a PQC key.
// Used by the Fabric factory bridge in pqcfactory.go.
type PQCKeyImportOpts struct {
	IsPrivate   bool
	IsEphemeral bool
}

func (o *PQCKeyImportOpts) Algorithm() string { return "PQC" }
func (o *PQCKeyImportOpts) Ephemeral() bool   { return o.IsEphemeral }
