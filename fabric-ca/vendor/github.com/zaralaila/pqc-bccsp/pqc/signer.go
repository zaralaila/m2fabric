package pqc

import (
	"crypto"
	"crypto/rand"
	"fmt"

	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	fndsa "github.com/pornin/go-fn-dsa/fndsa"
)

// logn512 is the degree parameter for FN-DSA-512 (2^9 = 512).
const logn512 uint = 9

// fndsaCtx is the empty domain context used for all FN-DSA operations.
var fndsaCtx fndsa.DomainContext

// GenerateKey generates a new key pair for the specified algorithm.
func GenerateKey(keyType KeyType) (*PQCKey, error) {
	switch keyType {
	case MLDSA44:
		pub, priv, err := mldsa44.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-44 key generation failed: %w", err)
		}
		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-44 public key marshal failed: %w", err)
		}
		privBytes, err := priv.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-44 private key marshal failed: %w", err)
		}
		return &PQCKey{KeyType: MLDSA44, PublicKey: pubBytes, PrivKey: privBytes}, nil

	case MLDSA65:
		pub, priv, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 key generation failed: %w", err)
		}
		pubBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 public key marshal failed: %w", err)
		}
		privBytes, err := priv.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("ML-DSA-65 private key marshal failed: %w", err)
		}
		return &PQCKey{KeyType: MLDSA65, PublicKey: pubBytes, PrivKey: privBytes}, nil

	case FNDSA512:
		skey, vkey, err := fndsa.KeyGen(logn512, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("FN-DSA-512 key generation failed: %w", err)
		}
		return &PQCKey{KeyType: FNDSA512, PublicKey: vkey, PrivKey: skey}, nil

	default:
		return nil, fmt.Errorf("unknown key type: %d", keyType)
	}
}

// Sign produces a signature over msg using the private key in k.
func Sign(k *PQCKey, msg []byte) ([]byte, error) {
	if !k.Private() {
		return nil, fmt.Errorf("cannot sign: key has no private component")
	}

	switch k.KeyType {
	case MLDSA44:
		var priv mldsa44.PrivateKey
		if err := priv.UnmarshalBinary(k.PrivKey); err != nil {
			return nil, fmt.Errorf("ML-DSA-44 private key unmarshal failed: %w", err)
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(&priv, msg, nil, false, sig); err != nil {
			return nil, fmt.Errorf("ML-DSA-44 signing failed: %w", err)
		}
		return sig, nil

	case MLDSA65:
		var priv mldsa65.PrivateKey
		if err := priv.UnmarshalBinary(k.PrivKey); err != nil {
			return nil, fmt.Errorf("ML-DSA-65 private key unmarshal failed: %w", err)
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(&priv, msg, nil, false, sig); err != nil {
			return nil, fmt.Errorf("ML-DSA-65 signing failed: %w", err)
		}
		return sig, nil

	case FNDSA512:
		sig, err := fndsa.Sign(rand.Reader, k.PrivKey, fndsaCtx, crypto.Hash(0), msg)
		if err != nil {
			return nil, fmt.Errorf("FN-DSA-512 signing failed: %w", err)
		}
		return sig, nil

	default:
		return nil, fmt.Errorf("unknown key type: %d", k.KeyType)
	}
}

// Verify checks a signature over msg using the public key in k.
// Returns true if the signature is valid.
func Verify(k *PQCKey, msg, sig []byte) (bool, error) {
	switch k.KeyType {
	case MLDSA44:
		var pub mldsa44.PublicKey
		if err := pub.UnmarshalBinary(k.PublicKey); err != nil {
			return false, fmt.Errorf("ML-DSA-44 public key unmarshal failed: %w", err)
		}
		return mldsa44.Verify(&pub, msg, nil, sig), nil

	case MLDSA65:
		var pub mldsa65.PublicKey
		if err := pub.UnmarshalBinary(k.PublicKey); err != nil {
			return false, fmt.Errorf("ML-DSA-65 public key unmarshal failed: %w", err)
		}
		return mldsa65.Verify(&pub, msg, nil, sig), nil

	case FNDSA512:
		ok := fndsa.Verify(k.PublicKey, fndsaCtx, crypto.Hash(0), msg, sig)
		return ok, nil

	default:
		return false, fmt.Errorf("unknown key type: %d", k.KeyType)
	}
}
