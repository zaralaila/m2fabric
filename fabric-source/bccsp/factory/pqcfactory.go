/*
Copyright Zara Laila Cheong. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package factory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/sw"
	"github.com/pkg/errors"
	"github.com/zaralaila/pqc-bccsp/pqc"
)

const PQCBasedFactoryName = "PQC"

type PQCFactory struct{}

func (f *PQCFactory) Name() string { return PQCBasedFactoryName }

func (f *PQCFactory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	if config == nil || config.PQC == nil {
		return nil, errors.New("Invalid config. PQC options must not be nil.")
	}
	algName := config.PQC.Algorithm
	if algName == "" {
		algName = "MLDSA44"
	}
	inner, err := pqc.New(algName)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to initialize PQC BCCSP")
	}

	var ks bccsp.KeyStore
	keystorePath := ""
	if config.SW != nil && config.SW.FileKeystore != nil && config.SW.FileKeystore.KeyStorePath != "" {
		keystorePath = config.SW.FileKeystore.KeyStorePath
		fks, err := sw.NewFileBasedKeyStore(nil, keystorePath, false)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to initialize key store")
		}
		ks = fks
	} else {
		ks = sw.NewDummyKeyStore()
	}

	swCSP, err := sw.NewWithParams(256, "SHA2", ks)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to initialize SW BCCSP fallback")
	}

	return &pqcBCCSPWrapper{inner: inner, sw: swCSP, keystorePath: keystorePath}, nil
}

type PQCOpts struct {
	Algorithm string `json:"algorithm" yaml:"Algorithm"`
}

type pqcBCCSPWrapper struct {
	inner        *pqc.PQCBCCSP
	sw           bccsp.BCCSP
	keystorePath string
}

func (w *pqcBCCSPWrapper) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	k, err := w.inner.KeyGen()
	if err != nil {
		return nil, err
	}
	return &pqcKeyWrapper{inner: k}, nil
}

func (w *pqcBCCSPWrapper) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return w.sw.KeyDeriv(k, opts)
}

func (w *pqcBCCSPWrapper) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	switch v := raw.(type) {
	case []byte:
		// Try x509 certificate first — delegate to SW which handles ECDSA natively
		if _, err := x509.ParseCertificate(v); err == nil {
			return w.sw.KeyImport(raw, opts)
		}
		// Try PKIX public key — delegate to SW
		if pub, err := x509.ParsePKIXPublicKey(v); err == nil {
			if _, ok := pub.(*ecdsa.PublicKey); ok {
				return w.sw.KeyImport(raw, opts)
			}
		}
		// Raw PQC key bytes
		private := false
		if pqcOpts, ok := opts.(*pqc.PQCKeyImportOpts); ok {
			private = pqcOpts.IsPrivate
		}
		k, err := w.inner.ImportKey(v, private)
		if err != nil {
			return nil, err
		}
		return &pqcKeyWrapper{inner: k}, nil

	case *ecdsa.PublicKey:
		return w.sw.KeyImport(raw, opts)

	case *x509.Certificate:
		return w.sw.KeyImport(raw, opts)

	default:
		return nil, fmt.Errorf("KeyImport: unsupported raw type %T", raw)
	}
}

func (w *pqcBCCSPWrapper) GetKey(ski []byte) (bccsp.Key, error) {
	// Try SW first — handles ECDSA keys from keystore
	if w.sw != nil {
		k, err := w.sw.GetKey(ski)
		if err == nil {
			return k, nil
		}
	}
	// Try reading PQC key from keystore directory directly
	if w.keystorePath != "" {
		skiHex := hex.EncodeToString(ski)
		keyFile := filepath.Join(w.keystorePath, skiHex+"_sk")
		data, err := os.ReadFile(keyFile)
		if err == nil && len(data) > 0 {
			k, err := w.inner.ImportKey(data, true)
			if err == nil {
				return &pqcKeyWrapper{inner: k}, nil
			}
		}
	}
	return nil, fmt.Errorf("GetKey: key not found for SKI %x", ski)
}

func (w *pqcBCCSPWrapper) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	return w.inner.Hash(msg)
}

func (w *pqcBCCSPWrapper) GetHash(opts bccsp.HashOpts) (hash.Hash, error) {
	return w.inner.GetHash(), nil
}

func (w *pqcBCCSPWrapper) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	if pqcKey, ok := k.(*pqcKeyWrapper); ok {
		return w.inner.Sign(pqcKey.inner, digest)
	}
	return w.sw.Sign(k, digest, opts)
}

func (w *pqcBCCSPWrapper) Verify(k bccsp.Key, sig, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	if pqcKey, ok := k.(*pqcKeyWrapper); ok {
		return w.inner.Verify(pqcKey.inner, sig, digest)
	}
	// Delegate all non-PQC verification to SW (ECDSA MSP certificates)
	return w.sw.Verify(k, sig, digest, opts)
}

func (w *pqcBCCSPWrapper) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	return w.sw.Encrypt(k, plaintext, opts)
}

func (w *pqcBCCSPWrapper) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	return w.sw.Decrypt(k, ciphertext, opts)
}

type pqcKeyWrapper struct {
	inner *pqc.PQCBCCSPKey
}

func (k *pqcKeyWrapper) Bytes() ([]byte, error)        { return k.inner.Bytes() }
func (k *pqcKeyWrapper) SKI() []byte                   { return k.inner.SKI() }
func (k *pqcKeyWrapper) Symmetric() bool               { return false }
func (k *pqcKeyWrapper) Private() bool                 { return k.inner.IsPrivate() }
func (k *pqcKeyWrapper) PublicKey() (bccsp.Key, error) {
	return &pqcKeyWrapper{inner: k.inner.PublicOnly()}, nil
}

// ecdsaPublicKeyWrapper is kept for SKI computation only.
// All actual ECDSA operations are now delegated to the SW BCCSP.
type ecdsaPublicKeyWrapper struct {
	pub *ecdsa.PublicKey
}

func (k *ecdsaPublicKeyWrapper) Bytes() ([]byte, error) {
	return elliptic.Marshal(k.pub.Curve, k.pub.X, k.pub.Y), nil
}

func (k *ecdsaPublicKeyWrapper) SKI() []byte {
	raw := elliptic.Marshal(k.pub.Curve, k.pub.X, k.pub.Y)
	h := sha256.Sum256(raw)
	return h[:]
}

func (k *ecdsaPublicKeyWrapper) Symmetric() bool               { return false }
func (k *ecdsaPublicKeyWrapper) Private() bool                 { return false }
func (k *ecdsaPublicKeyWrapper) PublicKey() (bccsp.Key, error) { return k, nil }
