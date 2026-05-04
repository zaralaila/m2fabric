/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"strings"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	pqclib "github.com/zaralaila/pqc-bccsp/pqc"
)

// isUnknownAuthorityError returns true if the error is an x509 unknown authority error.
func isUnknownAuthorityError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "unknown authority") ||
		strings.Contains(s, "certificate signed by unknown") ||
		strings.Contains(s, "unknown public key")
}

// buildPQCChain manually builds a certificate chain for PQC-issued certs.
// Go's x509.Verify cannot verify chains with unknown public key algorithms,
// so we manually match the leaf's Issuer to a root/intermediate CA Subject.
func (msp *bccspmsp) buildPQCChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	// Self-signed CA: return [cert].
	if cert.IsCA && string(cert.RawIssuer) == string(cert.RawSubject) {
		return []*x509.Certificate{cert}, nil
	}
	// Search intermediates first, then roots, for the issuer.
	for _, ids := range [][]Identity{msp.intermediateCerts, msp.rootCerts} {
		for _, id := range ids {
			ca := id.(*identity).cert
			if string(cert.RawIssuer) == string(ca.RawSubject) {
				return []*x509.Certificate{cert, ca}, nil
			}
		}
	}
	return nil, x509.UnknownAuthorityError{Cert: cert}
}

// loadPQCSignerFromPEM loads a PQC private key from PEM bytes.
// The algorithm is inferred from the key length (matches WritePQCPrivKeyPEM format).
func loadPQCSignerFromPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("loadPQCSignerFromPEM: invalid PEM block")
	}
	privBytes := block.Bytes
	var algoName string
	switch len(privBytes) {
	case 2560:
		algoName = "MLDSA44"
	case 4032:
		algoName = "MLDSA65"
	case 1281:
		algoName = "FNDSA512"
	default:
		return nil, errors.Errorf("loadPQCSignerFromPEM: unrecognised key size %d bytes", len(privBytes))
	}
	csp, err := pqclib.New(algoName)
	if err != nil {
		return nil, errors.WithMessagef(err, "loadPQCSignerFromPEM: failed to create CSP for %s", algoName)
	}
	privKey, err := csp.ImportKey(privBytes, true)
	if err != nil {
		return nil, errors.WithMessage(err, "loadPQCSignerFromPEM: failed to import key")
	}
	pubKeyBytes := privKey.PublicKeyBytes()
	return &pqcMSPSigner{csp: csp, priv: privKey, pubBytes: pubKeyBytes}, nil
}

type pqcMSPSigner struct {
	csp      *pqclib.PQCBCCSP
	priv     *pqclib.PQCBCCSPKey
	pubBytes []byte
}

func (s *pqcMSPSigner) Public() crypto.PublicKey { return s.pubBytes }

func (s *pqcMSPSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.priv, digest)
}

// newPQCSigningIdentity creates a SigningIdentity for a PQC key pair.
func newPQCSigningIdentity(cert *x509.Certificate, pk bccsp.Key, signer crypto.Signer, msp *bccspmsp) (SigningIdentity, error) {
	return newSigningIdentity(cert, pk, signer, msp)
}
