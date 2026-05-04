/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package sw

import (
	"encoding/asn1"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	pqclib "github.com/zaralaila/pqc-bccsp/pqc"
)

// Well-known OIDs for PQC signature algorithms.
var (
	oidMLDSA44  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidFNDSA512 = asn1.ObjectIdentifier{1, 3, 9999, 3, 6}
)

// pqcPublicKey is a BCCSP key for PQC certificates whose public key type
// is not recognized by Go's x509 package. It carries the raw SubjectPublicKeyInfo
// bytes so that MSP loading and signature verification can succeed.
type pqcPublicKey struct {
	certRaw []byte // RawSubjectPublicKeyInfo (ASN.1 DER)
}

func (k *pqcPublicKey) Type() string           { return "PQC" }
func (k *pqcPublicKey) Bytes() ([]byte, error) { return k.certRaw, nil }
func (k *pqcPublicKey) SKI() []byte {
	if len(k.certRaw) >= 32 {
		return k.certRaw[:32]
	}
	return k.certRaw
}
func (k *pqcPublicKey) Symmetric() bool              { return false }
func (k *pqcPublicKey) Private() bool                { return false }
func (k *pqcPublicKey) PublicKey() (bccsp.Key, error) { return k, nil }

// parseSPKI extracts the algorithm name and raw public key bytes from an
// ASN.1 DER-encoded SubjectPublicKeyInfo.
func parseSPKI(spkiDER []byte) (algoName string, pubKeyBytes []byte, err error) {
	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
	}
	type subjectPublicKeyInfo struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return "", nil, errors.Wrap(err, "failed to unmarshal SPKI")
	}
	oid := spki.Algorithm.Algorithm
	switch {
	case oid.Equal(oidMLDSA44):
		return "MLDSA44", spki.PublicKey.Bytes, nil
	case oid.Equal(oidMLDSA65):
		return "MLDSA65", spki.PublicKey.Bytes, nil
	case oid.Equal(oidFNDSA512):
		return "FNDSA512", spki.PublicKey.Bytes, nil
	default:
		return "", nil, errors.Errorf("unknown PQC algorithm OID: %v", oid)
	}
}

// pqcPublicKeyVerifier verifies signatures using PQC public keys.
type pqcPublicKeyVerifier struct{}

func (v *pqcPublicKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	pk, ok := k.(*pqcPublicKey)
	if !ok {
		return false, errors.New("invalid key type, expected *pqcPublicKey")
	}
	algoName, pubKeyBytes, err := parseSPKI(pk.certRaw)
	if err != nil {
		return false, errors.WithMessage(err, "pqcPublicKeyVerifier: failed parsing SPKI")
	}
	csp, err := pqclib.New(algoName)
	if err != nil {
		return false, errors.WithMessagef(err, "pqcPublicKeyVerifier: failed creating CSP for %s", algoName)
	}
	importedKey, err := csp.ImportKey(pubKeyBytes, false)
	if err != nil {
		return false, errors.WithMessage(err, "pqcPublicKeyVerifier: failed importing public key")
	}
	return csp.Verify(importedKey, signature, digest)
}
