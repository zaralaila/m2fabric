/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	pqclib "github.com/zaralaila/pqc-bccsp/pqc"
)

// pqcTestKey wraps a generated PQC keypair plus its OID and CSP, used to sign
// test certificates.
type pqcTestKey struct {
	algo string
	oid  asn1.ObjectIdentifier
	csp  *pqclib.PQCBCCSP
	key  *pqclib.PQCBCCSPKey
}

func newPQCTestKey(t *testing.T, algo string) *pqcTestKey {
	t.Helper()
	csp, err := pqclib.New(algo)
	require.NoError(t, err)
	k, err := csp.KeyGen()
	require.NoError(t, err)
	var oid asn1.ObjectIdentifier
	switch algo {
	case "MLDSA44":
		oid = oidMLDSA44PQC
	case "MLDSA65":
		oid = oidMLDSA65PQC
	case "FNDSA512":
		oid = oidFNDSA512PQC
	default:
		t.Fatalf("unsupported algo %q", algo)
	}
	return &pqcTestKey{algo: algo, oid: oid, csp: csp, key: k}
}

// makePQCCert constructs a minimal X.509 certificate carrying a PQC SPKI and
// signed by `signer`. If signer == subject, the certificate is self-signed
// (used for the CA root). The signature follows the same convention as
// fabric-ca's CreatePQCCertificate: SHA-256(TBSCertificate) signed by the
// PQC private key, with the cert's SignatureAlgorithm field set to
// ECDSAWithSHA256 (matching the live cert generator).
func makePQCCert(
	t *testing.T,
	subject *pqcTestKey,
	signer *pqcTestKey,
	cn string,
	issuerCN string,
	isCA bool,
	notBefore, notAfter time.Time,
	serial int64,
) *x509.Certificate {
	t.Helper()

	// SubjectPublicKeyInfo
	subjectPub := subject.key.PublicKeyBytes()
	spki := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: subject.oid},
		PublicKey: asn1.BitString{Bytes: subjectPub, BitLength: len(subjectPub) * 8},
	}
	spkiDER, err := asn1.Marshal(spki)
	require.NoError(t, err)

	// Subject and issuer DNs (single CN attribute)
	mkRDN := func(cn string) []byte {
		name := pkix.Name{CommonName: cn}
		der, err := asn1.Marshal(name.ToRDNSequence())
		require.NoError(t, err)
		return der
	}
	subjectRDN := mkRDN(cn)
	issuerRDN := mkRDN(issuerCN)

	// BasicConstraints
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	bcDER, err := asn1.Marshal(basicConstraints{IsCA: isCA})
	require.NoError(t, err)
	bcExt := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
		Critical: true,
		Value:    bcDER,
	}

	exts := []pkix.Extension{bcExt}
	if isCA {
		// KeyUsage: digitalSignature(0) + keyCertSign(5) + cRLSign(6)
		var bits [2]byte
		bits[0] |= 0x80 // digitalSignature
		bits[0] |= 0x04 // keyCertSign
		bits[0] |= 0x02 // cRLSign
		kuDER, err := asn1.Marshal(asn1.BitString{Bytes: bits[:], BitLength: 9})
		require.NoError(t, err)
		exts = append(exts, pkix.Extension{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
			Critical: true,
			Value:    kuDER,
		})
	}

	sigAlg := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ECDSAWithSHA256, matches generator
	}

	type tbsCertificate struct {
		Version              int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber         *big.Int
		Signature            pkix.AlgorithmIdentifier
		Issuer               asn1.RawValue
		Validity             struct{ NotBefore, NotAfter time.Time }
		Subject              asn1.RawValue
		SubjectPublicKeyInfo asn1.RawValue
		Extensions           []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	tbs := tbsCertificate{
		Version:              2,
		SerialNumber:         big.NewInt(serial),
		Signature:            sigAlg,
		Issuer:               asn1.RawValue{FullBytes: issuerRDN},
		Validity:             struct{ NotBefore, NotAfter time.Time }{notBefore.UTC(), notAfter.UTC()},
		Subject:              asn1.RawValue{FullBytes: subjectRDN},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiDER},
		Extensions:           exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	require.NoError(t, err)

	digest := sha256.Sum256(tbsDER)
	sig, err := signer.csp.Sign(signer.key, digest[:])
	require.NoError(t, err)

	type certificate struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		Signature          asn1.BitString
	}
	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlg,
		Signature:          asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	certDER, err := asn1.Marshal(cert)
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return parsed
}

// newMSPWithRoots builds a minimal bccspmsp populated with the given root CAs,
// sufficient for buildPQCChain to operate.
func newMSPWithRoots(t *testing.T, roots ...*x509.Certificate) *bccspmsp {
	t.Helper()
	m := &bccspmsp{}
	for _, r := range roots {
		m.rootCerts = append(m.rootCerts, &identity{cert: r})
	}
	return m
}

func TestBuildPQCChain_ValidChain(t *testing.T) {
	for _, algo := range []string{"MLDSA44", "MLDSA65", "FNDSA512"} {
		t.Run(algo, func(t *testing.T) {
			ca := newPQCTestKey(t, algo)
			leaf := newPQCTestKey(t, algo)
			notBefore := time.Now().Add(-time.Hour)
			notAfter := time.Now().Add(24 * time.Hour)

			caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true, notBefore, notAfter, 1)
			leafCert := makePQCCert(t, leaf, ca, "TestLeaf", "TestCA", false, notBefore, notAfter, 2)

			m := newMSPWithRoots(t, caCert)
			chain, err := m.buildPQCChain(leafCert)
			require.NoError(t, err)
			require.Len(t, chain, 2)
			require.Equal(t, leafCert.Raw, chain[0].Raw)
			require.Equal(t, caCert.Raw, chain[1].Raw)
		})
	}
}

func TestBuildPQCChain_TamperedSignature(t *testing.T) {
	for _, algo := range []string{"MLDSA44", "MLDSA65", "FNDSA512"} {
		t.Run(algo, func(t *testing.T) {
			ca := newPQCTestKey(t, algo)
			leaf := newPQCTestKey(t, algo)
			notBefore := time.Now().Add(-time.Hour)
			notAfter := time.Now().Add(24 * time.Hour)

			caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true, notBefore, notAfter, 1)
			leafCert := makePQCCert(t, leaf, ca, "TestLeaf", "TestCA", false, notBefore, notAfter, 2)

			// Flip a byte in the parsed signature. Note: x509.ParseCertificate copies
			// the signature into cert.Signature, so mutating that field is enough for
			// buildPQCChain (which reads cert.Signature directly).
			leafCert.Signature[0] ^= 0xFF

			m := newMSPWithRoots(t, caCert)
			_, err := m.buildPQCChain(leafCert)
			require.Error(t, err)
			require.Contains(t, err.Error(), "post-quantum signature does not verify")
		})
	}
}

func TestBuildPQCChain_UnknownIssuer(t *testing.T) {
	ca := newPQCTestKey(t, "MLDSA44")
	other := newPQCTestKey(t, "MLDSA44")
	leaf := newPQCTestKey(t, "MLDSA44")
	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)

	caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true, notBefore, notAfter, 1)
	leafCert := makePQCCert(t, leaf, other, "TestLeaf", "OtherCA", false, notBefore, notAfter, 2)

	m := newMSPWithRoots(t, caCert)
	_, err := m.buildPQCChain(leafCert)
	require.Error(t, err)
}

func TestBuildPQCChain_ExpiredCert(t *testing.T) {
	ca := newPQCTestKey(t, "MLDSA44")
	leaf := newPQCTestKey(t, "MLDSA44")
	caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true,
		time.Now().Add(-2*time.Hour), time.Now().Add(2*time.Hour), 1)
	leafCert := makePQCCert(t, leaf, ca, "TestLeaf", "TestCA", false,
		time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), 2)

	m := newMSPWithRoots(t, caCert)
	_, err := m.buildPQCChain(leafCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired")
}

func TestBuildPQCChain_NotYetValid(t *testing.T) {
	ca := newPQCTestKey(t, "MLDSA44")
	leaf := newPQCTestKey(t, "MLDSA44")
	caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true,
		time.Now().Add(-2*time.Hour), time.Now().Add(2*time.Hour), 1)
	leafCert := makePQCCert(t, leaf, ca, "TestLeaf", "TestCA", false,
		time.Now().Add(time.Hour), time.Now().Add(48*time.Hour), 2)

	m := newMSPWithRoots(t, caCert)
	_, err := m.buildPQCChain(leafCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not yet valid")
}

func TestBuildPQCChain_SelfSignedRootNotConfigured(t *testing.T) {
	ca := newPQCTestKey(t, "MLDSA44")
	caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), 1)

	// MSP has NO roots configured.
	m := newMSPWithRoots(t)
	_, err := m.buildPQCChain(caCert)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a configured root CA")
}

func TestBuildPQCChain_HelpersOnPQCCert(t *testing.T) {
	ca := newPQCTestKey(t, "MLDSA65")
	caCert := makePQCCert(t, ca, ca, "TestCA", "TestCA", true,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), 1)

	require.True(t, isPQCCertificate(caCert))
	algo, pub, err := pqcSPKIInfo(caCert)
	require.NoError(t, err)
	require.Equal(t, "MLDSA65", algo)
	require.Equal(t, ca.key.PublicKeyBytes(), pub)
}
