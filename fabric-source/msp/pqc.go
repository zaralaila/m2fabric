/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package msp

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"strings"
	"time"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/pkg/errors"
	pqclib "github.com/zaralaila/pqc-bccsp/pqc"
)

// Post-quantum algorithm OIDs.
//   - ML-DSA-44 / ML-DSA-65: FIPS 204
//   - FN-DSA-512:            FIPS 206 draft assignment used by go-fn-dsa
var (
	oidMLDSA44PQC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65PQC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidFNDSA512PQC = asn1.ObjectIdentifier{1, 3, 9999, 3, 6}
)

// pqcAlgoFromOID maps a known post-quantum algorithm OID to the algorithm name
// understood by pqclib. Returns "" if the OID is not a recognised PQC algorithm.
func pqcAlgoFromOID(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(oidMLDSA44PQC):
		return "MLDSA44"
	case oid.Equal(oidMLDSA65PQC):
		return "MLDSA65"
	case oid.Equal(oidFNDSA512PQC):
		return "FNDSA512"
	}
	return ""
}

// pqcSPKIInfo parses cert.RawSubjectPublicKeyInfo and returns the PQC algorithm
// name and raw public key bytes if the SPKI carries a known post-quantum OID.
// Returns ("", nil, nil) when the public key is not a recognised PQC algorithm.
func pqcSPKIInfo(cert *x509.Certificate) (string, []byte, error) {
	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	var s spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &s); err != nil {
		return "", nil, errors.WithMessage(err, "parse SPKI")
	}
	algo := pqcAlgoFromOID(s.Algorithm.Algorithm)
	if algo == "" {
		return "", nil, nil
	}
	return algo, s.PublicKey.Bytes, nil
}

// certSignatureAlgorithmOID extracts the OID of the certificate's outer
// signatureAlgorithm field by re-parsing cert.Raw. Go's x509.Certificate
// struct does not expose the OID directly when the algorithm is unknown to
// crypto/x509 (e.g. post-quantum), so we re-read the wrapper SEQUENCE.
func certSignatureAlgorithmOID(cert *x509.Certificate) (asn1.ObjectIdentifier, error) {
	type wrapper struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm pkix.AlgorithmIdentifier
		SignatureValue     asn1.BitString
	}
	var w wrapper
	if _, err := asn1.Unmarshal(cert.Raw, &w); err != nil {
		return nil, errors.WithMessage(err, "parse outer Certificate")
	}
	return w.SignatureAlgorithm.Algorithm, nil
}

// isPQCCertificate reports whether cert's SubjectPublicKeyInfo carries a known
// post-quantum algorithm OID.
func isPQCCertificate(cert *x509.Certificate) bool {
	algo, _, _ := pqcSPKIInfo(cert)
	return algo != ""
}

// hasPQCAnchors reports whether any of the MSP's trust anchors (root or
// intermediate CAs) is a post-quantum certificate. When true, the chain
// validator must use buildPQCChain because Go's x509.Verify cannot parse
// PQC public keys. Slices may contain nil entries during MSP setup; those
// are skipped.
func (msp *bccspmsp) hasPQCAnchors() bool {
	for _, set := range [][]Identity{msp.rootCerts, msp.intermediateCerts} {
		for _, id := range set {
			ident, ok := id.(*identity)
			if !ok || ident == nil {
				continue
			}
			if isPQCCertificate(ident.cert) {
				return true
			}
		}
	}
	return false
}

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

// buildPQCChain validates and returns the certification chain for cert,
// supporting hybrid chains containing both classical and post-quantum links.
//
// For each link [child <- issuer] in the chain the validator:
//
//  1. Locates issuer in the MSP intermediate or root CA set by Subject DN match
//  2. Checks notBefore/notAfter on both child and issuer
//  3. Checks issuer.IsCA and (when KeyUsage is present) keyCertSign
//  4. Checks AuthorityKeyId(child) == SubjectKeyId(issuer) when both are present
//  5. Verifies the cryptographic signature using the appropriate algorithm:
//       - PQC issuer  -> SHA-256(child.RawTBSCertificate) verified via pqclib
//       - classical   -> Go's x509.Certificate.CheckSignatureFrom
//
// Algorithm dispatch is keyed on the issuer's SubjectPublicKeyInfo OID rather
// than the child's signatureAlgorithm field. CreatePQCCertificate stamps a
// fixed ECDSAWithSHA256 OID into the signatureAlgorithm field of every
// PQC-signed cert; the issuer's SPKI OID is the only authoritative indicator
// of which verification path is correct.
//
// Returns the validated chain [leaf, ..., root]. Errors identify the failing
// step and certificate.
func (msp *bccspmsp) buildPQCChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	const maxChainDepth = 10
	now := time.Now()
	chain := []*x509.Certificate{cert}
	current := cert

	for i := 0; i < maxChainDepth; i++ {
		// Self-signed terminator: must be a configured root.
		if bytes.Equal(current.RawIssuer, current.RawSubject) {
			if !msp.isConfiguredRoot(current) {
				return nil, errors.Errorf(
					"buildPQCChain: self-signed certificate %q is not a configured root CA",
					current.Subject.CommonName)
			}
			if err := msp.verifyChainLink(current, current, now); err != nil {
				return nil, errors.WithMessagef(err,
					"buildPQCChain: self-signed root %q", current.Subject.CommonName)
			}
			return chain, nil
		}

		issuer, err := msp.findIssuerFor(current)
		if err != nil {
			return nil, err
		}
		if err := msp.verifyChainLink(current, issuer, now); err != nil {
			return nil, errors.WithMessagef(err,
				"buildPQCChain: link %d (%q <- %q)",
				i, current.Subject.CommonName, issuer.Subject.CommonName)
		}
		chain = append(chain, issuer)
		current = issuer
	}
	return nil, errors.Errorf("buildPQCChain: chain depth exceeds %d", maxChainDepth)
}

// findIssuerFor searches MSP intermediate then root CA sets for a certificate
// whose Subject DN matches cert.Issuer.
func (msp *bccspmsp) findIssuerFor(cert *x509.Certificate) (*x509.Certificate, error) {
	for _, set := range [][]Identity{msp.intermediateCerts, msp.rootCerts} {
		for _, id := range set {
			ident, ok := id.(*identity)
			if !ok || ident == nil {
				continue
			}
			if bytes.Equal(cert.RawIssuer, ident.cert.RawSubject) {
				return ident.cert, nil
			}
		}
	}
	return nil, x509.UnknownAuthorityError{Cert: cert}
}

// isConfiguredRoot reports whether cert is one of the MSP's configured root certs.
func (msp *bccspmsp) isConfiguredRoot(cert *x509.Certificate) bool {
	for _, id := range msp.rootCerts {
		ident, ok := id.(*identity)
		if !ok || ident == nil {
			continue
		}
		if bytes.Equal(ident.cert.Raw, cert.Raw) {
			return true
		}
	}
	return false
}

// verifyChainLink runs all per-link checks: validity period, CA constraints,
// AKID/SKID matching, and signature verification.
//
// When child == issuer (self-signed root) the child-validity check is skipped
// because it is identical to the issuer-validity check.
func (msp *bccspmsp) verifyChainLink(child, issuer *x509.Certificate, now time.Time) error {
	if now.Before(issuer.NotBefore) {
		return errors.Errorf("issuer not yet valid (notBefore %s)", issuer.NotBefore)
	}
	if now.After(issuer.NotAfter) {
		return errors.Errorf("issuer expired (notAfter %s)", issuer.NotAfter)
	}
	if child != issuer {
		if now.Before(child.NotBefore) {
			return errors.Errorf("certificate not yet valid (notBefore %s)", child.NotBefore)
		}
		if now.After(child.NotAfter) {
			return errors.Errorf("certificate expired (notAfter %s)", child.NotAfter)
		}
	}

	if !issuer.IsCA {
		return errors.New("issuer is not a CA (BasicConstraints false or absent)")
	}
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("issuer KeyUsage does not include keyCertSign")
	}

	if len(child.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 {
		if !bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId) {
			return errors.New("AuthorityKeyId of child does not match SubjectKeyId of issuer")
		}
	}

	// Dispatch on the child's signatureAlgorithm OID. PQC certificates issued
	// by the M2Fabric CA carry the PQC algorithm OID directly in this field
	// (post-fix); legacy PQC certificates that still carry the
	// ecdsa-with-SHA256 placeholder are handled by the SPKI fallback below.
	sigAlgOID, err := certSignatureAlgorithmOID(child)
	if err != nil {
		return errors.WithMessage(err, "read child signatureAlgorithm OID")
	}
	algo := pqcAlgoFromOID(sigAlgOID)

	// Fallback: if the child's sigAlg is a classical OID but the issuer's SPKI
	// carries a PQC OID, this is a legacy-format PQC certificate. Trust the
	// issuer's algorithm and verify accordingly.
	issuerAlgo, issuerRawPub, err := pqcSPKIInfo(issuer)
	if err != nil {
		return errors.WithMessage(err, "parse issuer SPKI")
	}
	if algo == "" && issuerAlgo != "" {
		algo = issuerAlgo
	}

	if algo == "" {
		// Fully classical link: delegate signature verification to Go x509.
		return child.CheckSignatureFrom(issuer)
	}

	if issuerAlgo == "" {
		return errors.Errorf("certificate claims %s signature but issuer public key is not post-quantum", algo)
	}
	if issuerAlgo != algo {
		return errors.Errorf("certificate signatureAlgorithm %s does not match issuer key algorithm %s",
			algo, issuerAlgo)
	}

	// Post-quantum verification: pass the raw TBSCertificate to pqclib. The
	// underlying ML-DSA / FN-DSA primitives perform their FIPS-mandated
	// internal hashing, so no caller-side pre-hash is needed.
	csp, err := pqclib.New(algo)
	if err != nil {
		return errors.WithMessagef(err, "instantiate PQC CSP for %s", algo)
	}
	pubKey, err := csp.ImportKey(issuerRawPub, false)
	if err != nil {
		return errors.WithMessage(err, "import issuer public key")
	}
	valid, err := csp.Verify(pubKey, child.Signature, child.RawTBSCertificate)
	if err != nil {
		return errors.WithMessage(err, "PQC signature verification")
	}
	if valid {
		return nil
	}

	// Legacy fallback: certificates produced by the pre-fix generator signed
	// SHA-256(TBSCertificate) instead of the raw TBS. Try once more with the
	// pre-hash so that already-issued credentials remain verifiable through
	// the migration window.
	digest := sha256.Sum256(child.RawTBSCertificate)
	valid, err = csp.Verify(pubKey, child.Signature, digest[:])
	if err != nil {
		return errors.WithMessage(err, "PQC signature verification (pre-hash retry)")
	}
	if !valid {
		return errors.Errorf("post-quantum signature does not verify (algorithm %s)", algo)
	}
	return nil
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
