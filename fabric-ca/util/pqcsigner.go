/*
Copyright Zara Laila Cheong. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"time"

	cfslsigner "github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/pkg/errors"
	pqclib "github.com/zaralaila/pqc-bccsp/pqc"
)

var (
	OIDMLDsa44  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	OIDMLDsa65  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	OIDFNDsa512 = asn1.ObjectIdentifier{1, 3, 9999, 3, 6}
)

type PQCPublicKey struct {
	OID    asn1.ObjectIdentifier
	Algo   string
	RawPub []byte
}

type pqcCryptoSigner struct {
	csp *pqclib.PQCBCCSP
	key *pqclib.PQCBCCSPKey
	pub *PQCPublicKey
}

func (s *pqcCryptoSigner) Public() crypto.PublicKey { return s.pub }

func (s *pqcCryptoSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return s.csp.Sign(s.key, digest)
}

type pqcBCCSPKeyWrapper struct {
	inner *pqclib.PQCBCCSPKey
}

func (w *pqcBCCSPKeyWrapper) Bytes() ([]byte, error)        { return w.inner.Bytes() }
func (w *pqcBCCSPKeyWrapper) SKI() []byte                   { return w.inner.SKI() }
func (w *pqcBCCSPKeyWrapper) Symmetric() bool               { return false }
func (w *pqcBCCSPKeyWrapper) Private() bool                 { return w.inner.IsPrivate() }
func (w *pqcBCCSPKeyWrapper) PublicKey() (bccsp.Key, error) {
	return &pqcBCCSPKeyWrapper{inner: w.inner.PublicOnly()}, nil
}

func IsPQCAlgo(algo string) bool {
	switch algo {
	case "mldsa44", "mldsa65", "fndsa512", "MLDSA44", "MLDSA65", "FNDSA512":
		return true
	}
	return false
}

func normalisePQCAlgo(algo string) string {
	switch algo {
	case "mldsa44", "MLDSA44":
		return "MLDSA44"
	case "mldsa65", "MLDSA65":
		return "MLDSA65"
	case "fndsa512", "FNDSA512":
		return "FNDSA512"
	}
	return algo
}

func pqcOIDForAlgo(algo string) (asn1.ObjectIdentifier, error) {
	switch normalisePQCAlgo(algo) {
	case "MLDSA44":
		return OIDMLDsa44, nil
	case "MLDSA65":
		return OIDMLDsa65, nil
	case "FNDSA512":
		return OIDFNDsa512, nil
	}
	return nil, errors.Errorf("unknown PQC algorithm: %s", algo)
}

func BCCSPPQCKeyRequestGenerate(algo string) (bccsp.Key, crypto.Signer, error) {
	name := normalisePQCAlgo(algo)
	csp, err := pqclib.New(name)
	if err != nil {
		return nil, nil, errors.WithMessagef(err, "failed to create PQC BCCSP for %s", name)
	}
	k, err := csp.KeyGen()
	if err != nil {
		return nil, nil, errors.WithMessage(err, "PQC KeyGen failed")
	}
	rawPub := k.PublicKeyBytes()
	oid, err := pqcOIDForAlgo(algo)
	if err != nil {
		return nil, nil, err
	}
	pub := &PQCPublicKey{OID: oid, Algo: name, RawPub: rawPub}
	signer := &pqcCryptoSigner{csp: csp, key: k, pub: pub}
	wrapper := &pqcBCCSPKeyWrapper{inner: k}
	pqcSignerActive = true
	return wrapper, signer, nil
}

func MarshalPQCSPKI(pub *PQCPublicKey) ([]byte, error) {
	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
	}
	type subjectPublicKeyInfo struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}
	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{Algorithm: pub.OID},
		PublicKey: asn1.BitString{Bytes: pub.RawPub, BitLength: len(pub.RawPub) * 8},
	}
	return asn1.Marshal(spki)
}

type certValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func CreatePQCCertificate(
	template *x509.Certificate,
	parent *x509.Certificate,
	pubKey *PQCPublicKey,
	caSigner crypto.Signer,
	caSignAlg x509.SignatureAlgorithm,
) ([]byte, error) {
	spkiDER, err := MarshalPQCSPKI(pubKey)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal PQC SPKI")
	}
	issuer := template
	if parent != nil {
		issuer = parent
	}
	sigAlgOID, sigAlgParams, err := sigAlgFromX509(caSignAlg)
	if err != nil {
		return nil, err
	}
	exts, err := buildExtensions(template, parent == nil)
	if err != nil {
		return nil, err
	}
	type tbsCertificate struct {
		Version              int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber         *big.Int
		Signature            pkix.AlgorithmIdentifier
		Issuer               asn1.RawValue
		Validity             certValidity
		Subject              asn1.RawValue
		SubjectPublicKeyInfo asn1.RawValue
		Extensions           []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	issuerRDN, err := asn1.Marshal(issuer.Subject.ToRDNSequence())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal issuer RDN")
	}
	subjectRDN, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal subject RDN")
	}
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: sigAlgOID, Parameters: sigAlgParams}
	tbs := tbsCertificate{
		Version:              2,
		SerialNumber:         template.SerialNumber,
		Signature:            sigAlg,
		Issuer:               asn1.RawValue{FullBytes: issuerRDN},
		Validity:             certValidity{NotBefore: template.NotBefore.UTC(), NotAfter: template.NotAfter.UTC()},
		Subject:              asn1.RawValue{FullBytes: subjectRDN},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiDER},
		Extensions:           exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal TBSCertificate")
	}
	digest, err := hashForSigAlg(caSignAlg, tbsDER)
	if err != nil {
		return nil, err
	}
	sig, err := caSigner.Sign(rand.Reader, digest, hashOptsForSigAlg(caSignAlg))
	if err != nil {
		return nil, errors.WithMessage(err, "CA signing failed")
	}
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
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal Certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func sigAlgFromX509(alg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, asn1.RawValue, error) {
	null := asn1.RawValue{Tag: 5}
	switch alg {
	case x509.ECDSAWithSHA256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, null, nil
	case x509.ECDSAWithSHA384:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, null, nil
	}
	return nil, asn1.RawValue{}, errors.Errorf("unsupported CA signature algorithm: %v", alg)
}

func hashForSigAlg(alg x509.SignatureAlgorithm, data []byte) ([]byte, error) {
	h := hashOptsForSigAlg(alg)
	if h == 0 {
		return nil, errors.Errorf("unsupported signature algorithm for hashing: %v", alg)
	}
	hasher := h.New()
	hasher.Write(data)
	return hasher.Sum(nil), nil
}

func hashOptsForSigAlg(alg x509.SignatureAlgorithm) crypto.Hash {
	switch alg {
	case x509.ECDSAWithSHA256:
		return crypto.SHA256
	case x509.ECDSAWithSHA384:
		return crypto.SHA384
	}
	return 0
}

func buildExtensions(tmpl *x509.Certificate, isCA bool) ([]pkix.Extension, error) {
	var exts []pkix.Extension
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}
	bc := basicConstraints{IsCA: isCA}
	if isCA && tmpl.MaxPathLen > 0 {
		bc.MaxPathLen = tmpl.MaxPathLen
	}
	bcDER, err := asn1.Marshal(bc)
	if err != nil {
		return nil, err
	}
	exts = append(exts, pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: bcDER,
	})
	if len(tmpl.SubjectKeyId) > 0 {
		skidDER, err := asn1.Marshal(tmpl.SubjectKeyId)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: skidDER})
	}
	if tmpl.KeyUsage != 0 {
		kuDER, err := marshalKeyUsage(tmpl.KeyUsage)
		if err != nil {
			return nil, err
		}
		exts = append(exts, pkix.Extension{
			Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: kuDER,
		})
	}
	// Include SAN extension if the template has DNS names, IP addresses, or email addresses.
	if len(tmpl.DNSNames) > 0 || len(tmpl.IPAddresses) > 0 || len(tmpl.EmailAddresses) > 0 || len(tmpl.URIs) > 0 {
		sanExt, err := marshalSANExtension(tmpl)
		if err != nil {
			return nil, err
		}
		exts = append(exts, sanExt)
	}
	exts = append(exts, tmpl.ExtraExtensions...)
	return exts, nil
}

// marshalSANExtension builds the X.509 Subject Alternative Name extension (OID 2.5.29.17).
func marshalSANExtension(tmpl *x509.Certificate) (pkix.Extension, error) {
	// Use a temporary x509.Certificate to let the stdlib marshal the SAN for us.
	tmp := &x509.Certificate{
		DNSNames:       tmpl.DNSNames,
		IPAddresses:    tmpl.IPAddresses,
		EmailAddresses: tmpl.EmailAddresses,
		URIs:           tmpl.URIs,
	}
	// x509.MarshalPKIXPublicKey is not what we need; use CreateCertificate with a
	// dummy key just to extract the SAN bytes via the template's raw extensions.
	// Simpler: marshal SAN directly using asn1.
	type generalName struct {
		Tag   int    `asn1:"tag"`
		Value []byte `asn1:"optional"`
	}
	var names []asn1.RawValue
	for _, dns := range tmp.DNSNames {
		names = append(names, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(dns)})
	}
	for _, ip := range tmp.IPAddresses {
		ip4 := ip.To4()
		if ip4 != nil {
			names = append(names, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip4})
		} else {
			names = append(names, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
		}
	}
	for _, email := range tmp.EmailAddresses {
		names = append(names, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	sanDER, err := asn1.Marshal(names)
	if err != nil {
		return pkix.Extension{}, errors.WithMessage(err, "failed to marshal SAN")
	}
	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
		Value: sanDER,
	}, nil
}

func marshalKeyUsage(ku x509.KeyUsage) ([]byte, error) {
	var bits [2]byte
	if ku&x509.KeyUsageDigitalSignature != 0 {
		bits[0] |= 0x80
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		bits[0] |= 0x40
	}
	if ku&x509.KeyUsageCertSign != 0 {
		bits[0] |= 0x04
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		bits[0] |= 0x02
	}
	bs := asn1.BitString{Bytes: bits[:], BitLength: 9}
	return asn1.Marshal(bs)
}

// init registers the PQCCertCreator hook with CFSSL's local signer so that
// certificates with PQC public keys are created via CreatePQCCertificate
// rather than x509.CreateCertificate, which does not support unknown key types.
func init() {
	local.SetPQCCertCreator(func(template, parent *x509.Certificate, priv crypto.Signer) ([]byte, error) {
		switch pub := template.PublicKey.(type) {
		case *PQCPublicKey:
			// Key generated by BCCSPPQCKeyRequestGenerate (CA self-sign path)
			return CreatePQCCertificate(template, parent, pub, priv, x509.ECDSAWithSHA256)
		case *cfslsigner.PQCPublicKeyRaw:
			// Key extracted from a client-submitted PQC CSR
			p := &PQCPublicKey{
				OID:    pub.OID,
				RawPub: pub.RawPub,
			}
			// Determine algo name from OID for SPKI marshalling
			switch {
			case pub.OID.Equal(OIDMLDsa44):
				p.Algo = "MLDSA44"
			case pub.OID.Equal(OIDMLDsa65):
				p.Algo = "MLDSA65"
			case pub.OID.Equal(OIDFNDsa512):
				p.Algo = "FNDSA512"
			default:
				return nil, errors.Errorf("PQCCertCreator: unknown PQC OID %v", pub.OID)
			}
			return CreatePQCCertificate(template, parent, p, priv, x509.ECDSAWithSHA256)
		default:
			// Classical subject key (ECDSA/RSA) signed by PQC CA key.
			return CreatePQCCertificateWithRawSPKI(template, parent, priv, x509.ECDSAWithSHA256)
		}
	})
}

// PQCPublicKeyBytes returns the raw public key bytes. Implements csr.PQCSignerPublicKey.
func (p *PQCPublicKey) PQCPublicKeyBytes() []byte { return p.RawPub }

// PQCOID returns the algorithm OID. Implements csr.PQCSignerPublicKey.
func (p *PQCPublicKey) PQCOID() asn1.ObjectIdentifier { return p.OID }

// WritePQCPrivKeyPEM writes the private key from a PQC crypto.Signer to a
// PEM file at path. This must be called after BCCSPPQCKeyRequestGenerate so
// that the CA can reload its key on restart via the ca-key.pem fallback path.
func WritePQCPrivKeyPEM(signer crypto.Signer, path string) error {
	s, ok := signer.(*pqcCryptoSigner)
	if !ok {
		return errors.Errorf("WritePQCPrivKeyPEM: expected *pqcCryptoSigner, got %T", signer)
	}
	privBytes, err := s.key.Bytes()
	if err != nil {
		return errors.WithMessage(err, "WritePQCPrivKeyPEM: failed to get private key bytes")
	}
	if len(privBytes) == 0 {
		return errors.New("WritePQCPrivKeyPEM: private key bytes are empty")
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	pemBytes := pem.EncodeToMemory(block)
	return os.WriteFile(path, pemBytes, 0600)
}

// LoadPQCSignerFromPEM reads a raw PQC private key from a PEM file written
// by WritePQCPrivKeyPEM and reconstructs a crypto.Signer from it.
// The algorithm is inferred from the key length.
func LoadPQCSignerFromPEM(keyFile string) (crypto.Signer, error) {
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.WithMessagef(err, "LoadPQCSignerFromPEM: cannot read %s", keyFile)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.Errorf("LoadPQCSignerFromPEM: no PEM block in %s", keyFile)
	}
	privBytes := block.Bytes
	// Infer algorithm from private key size (FIPS 204/206 fixed sizes)
	var algoName string
	switch len(privBytes) {
	case 2560:
		algoName = "MLDSA44"
	case 4032:
		algoName = "MLDSA65"
	case 1281:
		algoName = "FNDSA512"
	default:
		return nil, errors.Errorf("LoadPQCSignerFromPEM: unrecognised PQC key size %d bytes", len(privBytes))
	}
	csp, err := pqclib.New(algoName)
	if err != nil {
		return nil, errors.WithMessagef(err, "LoadPQCSignerFromPEM: failed to create BCCSP for %s", algoName)
	}
	k, err := csp.ImportKey(privBytes, true)
	if err != nil {
		return nil, errors.WithMessagef(err, "LoadPQCSignerFromPEM: ImportKey failed for %s", algoName)
	}
	oid, _ := pqcOIDForAlgo(algoName)
	pub := &PQCPublicKey{OID: oid, Algo: algoName, RawPub: k.PublicKeyBytes()}
	pqcSignerActive = true
	return &pqcCryptoSigner{csp: csp, key: k, pub: pub}, nil
}


// CreatePQCCertificateWithRawSPKI creates a certificate with a classical subject
// public key (ECDSA/RSA) signed by a PQC CA key, bypassing x509.CreateCertificate.
func CreatePQCCertificateWithRawSPKI(
	template *x509.Certificate,
	parent *x509.Certificate,
	caSigner crypto.Signer,
	caSignAlg x509.SignatureAlgorithm,
) ([]byte, error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(template.PublicKey)
	if err != nil {
		return nil, errors.WithMessage(err, "CreatePQCCertificateWithRawSPKI: failed to marshal subject SPKI")
	}
	issuer := template
	if parent != nil {
		issuer = parent
	}
	sigAlgOID, sigAlgParams, err := sigAlgFromX509(caSignAlg)
	if err != nil {
		return nil, err
	}
	exts, err := buildExtensions(template, parent == nil)
	if err != nil {
		return nil, err
	}
	type tbsCertificate struct {
		Version              int `asn1:"optional,explicit,tag:0,default:0"`
		SerialNumber         *big.Int
		Signature            pkix.AlgorithmIdentifier
		Issuer               asn1.RawValue
		Validity             certValidity
		Subject              asn1.RawValue
		SubjectPublicKeyInfo asn1.RawValue
		Extensions           []pkix.Extension `asn1:"optional,explicit,tag:3"`
	}
	issuerRDN, err := asn1.Marshal(issuer.Subject.ToRDNSequence())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal issuer RDN")
	}
	subjectRDN, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal subject RDN")
	}
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: sigAlgOID, Parameters: sigAlgParams}
	tbs := tbsCertificate{
		Version:              2,
		SerialNumber:         template.SerialNumber,
		Signature:            sigAlg,
		Issuer:               asn1.RawValue{FullBytes: issuerRDN},
		Validity:             certValidity{NotBefore: template.NotBefore.UTC(), NotAfter: template.NotAfter.UTC()},
		Subject:              asn1.RawValue{FullBytes: subjectRDN},
		SubjectPublicKeyInfo: asn1.RawValue{FullBytes: spkiDER},
		Extensions:           exts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal TBSCertificate")
	}
	digest, err := hashForSigAlg(caSignAlg, tbsDER)
	if err != nil {
		return nil, err
	}
	sig, err := caSigner.Sign(rand.Reader, digest, hashOptsForSigAlg(caSignAlg))
	if err != nil {
		return nil, errors.WithMessage(err, "CA signing failed")
	}
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
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal Certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}


// IsPQCSigner returns true if the given CFSSL signer uses a PQC private key.
func IsPQCSigner(s interface{}) bool {
	type hasPQCPriv interface {
		Certificate(label, profile string) (*x509.Certificate, error)
	}
	// Check by attempting to get the signer's underlying crypto.Signer public key
	type privKeyHolder interface {
		GetSigner() crypto.Signer
	}
	// Simplest duck-type: check if the CA cert's public key is our PQC type
	// by trying to cast it — we don't have direct access to the signer here,
	// so we use a package-level flag set when LoadPQCSignerFromPEM succeeds.
	return pqcSignerActive
}

// pqcSignerActive is set to true when the CA enrollment signer uses a PQC key.
var pqcSignerActive bool

// SetPQCSignerActive marks that the CA is using a PQC enrollment signer.
func SetPQCSignerActive(v bool) { pqcSignerActive = v }

// SelfSignTLSCert creates a self-signed ECDSA TLS certificate for the CA server.
// This is needed when the CA uses a PQC signing key, since Go's TLS stack
// cannot verify certificates signed with non-standard algorithms.
func SelfSignTLSCert(cn string, hosts []string, names []struct{ C, ST, O string }, homeDir string) ([]byte, error) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.WithMessage(err, "SelfSignTLSCert: failed to generate ECDSA key")
	}
	// Write the key to the keystore so the TLS listener can load it
	keyPath := homeDir + "/tls-key.pem"
	keyDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		return nil, errors.WithMessage(err, "SelfSignTLSCert: failed to marshal ECDSA key")
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err = os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return nil, errors.WithMessage(err, "SelfSignTLSCert: failed to write TLS key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.WithMessage(err, "SelfSignTLSCert: failed to generate serial")
	}
	if cn == "" {
		cn = "fabric-ca-server"
	}
	subj := pkix.Name{CommonName: cn}
	if len(names) > 0 {
		n := names[0]
		subj = pkix.Name{
			CommonName:   cn,
			Country:      []string{n.C},
			Province:     []string{n.ST},
			Organization: []string{n.O},
		}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subj,
		NotBefore:             time.Now().Add(-10 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              hosts,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	if err != nil {
		return nil, errors.WithMessage(err, "SelfSignTLSCert: x509.CreateCertificate failed")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}


// ExtractCNFromCSR extracts the CommonName from a PQC CSR's raw DER bytes
// without relying on x509.ParseCertificateRequest (which rejects unknown OIDs).
func ExtractCNFromCSR(csrDER []byte) (string, error) {
	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	type certificationRequestInfo struct {
		Version             int
		Subject             asn1.RawValue
		SubjectPublicKeyInfo spki
		Attributes          []asn1.RawValue `asn1:"optional,tag:0"`
	}
	type certificationRequest struct {
		CertificationRequestInfo certificationRequestInfo
		SignatureAlgorithm       pkix.AlgorithmIdentifier
		Signature                asn1.BitString
	}
	var req certificationRequest
	if _, err := asn1.Unmarshal(csrDER, &req); err != nil {
		return "", errors.WithMessage(err, "ExtractCNFromCSR: failed to parse CSR ASN.1")
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(req.CertificationRequestInfo.Subject.FullBytes, &subject); err != nil {
		return "", errors.WithMessage(err, "ExtractCNFromCSR: failed to parse subject")
	}
	var name pkix.Name
	name.FillFromRDNSequence(&subject)
	return name.CommonName, nil
}


// PQCSigningKey is implemented by bccsp.Key wrappers that also hold a crypto.Signer
// for PQC algorithms. Used by CreateToken to generate PQC authentication tokens.
type PQCSigningKey interface {
	CryptoSigner() crypto.Signer
}

// CryptoSigner returns a crypto.Signer backed by this PQC key. Implements PQCSigningKey.
func (w *pqcBCCSPKeyWrapper) CryptoSigner() crypto.Signer {
	algoName := w.inner.KeyTypeName()
	csp, _ := pqclib.New(algoName)
	oid, _ := pqcOIDForAlgo(algoName)
	pub := &PQCPublicKey{OID: oid, Algo: algoName, RawPub: w.inner.PublicKeyBytes()}
	return &pqcCryptoSigner{csp: csp, key: w.inner, pub: pub}
}

// GenPQCToken generates a fabric-ca authentication token signed with a PQC key.
func GenPQCToken(cert []byte, signer crypto.Signer, method, uri string, body []byte) (string, error) {
	b64body := base64.StdEncoding.EncodeToString(body)
	b64cert := base64.StdEncoding.EncodeToString(cert)
	b64uri := base64.StdEncoding.EncodeToString([]byte(uri))
	payload := method + "." + b64uri + "." + b64body + "." + b64cert
	h := crypto.SHA256.New()
	h.Write([]byte(payload))
	digest := h.Sum(nil)
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", errors.WithMessage(err, "GenPQCToken: signing failed")
	}
	b64sig := base64.StdEncoding.EncodeToString(sig)
	return b64cert + "." + b64sig, nil
}


// VerifyPQCToken verifies a fabric-ca authentication token signed with a PQC key.
// It extracts the raw public key from the certificate's SPKI and verifies the signature.
func VerifyPQCToken(cert *x509.Certificate, sig []byte, sigString string) error {
	// Extract the raw public key from the certificate's RawSubjectPublicKeyInfo
	type spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	var s spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &s); err != nil {
		return errors.WithMessage(err, "VerifyPQCToken: failed to parse SPKI")
	}
	rawPub := s.PublicKey.Bytes
	oid := s.Algorithm.Algorithm

	// Determine algorithm from OID
	var algoName string
	switch {
	case oid.Equal(OIDMLDsa44):
		algoName = "MLDSA44"
	case oid.Equal(OIDMLDsa65):
		algoName = "MLDSA65"
	case oid.Equal(OIDFNDsa512):
		algoName = "FNDSA512"
	default:
		return errors.Errorf("VerifyPQCToken: unknown PQC OID %v", oid)
	}

	csp, err := pqclib.New(algoName)
	if err != nil {
		return errors.WithMessage(err, "VerifyPQCToken: failed to create PQC CSP")
	}

	// Hash the sigString with SHA-256 (matches GenPQCToken)
	h := crypto.SHA256.New()
	h.Write([]byte(sigString))
	digest := h.Sum(nil)

	// Import the public key and verify
	pubKey, err := csp.ImportKey(rawPub, false)
	if err != nil {
		return errors.WithMessage(err, "VerifyPQCToken: failed to import public key")
	}
	valid, err := csp.Verify(pubKey, sig, digest)
	if err != nil {
		return errors.WithMessage(err, "VerifyPQCToken: verification error")
	}
	if !valid {
		return errors.New("VerifyPQCToken: signature verification failed")
	}
	return nil
}
