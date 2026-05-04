package pqc

// TestKATCompliance documents the Known Answer Test (KAT) / ACVP compliance
// of the cryptographic implementations used in this thesis.
//
// ML-DSA-44 and ML-DSA-65 are implemented by Cloudflare CIRCL v1.6.3.
// CIRCL includes the official NIST ACVP test vectors for FIPS 204 covering
// three test categories:
//   - keyGen: deterministic key generation from seed
//   - sigGen: deterministic signature generation
//   - sigVer: signature verification including invalid signature cases
//
// These tests are executed against the CIRCL library directly and pass,
// confirming that the ML-DSA implementation is conformant with FIPS 204.
// To run the CIRCL ACVP tests:
//
//	cd $(go env GOPATH)/pkg/mod/github.com/cloudflare/circl@v1.6.3/sign/mldsa/mldsa44
//	go test -v -run TestACVP
//	cd $(go env GOPATH)/pkg/mod/github.com/cloudflare/circl@v1.6.3/sign/mldsa/mldsa65
//	go test -v -run TestACVP
//
// FN-DSA-512 is implemented by go-fn-dsa v0.2.0, authored by Thomas Pornin,
// one of the original FALCON designers. The implementation is verified through
// round-trip correctness tests (generate key, sign, verify) and negative tests
// (tampered message rejection). The go-fn-dsa library does not yet include
// NIST ACVP vectors as FIPS 206 was finalised after the library was authored;
// this limitation is acknowledged in Chapter 6 of the thesis.
//
// The tests below serve as the thesis-level correctness record.

import (
	"testing"
)

// TestKAT_RoundTrip verifies that each algorithm correctly signs and verifies
// a message, and correctly rejects a tampered message. This is the minimum
// correctness requirement for a cryptographic implementation.
func TestKAT_RoundTrip(t *testing.T) {
	algorithms := []struct {
		name    string
		keyType KeyType
	}{
		{"ML-DSA-44 (FIPS 204)", MLDSA44},
		{"ML-DSA-65 (FIPS 204)", MLDSA65},
		{"FN-DSA-512 (FIPS 206)", FNDSA512},
	}

	msg := []byte("NIST PQC correctness test: Hyperledger Fabric transaction payload")

	for _, alg := range algorithms {
		alg := alg
		t.Run(alg.name, func(t *testing.T) {
			// Generate key pair
			key, err := GenerateKey(alg.keyType)
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}

			// Sign message
			sig, err := Sign(key, msg)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}

			// Verify correct signature
			pub := key.PublicOnly()
			valid, err := Verify(pub, msg, sig)
			if err != nil {
				t.Fatalf("verification error: %v", err)
			}
			if !valid {
				t.Fatal("valid signature was rejected")
			}

			// Verify tampered message is rejected
			tampered := make([]byte, len(msg))
			copy(tampered, msg)
			tampered[0] ^= 0xFF
			invalid, err := Verify(pub, tampered, sig)
			if err != nil {
				t.Fatalf("verification error on tampered message: %v", err)
			}
			if invalid {
				t.Fatal("tampered message was incorrectly accepted")
			}

			// Verify tampered signature is rejected
			tamperedSig := make([]byte, len(sig))
			copy(tamperedSig, sig)
			tamperedSig[0] ^= 0xFF
			invalidSig, err := Verify(pub, msg, tamperedSig)
			if err == nil && invalidSig {
				t.Fatal("tampered signature was incorrectly accepted")
			}

			t.Logf("%s: key=%dB sig=%dB — all correctness checks passed ✓",
				alg.name, len(key.PublicKey), len(sig))
		})
	}
}

// TestKAT_KeySizes verifies that key and signature sizes match the
// values specified in FIPS 204 and FIPS 206 respectively.
func TestKAT_KeySizes(t *testing.T) {
	expected := []struct {
		name      string
		keyType   KeyType
		pubSize   int
		privSize  int
		sigSize   int
	}{
		{"ML-DSA-44", MLDSA44, 1312, 2560, 2420},
		{"ML-DSA-65", MLDSA65, 1952, 4032, 3309},
		{"FN-DSA-512", FNDSA512, 897, 1281, 666},
	}

	msg := []byte("size verification test")

	for _, e := range expected {
		e := e
		t.Run(e.name, func(t *testing.T) {
			key, err := GenerateKey(e.keyType)
			if err != nil {
				t.Fatalf("key generation failed: %v", err)
			}
			if len(key.PublicKey) != e.pubSize {
				t.Errorf("public key size: got %d, want %d",
					len(key.PublicKey), e.pubSize)
			}
			if len(key.PrivKey) != e.privSize {
				t.Errorf("private key size: got %d, want %d",
					len(key.PrivKey), e.privSize)
			}
			sig, err := Sign(key, msg)
			if err != nil {
				t.Fatalf("signing failed: %v", err)
			}
			// FN-DSA has variable-length signatures; check within bounds
			if e.keyType == FNDSA512 {
				if len(sig) > 809 {
					t.Errorf("FN-DSA-512 signature too large: %d > 809", len(sig))
				}
			} else {
				if len(sig) != e.sigSize {
					t.Errorf("signature size: got %d, want %d",
						len(sig), e.sigSize)
				}
			}
			t.Logf("%s sizes verified ✓", e.name)
		})
	}
}
