package pqc

import (
	"testing"
)

func testBCCSP(t *testing.T, algName string) {
	t.Helper()

	csp, err := New(algName)
	if err != nil {
		t.Fatalf("%s: New() failed: %v", algName, err)
	}

	k, err := csp.KeyGen()
	if err != nil {
		t.Fatalf("%s: KeyGen() failed: %v", algName, err)
	}

	msg := []byte("fabric transaction payload")
	sig, err := csp.Sign(k, msg)
	if err != nil {
		t.Fatalf("%s: Sign() failed: %v", algName, err)
	}
	t.Logf("%s: signature produced (%d bytes)", algName, len(sig))

	pub := k.PublicOnly()
	valid, err := csp.Verify(pub, sig, msg)
	if err != nil {
		t.Fatalf("%s: Verify() failed: %v", algName, err)
	}
	if !valid {
		t.Fatalf("%s: valid signature rejected", algName)
	}
	t.Logf("%s: sign/verify ✓", algName)

	ski1 := k.SKI()
	ski2 := k.SKI()
	if string(ski1) != string(ski2) {
		t.Fatalf("%s: SKI is not deterministic", algName)
	}
	t.Logf("%s: SKI deterministic ✓ (%x...)", algName, ski1[:8])
}

func TestBCCSP_MLDSA44(t *testing.T)  { testBCCSP(t, "MLDSA44") }
func TestBCCSP_MLDSA65(t *testing.T)  { testBCCSP(t, "MLDSA65") }
func TestBCCSP_FNDSA512(t *testing.T) { testBCCSP(t, "FNDSA512") }
func TestBCCSP_Invalid(t *testing.T) {
	_, err := New("INVALID")
	if err == nil {
		t.Fatal("expected error for invalid algorithm, got nil")
	}
	t.Logf("invalid algorithm correctly rejected ✓")
}
