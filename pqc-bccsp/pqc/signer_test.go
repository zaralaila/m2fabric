package pqc

import (
	"testing"
)

func testAlgorithm(t *testing.T, keyType KeyType, name string) {
	t.Helper()

	// Generate a key pair
	key, err := GenerateKey(keyType)
	if err != nil {
		t.Fatalf("%s: key generation failed: %v", name, err)
	}
	t.Logf("%s: public key size  = %d bytes", name, len(key.PublicKey))
	t.Logf("%s: private key size = %d bytes", name, len(key.PrivKey))

	// Sign a test message
	msg := []byte("Hyperledger Fabric post-quantum test transaction")
	sig, err := Sign(key, msg)
	if err != nil {
		t.Fatalf("%s: signing failed: %v", name, err)
	}
	t.Logf("%s: signature size   = %d bytes", name, len(sig))

	// Verify with correct public key — must return true
	pubOnly := key.PublicOnly()
	valid, err := Verify(pubOnly, msg, sig)
	if err != nil {
		t.Fatalf("%s: verification error: %v", name, err)
	}
	if !valid {
		t.Fatalf("%s: valid signature failed verification", name)
	}
	t.Logf("%s: valid signature verified correctly ✓", name)

	// Verify with wrong message — must return false
	wrongMsg := []byte("tampered message")
	invalid, err := Verify(pubOnly, wrongMsg, sig)
	if err != nil {
		t.Fatalf("%s: verification error on wrong message: %v", name, err)
	}
	if invalid {
		t.Fatalf("%s: invalid signature incorrectly accepted", name)
	}
	t.Logf("%s: tampered message correctly rejected ✓", name)
}

func TestMLDSA44(t *testing.T)  { testAlgorithm(t, MLDSA44, "ML-DSA-44") }
func TestMLDSA65(t *testing.T)  { testAlgorithm(t, MLDSA65, "ML-DSA-65") }
func TestFNDSA512(t *testing.T) { testAlgorithm(t, FNDSA512, "FN-DSA-512") }

func BenchmarkMLDSA44KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(MLDSA44)
	}
}
func BenchmarkMLDSA44Sign(b *testing.B) {
	key, _ := GenerateKey(MLDSA44)
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(key, msg)
	}
}
func BenchmarkMLDSA44Verify(b *testing.B) {
	key, _ := GenerateKey(MLDSA44)
	msg := []byte("benchmark message")
	sig, _ := Sign(key, msg)
	pub := key.PublicOnly()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}
func BenchmarkMLDSA65KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(MLDSA65)
	}
}
func BenchmarkMLDSA65Sign(b *testing.B) {
	key, _ := GenerateKey(MLDSA65)
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(key, msg)
	}
}
func BenchmarkMLDSA65Verify(b *testing.B) {
	key, _ := GenerateKey(MLDSA65)
	msg := []byte("benchmark message")
	sig, _ := Sign(key, msg)
	pub := key.PublicOnly()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}
func BenchmarkFNDSA512KeyGen(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKey(FNDSA512)
	}
}
func BenchmarkFNDSA512Sign(b *testing.B) {
	key, _ := GenerateKey(FNDSA512)
	msg := []byte("benchmark message")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(key, msg)
	}
}
func BenchmarkFNDSA512Verify(b *testing.B) {
	key, _ := GenerateKey(FNDSA512)
	msg := []byte("benchmark message")
	sig, _ := Sign(key, msg)
	pub := key.PublicOnly()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(pub, msg, sig)
	}
}
