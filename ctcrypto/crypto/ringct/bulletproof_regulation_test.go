package ringct

import (
	"math/rand"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

func TestEdgeBulletProofWithRegulation(t *testing.T) {
	random_gamma := crypto.SkGen()
	sL, sR, rho, S := GenRegulationParaForBulletproof()
	if S == nil {
		t.Fatalf("GenRegulationParaForBulletproof test failed")
	}
	b0 := BULLETPROOF_Prove_Amount_WithRegulation(0, &random_gamma, sL, sR, rho)

	if !b0.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof 0 amount test failed")
	}
	if !b0.BULLETPROOF_Verify_fast() {
		t.Fatalf("BulletProof fast 0 amount test failed")
	}

	if !b0.BULLETPROOF_Verify_ultrafast() {
		t.Fatalf("BulletProof ultra fast 0 amount test failed")
	}

	bmax := BULLETPROOF_Prove_Amount_WithRegulation(0xffffffffffffffff, &random_gamma, sL, sR, rho)

	if !bmax.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof 0xffffffffffffffff max amount test failed")
	}
	if !bmax.BULLETPROOF_Verify_fast() {
		t.Fatalf("BulletProof fast 0xffffffffffffffff max amount test failed")
	}
	if !bmax.BULLETPROOF_Verify_ultrafast() {
		t.Fatalf("BulletProof ultrafast 0xffffffffffffffff max amount test failed")
	}

	invalid_8 := crypto.Zero
	invalid_8[8] = 1

	binvalid8 := BULLETPROOF_Prove_WithRegulation(&invalid_8, &random_gamma, sL, sR, rho)

	if binvalid8.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof invalid 8 test failed")
	}

	if binvalid8.BULLETPROOF_Verify_fast() {
		t.Fatalf("BulletProof invalid 8 test failed")
	}
	if binvalid8.BULLETPROOF_Verify_ultrafast() {
		t.Fatalf("BulletProof invalid 8 test failed")
	}

	invalid_31 := crypto.Zero
	invalid_31[31] = 1

	binvalid31 := BULLETPROOF_Prove_WithRegulation(&invalid_31, &random_gamma, sL, sR, rho)

	if binvalid31.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof invalid 31 test failed")
	}
	if binvalid31.BULLETPROOF_Verify_fast() {
		t.Fatalf("BulletProof invalid 31 fast test failed")
	}
	if binvalid31.BULLETPROOF_Verify_ultrafast() {
		t.Fatalf("BulletProof invalid 31 fast test failed")
	}

}

func TestEdgeBulletProofWithRegulationRaw(t *testing.T) {
	random_gamma := crypto.SkGen()
	sL, sR, rho, S := GenRegulationParaForBulletproof()
	b00 := BULLETPROOF_Prove_Amount_WithRegulation(0, &random_gamma, sL, sR, rho)

	if !b00.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof 0 amount test failed")
	}
	if S == nil {
		t.Fatalf("GenRegulationParaForBulletproof test failed")
	}
	b0 := BULLETPROOF_Prove_Amount_WithRegulation_Raw(0, &random_gamma, sL, sR, rho)

	if !b0.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof ultra fast 0 amount test failed")
	}
	amount := b0.ExtractAmount(sL)
	if *d2h(0) != amount {
		t.Fatalf("BulletProof ultrafast 0 ExtractAmount failed")
	}

	bmax := BULLETPROOF_Prove_Amount_WithRegulation_Raw(0xffffffffffffffff, &random_gamma, sL, sR, rho)

	if !bmax.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof ultrafast 0xffffffffffffffff max amount test failed")
	}
	amount = bmax.ExtractAmount(sL)
	if *d2h(0xffffffffffffffff) != amount {
		t.Fatalf("BulletProof ultrafast 0xffffffffffffffff ExtractAmount failed")
	}

	invalid_8 := crypto.Zero
	invalid_8[8] = 1

	binvalid8 := BULLETPROOF_Prove_WithRegulation_Raw(&invalid_8, &random_gamma, sL, sR, rho)

	if binvalid8.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof invalid 8 test failed")
	}

	invalid_31 := crypto.Zero
	invalid_31[31] = 1

	binvalid31 := BULLETPROOF_Prove_WithRegulation_Raw(&invalid_31, &random_gamma, sL, sR, rho)

	if binvalid31.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof invalid 31 fast test failed")
	}

}

func TestEdgeBulletProofWithRegulationOpt(t *testing.T) {
	random_gamma := crypto.SkGen()
	sL, sR, rho, S := GenRegulationParaForBulletproof()
	b00 := BULLETPROOF_Prove_Amount_WithRegulation(0, &random_gamma, sL, sR, rho)

	if !b00.BULLETPROOF_Verify() {
		t.Fatalf("BulletProof 0 amount test failed")
	}
	if S == nil {
		t.Fatalf("GenRegulationParaForBulletproof test failed")
	}
	b0 := BULLETPROOF_Prove_Amount_WithRegulation_Raw(0, &random_gamma, sL, sR, rho)
	proof := []BulletProof{*b0}
	if !b0.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof ultra fast 0 amount test failed")
	}

	amount := b0.ExtractAmount(sL)
	if *d2h(0) != amount {
		t.Fatalf("BulletProof ultrafast 0 ExtractAmount failed")
	}

	bmax := BULLETPROOF_Prove_Amount_WithRegulation_Raw(0xffffffffffffffff, &random_gamma, sL, sR, rho)

	if !bmax.BULLETPROOF_Verify_Raw_ultrafast() {
		t.Fatalf("BulletProof ultrafast 0xffffffffffffffff max amount test failed")
	}
	amount = bmax.ExtractAmount(sL)
	if *d2h(0xffffffffffffffff) != amount {
		t.Fatalf("BulletProof ultrafast 0xffffffffffffffff ExtractAmount failed")
	}
	count := 2
	_masks := make([]crypto.Key, count)
	_amount := make([]crypto.Key, count)
	for i := range _masks {
		_masks[i] = crypto.SkGen()
		_amount[i] = *d2h(rand.Uint64())
	}
	sL2, sR2, rho, S := GenRegulationParaForBulletproof2(uint32(count))
	proof0 := BULLETPROOF_Prove2_raw(_amount, _masks)
	if !BULLETPROOF_Verify2_Optimized_WithRegulation([]BulletProof{*proof0}) {
		t.Fatalf("BulletProof BULLETPROOF_Verify2_Optimized_WithRegulation test failed")
	}

	proof = []BulletProof{*BULLETPROOF_Prove2_WithRegulation(_amount, _masks, sL2, sR2, *rho)}

	if !BULLETPROOF_Verify2_Optimized_WithRegulation(proof) {
		t.Fatalf("BulletProof BULLETPROOF_Verify2_Optimized_WithRegulation test failed")
	}
}

func BenchmarkBulletproofVerifyultrafastRaw(b *testing.B) {

	cpufile, err := os.Create("/tmp/bp_cpuprofile_fast.prof")
	if err != nil {

	}
	if err := pprof.StartCPUProfile(cpufile); err != nil {
	}
	defer pprof.StopCPUProfile()

	random_gamma := crypto.SkGen()
	sL, sR, rho, _ := GenRegulationParaForBulletproof()
	bp := BULLETPROOF_Prove_Amount_WithRegulation_Raw(0, &random_gamma, sL, sR, rho)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !bp.BULLETPROOF_Verify_Raw_ultrafast() {
			b.Fatalf("BulletProof verification failed")
		}
	}
}

func BenchmarkBulletProofRawWithMultipleV(b *testing.B) {
	count := 2
	proofCount := 5
	var proofs []BulletProof
	for i := 0; i < proofCount; i++ {
		_masks := make([]crypto.Key, count)
		_amount := make([]crypto.Key, count)
		for i := range _masks {
			_masks[i] = crypto.SkGen()
			_amount[i] = *d2h(rand.Uint64())
		}
		sL2, sR2, rho, _ := GenRegulationParaForBulletproof2(uint32(count))
		proofs = append(proofs, *BULLETPROOF_Prove2_WithRegulation(_amount, _masks, sL2, sR2, *rho))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !BULLETPROOF_Verify2_Optimized_WithRegulation(proofs) {
			b.Fatalf("BULLETPROOF_Verify2_Optimized failed")
		}
	}
}