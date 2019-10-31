package benchmark

import (
	"github.com/ethereum/go-ethereum/ctcrypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto/ringct"
	"github.com/ethereum/go-ethereum/params"
	"math/rand"
	"testing"
)

func BenchmarkBulletproofsVerify(b *testing.B) {
	random_gamma := crypto.SkGen()
	bp := ringct.BULLETPROOF_Prove_Amount(0, &random_gamma)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !bp.BULLETPROOF_Verify_ultrafast() {
			b.Fatalf("BulletProof verification failed")
		}
	}
}

func BenchmarkBulletproofsWithRegulationVerify(b *testing.B) {
	random_gamma := crypto.SkGen()
	sL, sR, rho, _ := ringct.GenRegulationParaForBulletproof()
	bp := ringct.BULLETPROOF_Prove_Amount_WithRegulation_Raw(0, &random_gamma, sL, sR, rho)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !bp.BULLETPROOF_Verify_Raw_ultrafast() {
			b.Fatalf("BulletProof verification failed")
		}
	}
}

func BenchmarkBulletproofsVerifyBatch(b *testing.B) {
	count := 1
	proofCount := 1
	var proofs []ringct.BulletProof
	for i := 0; i < proofCount; i++ {
		_masks := make([]crypto.Key, count)
		_amount := make([]crypto.Key, count)
		for i := range _masks {
			_masks[i] = crypto.SkGen()
			_amount[i] = *ringct.D2h(rand.Uint64())
		}
		proofs = append(proofs, *ringct.BULLETPROOF_Prove2(_amount, _masks))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !ringct.BULLETPROOF_Verify2_Optimized(proofs) {
			b.Fatalf("BULLETPROOF_Verify2_Optimized failed")
		}
	}
}

func BenchmarkBulletproofsWithRegulationVerifyBatch(b *testing.B) {
	count := 1
	proofCount := 1
	var proofs []ringct.BulletProof
	for i := 0; i < proofCount; i++ {
		_masks := make([]crypto.Key, count)
		_amount := make([]crypto.Key, count)
		for i := range _masks {
			_masks[i] = crypto.SkGen()
			_amount[i] = *ringct.D2h(rand.Uint64())
		}
		sL2, sR2, rho, _ := ringct.GenRegulationParaForBulletproof2(uint32(count))
		proofs = append(proofs, *ringct.BULLETPROOF_Prove2_WithRegulation(_amount, _masks, sL2, sR2, *rho))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !ringct.BULLETPROOF_Verify2_Optimized_WithRegulation(proofs) {
			b.Fatalf("BULLETPROOF_Verify2_Optimized failed")
		}
	}
}

func BenchmarkBulletproofsVerifyBatch2V5P(b *testing.B) {
	count := 2
	proofCount := 5
	var proofs []ringct.BulletProof
	for i := 0; i < proofCount; i++ {
		_masks := make([]crypto.Key, count)
		_amount := make([]crypto.Key, count)
		for i := range _masks {
			_masks[i] = crypto.SkGen()
			_amount[i] = *ringct.D2h(rand.Uint64())
		}
		proofs = append(proofs, *ringct.BULLETPROOF_Prove2(_amount, _masks))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !ringct.BULLETPROOF_Verify2_Optimized(proofs) {
			b.Fatalf("BULLETPROOF_Verify2_Optimized failed")
		}
	}
}

func BenchmarkBulletproofsWithRegulationVerifyBatch2V5P(b *testing.B) {
	count := 2
	proofCount := 5
	var proofs []ringct.BulletProof
	for i := 0; i < proofCount; i++ {
		_masks := make([]crypto.Key, count)
		_amount := make([]crypto.Key, count)
		for i := range _masks {
			_masks[i] = crypto.SkGen()
			_amount[i] = *ringct.D2h(rand.Uint64())
		}
		sL2, sR2, rho, _ := ringct.GenRegulationParaForBulletproof2(uint32(count))
		proofs = append(proofs, *ringct.BULLETPROOF_Prove2_WithRegulation(_amount, _masks, sL2, sR2, *rho))
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !ringct.BULLETPROOF_Verify2_Optimized_WithRegulation(proofs) {
			b.Fatalf("BULLETPROOF_Verify2_Optimized failed")
		}
	}
}

func BenchmarkVerifiableShuffle(b *testing.B) {
	count := ctcrypto.GetM() * 16
	r1 := make([]crypto.Key, count)
	amount := make([]crypto.Key, count)
	inputs := make([]crypto.Key, count)
	r2 := make([]crypto.Key, count)
	outputs := make([]crypto.Key, count)
	individualProof := make([]ctcrypto.IndividualProof, count)
	inputGas := make([]uint64, count)
	for i := range r1 {
		r1[i] = crypto.SkGen()
		amount[i] = *ringct.D2h(rand.Uint64())
		inputs[i] = ctcrypto.GenCommitment(&amount[i], &r1[i])
		r2[i] = crypto.SkGen()
		var r1r2 crypto.Key
		crypto.ScAdd(&r1r2, &r1[i], &r2[i])
		outputs[i] = ctcrypto.GenCommitment(&amount[i], &r1r2)
		inputGas[i] = params.ShuffleGas * 10
		individualProof[i] = *ctcrypto.GenIndividualProof(&amount[i], &r1r2, &outputs[i], inputGas[i])
	}
	proof, shuffledOutputs, outputsGas, shuffledIndividualProof := ctcrypto.GenVerifiableShuffle(inputs, inputGas, r2, individualProof)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !ctcrypto.VerVerifiableShuffle(inputs, shuffledOutputs, inputGas, outputsGas, proof, shuffledIndividualProof) {
			b.Fatalf("VerVerifiableShuffle failed")
		}
	}
}