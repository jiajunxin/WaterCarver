package ctcrypto

import (
	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto/ringct"
	"math/rand"
	"testing"
)

func TestVerifiableShuffle(t *testing.T) {
	count := mAvailable * 16
	r1 := make([]crypto.Key, count)
	amount := make([]crypto.Key, count)
	inputs := make([]crypto.Key, count)
	r2 := make([]crypto.Key, count)
	outputs := make([]crypto.Key, count)
	individualProof := make([]IndividualProof, count)
	inputGas := make([]uint64, count)
	for i := range r1 {
		r1[i] = crypto.SkGen()
		amount[i] = *ringct.D2h(rand.Uint64())
		inputs[i] = GenCommitment(&amount[i], &r1[i])
		r2[i] = crypto.SkGen()
		var r1r2 crypto.Key
		crypto.ScAdd(&r1r2, &r1[i], &r2[i])
		outputs[i] = GenCommitment(&amount[i], &r1r2)
		inputGas[i] = shuffleUnitPrice * 10
		individualProof[i] = *GenIndividualProof(&amount[i], &r1r2, &outputs[i], inputGas[i])
	}
	proof, shuffledOutputs, outputsGas, shuffledIndividualProof := GenVerifiableShuffle(inputs, inputGas, r2, individualProof)
	if !VerVerifiableShuffle(inputs, shuffledOutputs, inputGas, outputsGas, proof, shuffledIndividualProof) {
		t.Fatalf("VerVerifiableShuffle failed")
	}
}

func BenchmarkVerifiableShuffle(b *testing.B) {
	count := mAvailable * 16
	r1 := make([]crypto.Key, count)
	amount := make([]crypto.Key, count)
	inputs := make([]crypto.Key, count)
	r2 := make([]crypto.Key, count)
	outputs := make([]crypto.Key, count)
	individualProof := make([]IndividualProof, count)
	inputGas := make([]uint64, count)
	for i := range r1 {
		r1[i] = crypto.SkGen()
		amount[i] = *ringct.D2h(rand.Uint64())
		inputs[i] = GenCommitment(&amount[i], &r1[i])
		r2[i] = crypto.SkGen()
		var r1r2 crypto.Key
		crypto.ScAdd(&r1r2, &r1[i], &r2[i])
		outputs[i] = GenCommitment(&amount[i], &r1r2)
		inputGas[i] = shuffleUnitPrice * 10
		individualProof[i] = *GenIndividualProof(&amount[i], &r1r2, &outputs[i], inputGas[i])
	}
	proof, shuffledOutputs, outputsGas, shuffledIndividualProof := GenVerifiableShuffle(inputs, inputGas, r2, individualProof)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if !VerVerifiableShuffle(inputs, shuffledOutputs, inputGas, outputsGas, proof, shuffledIndividualProof) {
			b.Fatalf("VerVerifiableShuffle failed")
		}
	}
}