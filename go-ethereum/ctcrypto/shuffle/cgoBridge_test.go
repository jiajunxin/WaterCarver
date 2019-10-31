package shuffle

import (
	"bytes"
	"testing"

	crypto2 "github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

func GenCommitment(amount, r *crypto2.Key) (commitment crypto2.Key) {
	crypto2.AddKeys2(&commitment, r, amount, &crypto2.H)
	return
}

func TestShuffle_ver(t *testing.T) {
	m := 64
	n := 64
	inputs := make([]crypto2.Key, m*n)
	for i := range inputs {
		inputs[i] = crypto2.SkGen()
		inputs[i] = GenCommitment(&inputs[i], &inputs[i])
	}
	outputs, _, proof := Shuffle_gen(m, n, inputs)
	for i := range outputs {
		if !outputs[i].Public_Key_Valid() {
			t.Fatalf("output invalid")
		}
	}
	if !Shuffle_ver(m, n, inputs, outputs, proof) {
		t.Fatalf("Shuffle_ver failed")
	}
}

func TestShuffle_with_regulation(t *testing.T) {
	m := 64
	n := 64
	inputs := make([]crypto2.Key, m*n)
	for i := range inputs {
		inputs[i] = crypto2.SkGen()
		inputs[i] = GenCommitment(&inputs[i], &inputs[i])
	}
	permutation := Gen_permutation(m * n)
	R := Gen_R(m * n)
	outputs, proof := Shuffle_gen_with_regulation(m, n, inputs, permutation, R)
	for i := range inputs {
		if !outputs[i].Public_Key_Valid() {
			t.Fatalf("output invalid")
		}
		var expectOutput crypto2.Key
		gr2 := crypto2.ScalarmultBase(R[permutation[i]])
		input := inputs[permutation[i]]
		crypto2.AddKeys(&expectOutput, &input, &gr2)
		if !bytes.Equal(expectOutput[:], outputs[i][:]) {
			t.Fatalf("output is wrong")
		}
	}
	if !Shuffle_ver(m, n, inputs, outputs, proof) {
		t.Fatalf("Shuffle_ver failed")
	}
}
