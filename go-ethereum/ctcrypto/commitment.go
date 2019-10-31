package ctcrypto

import (
	"bytes"
	. "github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

//go:generate gencodec -type CommitmentProof -out gen_commitmentProof_json.go

type CommitmentProof struct {
	C    Key    `json:"C"    gencodec:"required"`
	D    Key    `json:"D"    gencodec:"required"`
	D1   Key    `json:"D1"   gencodec:"required"`
	D2   Key    `json:"D2"   gencodec:"required"`
}

func GenChallengeClaimUTXO(x, r *Key) (c, D1, D2 Key) {
	w := SkGen()
	n := SkGen()
	var W Key
	AddKeys2_2(&W, &n, &w)
	c = *HashToScalar(W[:])
	ScMulAdd(&D1, &c, x, &w)
	ScMulAdd(&D2, &c, r, &n)
	return
}

func GenCommitment(amount, r *Key) (commitment Key) {
	AddKeys2_2(&commitment, r, amount)
	return
}

func GenCommitmentProof(amount, r1, r2 *Key) (proof CommitmentProof) {
	c,D,D1,D2 := genCommitmentProof(amount, r1, r2)
	proof.C = c
	proof.D = D
	proof.D1 = D1
	proof.D2 = D2
	return
}

func GenCommitmentProof2(r, amount1, amount2 *Key) (proof CommitmentProof) {
	c,D,D1,D2 := genCommitmentProof2(r, amount1, amount2)
	proof.C = c
	proof.D = D
	proof.D1 = D1
	proof.D2 = D2
	return
}

func (proof CommitmentProof) VerCommitmentProof(E, F *Key) bool {
	return verCommitmentProof(&proof.C, &proof.D, &proof.D1, &proof.D2, E, F)
}

func (proof CommitmentProof) VerCommitmentProof2(E, F *Key) bool {
	return verCommitmentProof2(&proof.C, &proof.D, &proof.D1, &proof.D2, E, F)
}

func genCommitmentProof(amount, r1, r2 *Key) (c,D,D1,D2 Key)  {
	w := SkGen()
	n1 := SkGen()
	n2 := SkGen()

	var W1,W2 Key
	AddKeys2_2(&W1, &n1, &w)
	AddKeys2_2(&W2, &n2, &w)

	c = *HashToScalar(W1[:], W2[:])

	ScMulAdd(&D, &c, amount, &w)
	ScMulAdd(&D1, &c, r1, &n1)
	ScMulAdd(&D2, &c, r2, &n2)
	return
}

func genCommitmentProof2(r, amount1, amount2 *Key) (c,D,D1,D2 Key)  {
	w := SkGen()
	n1 := SkGen()
	n2 := SkGen()

	var W1,W2 Key
	AddKeys2_2(&W1, &w, &n1)
	AddKeys2_2(&W2, &w, &n2)

	c = *HashToScalar(W1[:], W2[:])

	ScMulAdd(&D, &c, r, &w)
	ScMulAdd(&D1, &c, amount1, &n1)
	ScMulAdd(&D2, &c, amount2, &n2)
	return
}

func verCommitmentProof(c, D, D1, D2, E, F *Key) bool {
	var W1,W2 Key
	AddKeys2_2(&W1, D1, D)
	SubKeys(&W1, &W1, ScalarMultKey(E, c))
	AddKeys2_2(&W2, D2, D)
	SubKeys(&W2, &W2, ScalarMultKey(F, c))
	hash := *HashToScalar(W1[:], W2[:])
	return bytes.Equal(c[:], hash[:])
}

func verCommitmentProof2(c, D, D1, D2, E, F *Key) bool {
	var W1,W2 Key
	AddKeys2_2(&W1, D, D1)
	SubKeys(&W1, &W1, ScalarMultKey(E, c))
	AddKeys2_2(&W2, D, D2)
	SubKeys(&W2, &W2, ScalarMultKey(F, c))
	hash := *HashToScalar(W1[:], W2[:])
	return bytes.Equal(c[:], hash[:])
}