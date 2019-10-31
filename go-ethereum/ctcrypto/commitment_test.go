package ctcrypto

import (
	"bytes"
	. "github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"testing"
)


func TestGenCommitment(t *testing.T) {
	r := HexToKey("40c456ae1d9d8ed50950ffc635eb03c4aafb2c44c54d497d2e61843286fb5f04")
	amount := HexToKey("66e7457047eba6843a532fb1a30af4440b23e50140c8ff00b151210095bf1002")
	commitment := GenCommitment(&amount, &r)
	expect := HexToKey("db19abb6dba4d946a8d7408997c4bca53be69f5a6b87dd17a6a8cd8c46ff2697")
	if !bytes.Equal(commitment[:], expect[:]) {
		t.Fatalf("GenCommitment failed. expect:%s got:%s", expect, commitment)
	}
}

func TestVerCommitmentProof(t *testing.T) {
	amount := SkGen()
	r1 := SkGen()
	r2 := SkGen()
	E := GenCommitment(&amount, &r1)
	F := GenCommitment(&amount, &r2)
	c, D, D1, D2 := genCommitmentProof(&amount, &r1, &r2)
	if !verCommitmentProof(&c, &D, &D1, &D2, &E, &F) {
		t.Fatalf("verCommitmentProof failed")
	}
}

func TestVerCommitmentProof2(t *testing.T) {
	r := SkGen()
	amount1 := SkGen()
	amount2 := SkGen()
	E := GenCommitment(&amount1, &r)
	F := GenCommitment(&amount2, &r)
	c, D, D1, D2 := genCommitmentProof2(&r, &amount1, &amount2)
	if !verCommitmentProof2(&c, &D, &D1, &D2, &E, &F) {
		t.Fatalf("verCommitmentProof failed")
	}
}