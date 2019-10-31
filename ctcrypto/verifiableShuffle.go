package ctcrypto

import (
	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto/ringct"
	"github.com/ethereum/go-ethereum/ctcrypto/shuffle"
	"github.com/ethereum/go-ethereum/params"
	"runtime"
	"sync"
)

const shuffleUnitPrice = params.ShuffleGas

const (
	mAvailable = 16
)

//go:generate gencodec -type IndividualProof -out gen_individualProof_json.go

type IndividualProof struct {
	CHash  crypto.Key          `json:"cHash"     gencodec:"required"`
	Proof1 CommitmentProof     `json:"proof1"    gencodec:"required"`
	Proof2 CommitmentProof     `json:"proof2"    gencodec:"required"`
}

func GetM() int {
	return mAvailable
}

func CheckCount(count int) bool {
	return count % mAvailable == 0 && count / mAvailable >= mAvailable
}

func getMN(len int) (m, n int) {
	remainder := len % mAvailable
	if remainder == 0 {
		return mAvailable, len / mAvailable
	}
	return 0, 0
}

func checkGas(gas []uint64) bool {
	for i := range gas {
		if gas[i] < shuffleUnitPrice {
			return false
		}
	}
	return true
}

func updateGas(gas []uint64) []uint64 {
	outputGas := make([]uint64, len(gas))
	for i := range gas {
		outputGas[i] = gas[i] - shuffleUnitPrice
	}
	return outputGas
}

//the tx should be shuffled tx
func GenIndividualProof(amount, r1r2, output *crypto.Key, gas uint64) (proof *IndividualProof) {
	if gas < shuffleUnitPrice {
		return nil
	}
	updatedGas := gas - shuffleUnitPrice
	x_hash1 := *crypto.HashToScalar2(*output, *ringct.D2h(updatedGas))
	CHash := GenCommitment(&x_hash1, r1r2)
	//tx should equal to GenCommitment(amount, r1r2)
	proof1 := GenCommitmentProof(&x_hash1, r1r2, &crypto.Zero)
	proof2 := GenCommitmentProof2(r1r2, &x_hash1, amount)
	ret := IndividualProof{CHash, proof1, proof2}
	return &ret
}

func CheckIndividualProof(output *crypto.Key, gas uint64, proof *IndividualProof) bool {
	x_hash1 := *crypto.HashToScalar2(*output, *ringct.D2h(gas))
	G_x_hash1 := GenCommitment(&x_hash1, &crypto.Zero)
	if !proof.Proof1.VerCommitmentProof(&proof.CHash, &G_x_hash1) {
		return false
	}
	if !proof.Proof2.VerCommitmentProof2(&proof.CHash, output) {
		return false
	}
	return true
}

func GenVerifiableShuffle(inputs []crypto.Key, inputsGas []uint64, inputR []crypto.Key, individualProof []IndividualProof) (
		proof []byte, outputs []crypto.Key, outputsGas []uint64, individualProofRet []IndividualProof) {
	if len(inputs) != len(inputsGas) || len(individualProof) != len(inputsGas) {
		return
	}
	if !checkGas(inputsGas) {
		return
	}
	m, n := getMN(len(inputs))
	if n == 0 {
		return
	}
	permutation := shuffle.Gen_permutation(len(inputs))
	output, proof := shuffle.Shuffle_gen_with_regulation(m, n, inputs, permutation, inputR)

	//update gas
	gas := updateGas(inputsGas)
	//permute gas and individual proof as the permutation
	outputsGas = make([]uint64, len(gas))
	individualProofRet = make([]IndividualProof, len(individualProof))
	for i := range outputsGas {
		outputsGas[i] = gas[permutation[i]]
		individualProofRet[i] = individualProof[permutation[i]]
	}

	return proof, output, outputsGas, individualProofRet
}

func VerVerifiableShuffle(inputs []crypto.Key, outputs []crypto.Key, inputsGas []uint64,
	 outputsGas []uint64, proof []byte, individualProof []IndividualProof ) bool {
	//check len	 
	if len(inputs) != len(inputsGas) || len(inputs) != len(outputs) ||
	len(inputs) != len(outputsGas) || len(inputs) != len(individualProof){
		return false
	}
	//check gas generally
	var inputsGasSum, outputsGasSum uint64
	for i := range inputsGas {
		inputsGasSum += inputsGas[i]
		outputsGasSum += outputsGas[i]
	}
	if inputsGasSum != (outputsGasSum + shuffleUnitPrice * uint64(len(inputsGas))) {
		return false
	}
	//check shuffle proof
	result := make(chan bool)
	go func() {
		m, n := getMN(len(inputs))
		result <- shuffle.Shuffle_ver(m, n, inputs, outputs, proof)
	}()
	//check individual proof
	if CheckIndividualProofs(outputs, outputsGas, individualProof) {
		return <-result
	}
	<-result
	return false
}

func CheckIndividualProofs(outputs []crypto.Key, outputsGas []uint64, proofs []IndividualProof) bool {
	if len(proofs) != len(outputs) || len(proofs) != len(outputsGas) {
		return false
	}
	if len(proofs) == 0 {
		return false
	}
	result := true
	goNum := runtime.NumCPU()
	seg_len := len(proofs) / goNum
	if len(proofs) % goNum > 0 {
		seg_len = seg_len + 1
	}
	var wg sync.WaitGroup
	for i := 0; i < goNum; i ++ {
		down := i * seg_len
		up := i * seg_len + seg_len
		if up > len(proofs) {
			up = len(proofs)
		}
		if up <= down {
			break
		}
		wg.Add(1)
		go func(outputs_seg []crypto.Key, outputGas_seg []uint64, proofs_seg []IndividualProof) {
			defer wg.Done()
			for j := range outputs_seg {
				if !CheckIndividualProof(&outputs_seg[j], outputGas_seg[j], &proofs_seg[j]) {
					result = false
					return
				}
			}
		}(outputs[down:up], outputsGas[down:up], proofs[down:up])
	}
	wg.Wait()
	return result
}