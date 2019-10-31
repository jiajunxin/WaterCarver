package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const maxN = 64
const maxM = 16

func get_exponent(base Key, idx uint64) Key {

	salt := "bulletproof"
	var idx_buf [9]byte

	idx_buf_size := binary.PutUvarint(idx_buf[:], idx)

	hash_buf := append(base[:], []byte(salt)...)
	hash_buf = append(hash_buf, idx_buf[:idx_buf_size]...)

	output_hash_good := Key(Keccak256(hash_buf[:]))

	return Key(output_hash_good.HashToPoint())

}

func init() {
	data := make([]MultiexpData, 2 * maxN * maxM)
	var Hi [maxN* maxM]Key
	var Gi [maxN* maxM]Key
	var Hi_p3 [maxN* maxM]ExtendedGroupElement
	var Gi_p3 [maxN* maxM]ExtendedGroupElement
	for i := uint64(0); i < maxN*maxM; i++ {
		Hi[i] = get_exponent(H, i*2)
		Hi_p3[i].FromBytes(&Hi[i])

		Gi[i] = get_exponent(H, i*2+1)
		Gi_p3[i].FromBytes(&Gi[i])

		data[i * 2].Scalar = Zero
		data[i * 2].Point = Gi_p3[i]
		data[i * 2 + 1].Scalar = Zero
		data[i * 2 + 1].Point = Hi_p3[i]
	}
	InitCache(data)
}

func Test_Multiexp(t *testing.T)  {
	{
		var testData []MultiexpData

		var MINUS_INV_EIGHT = HexToKey("74a4197af07d0bf705c2da252b5c0b0d0000000000000000000000000000000a")
		var MINUS_ONE = HexToKey("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
		var N1 ExtendedGroupElement
		N1.FromBytes(&MINUS_ONE)
		var result Key
		var B_Precomputed [8]CachedGroupElement
		GePrecompute(&B_Precomputed, &N1)
		AddKeys3(&result, &MINUS_INV_EIGHT, &MINUS_ONE, &MINUS_ONE, &B_Precomputed)

		testData = append(testData, MultiexpData{Point: N1, Scalar:MINUS_INV_EIGHT})
		testData = append(testData, MultiexpData{Point: N1, Scalar:MINUS_ONE})
		result2, err := Multiexp(&testData, 0)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(result[:], result2[:]) != 0 {
			t.Fatalf("result != result2. result:%s result2:%s", result, result2)
		}
		term := result

		for i := 0; i < 50; i++ {
			testData = append(testData, MultiexpData{Point: N1, Scalar:MINUS_INV_EIGHT})
			testData = append(testData, MultiexpData{Point: N1, Scalar:MINUS_ONE})
			result2, err = Multiexp(&testData, 0)
			if err != nil {
				t.Fatal(err)
			}
			AddKeys(&result, &result, &term)
			if bytes.Compare(result[:], result2[:]) != 0 {
				t.Fatalf("result != result2. i:%d result:%s result2:%s", i, result, result2)
			}
		}
	}
}