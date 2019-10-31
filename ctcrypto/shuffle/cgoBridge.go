package shuffle

/*
#include "GoApis.h"

#cgo LDFLAGS: -L./ -lshuffle -Wl,-rpath=./
*/
import "C"
import (
	"math/rand"
	"reflect"
	"unsafe"

	crypto2 "github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

func toSlice(cPtr, goPtr unsafe.Pointer, n int) {
	sh := (*reflect.SliceHeader)(goPtr)
	sh.Cap = n
	sh.Len = n
	sh.Data = uintptr(cPtr)
}

func eraseSlice(goPtr unsafe.Pointer) {
	sh := (*reflect.SliceHeader)(goPtr)
	sh.Cap = 0
	sh.Len = 0
	sh.Data = uintptr(0)
}

func Shuffle_gen(m, n int, inputs []crypto2.Key) (outputs []crypto2.Key, permutation []int, proof []byte) {
	if m*n != len(inputs) {
		return
	}
	_inputs := make([]byte, len(inputs)*crypto2.KeyLength)
	for i := range inputs {
		copy(_inputs[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength], inputs[i][:])
	}
	var _outputs, _proof *C.char
	var _permutation *C.int
	var _outputsLen, _permutationLen, _proofLen int32
	C.shuffle_gen((*C.char)(unsafe.Pointer(&_inputs[0])), (C.int)(m), (C.int)(n),
		(**C.char)(unsafe.Pointer(&_outputs)), (*C.int)(unsafe.Pointer(&_outputsLen)),
		(**C.int)(unsafe.Pointer(&_permutation)), (*C.int)(unsafe.Pointer(&_permutationLen)),
		(**C.char)(unsafe.Pointer(&_proof)), (*C.int)(unsafe.Pointer(&_proofLen)))
	if _outputs == nil || _proof == nil || _permutation == nil ||
		_outputsLen == 0 || _permutationLen == 0 || _proofLen == 0 {
		return
	}
	defer C.deleteCharArray(_outputs)
	defer C.deleteIntArray(_permutation)
	defer C.deleteCharArray(_proof)

	var outputsSlice []byte // can only be used in this function, once getting outside, its data will be freed.
	toSlice(unsafe.Pointer(_outputs), unsafe.Pointer(&outputsSlice), int(_outputsLen*crypto2.KeyLength))
	defer eraseSlice(unsafe.Pointer(&outputsSlice))
	outputs = make([]crypto2.Key, _outputsLen)
	for i := range outputs {
		copy(outputs[i][:], outputsSlice[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength])
	}

	var permutationSlice []int32
	toSlice(unsafe.Pointer(_permutation), unsafe.Pointer(&permutationSlice), int(_permutationLen))
	defer eraseSlice(unsafe.Pointer(&permutationSlice))
	permutation = make([]int, _permutationLen)
	for i := range permutation {
		permutation[i] = int(permutationSlice[i])
	}

	var proofSlice []byte
	toSlice(unsafe.Pointer(_proof), unsafe.Pointer(&proofSlice), int(_proofLen))
	defer eraseSlice(unsafe.Pointer(&proofSlice))
	proof = make([]byte, _proofLen)
	copy(proof, proofSlice[:])

	return
}

func Gen_permutation(count int) []int32 {
	permutation := make([]int32, count)
	for i := range permutation {
		permutation[i] = int32(i)
	}
	for i := range permutation {
		j := rand.Intn(count)
		temp := permutation[i]
		permutation[i] = permutation[j]
		permutation[j] = temp
	}
	return permutation
}

func Gen_R(count int) []crypto2.Key {
	R := make([]crypto2.Key, count)
	for i := range R {
		R[i] = crypto2.SkGen()
	}
	return R
}

func Shuffle_gen_with_regulation(m, n int, inputs []crypto2.Key,
	permutation []int32, R []crypto2.Key) (outputs []crypto2.Key, proof []byte) {
	if m*n != len(inputs) || m*n != len(permutation) || m*n != len(R) {
		return
	}
	_inputs := make([]byte, len(inputs)*crypto2.KeyLength)
	for i := range inputs {
		copy(_inputs[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength], inputs[i][:])
	}
	_R := make([]byte, len(R)*crypto2.KeyLength)
	for i := range R {
		copy(_R[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength], R[i][:])
	}
	var _outputs, _proof *C.char
	var _outputsLen, _proofLen int32
	C.shuffle_gen_with_regulation((*C.char)(unsafe.Pointer(&_inputs[0])), (C.int)(m), (C.int)(n),
		(**C.char)(unsafe.Pointer(&_outputs)), (*C.int)(unsafe.Pointer(&_outputsLen)),
		(**C.char)(unsafe.Pointer(&_proof)), (*C.int)(unsafe.Pointer(&_proofLen)),
		(*C.int)(unsafe.Pointer(&permutation[0])), (*C.char)(unsafe.Pointer(&_R[0])))
	if _outputs == nil || _proof == nil || _outputsLen == 0 || _proofLen == 0 {
		return
	}
	defer C.deleteCharArray(_outputs)
	defer C.deleteCharArray(_proof)

	var outputsSlice []byte // can only be used in this function, once getting outside, its data will be freed.
	toSlice(unsafe.Pointer(_outputs), unsafe.Pointer(&outputsSlice), int(_outputsLen*crypto2.KeyLength))
	defer eraseSlice(unsafe.Pointer(&outputsSlice))
	outputs = make([]crypto2.Key, _outputsLen)
	for i := range outputs {
		copy(outputs[i][:], outputsSlice[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength])
	}

	var proofSlice []byte
	toSlice(unsafe.Pointer(_proof), unsafe.Pointer(&proofSlice), int(_proofLen))
	defer eraseSlice(unsafe.Pointer(&proofSlice))
	proof = make([]byte, _proofLen)
	copy(proof, proofSlice[:])

	return
}

func Shuffle_ver(m, n int, inputs []crypto2.Key, outputs []crypto2.Key, proof []byte) bool {
	if m*n != len(inputs) {
		return false
	}
	_inputs := make([]byte, len(inputs)*crypto2.KeyLength)
	for i := range inputs {
		copy(_inputs[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength], inputs[i][:])
	}

	_outputs := make([]byte, len(outputs)*crypto2.KeyLength)
	for i := range outputs {
		copy(_outputs[i*crypto2.KeyLength:(i+1)*crypto2.KeyLength], outputs[i][:])
	}

	ret, _ := C.shuffle_ver((*C.char)(unsafe.Pointer(&_inputs[0])), (C.int)(m), (C.int)(n),
		(*C.char)(unsafe.Pointer(&_outputs[0])), (C.int)(len(outputs)),
		(*C.char)(unsafe.Pointer(&proof[0])), (C.int)(len(proof)))

	if ret != 1 {
		return false
	}
	return true
}
