//
// Created by wyongcan on 2019/10/8.
//

package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto"
	crypto2 "github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto/ringct"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"time"
)

var alicePrivateKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
var alicePublicKey = common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7")
var bobPrivateKey, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
var bobPublicKey = common.HexToAddress("0x703c4b2bD70c169f5717101CaeE543299Fc946C7")

var BIGONE = big.NewInt(1)

var USE_BATCH_BULLETPROOFS_VER = true
var USE_BULLETPROOFS_WITHREGULATION = core.USE_BULLETPROOFS_WITHREGULATION

func printState(backend *backends.SimulatedBackend, ctx context.Context) {
	balance, _ := backend.BalanceAt(ctx, bobPublicKey, nil)
	fmt.Printf("bob balance: %s\n", balance.String())
	balance, _ = backend.BalanceAt(ctx, alicePublicKey, nil)
	fmt.Printf("alice balance: %s\n", balance.String())
	ctBalance, _ := backend.CTBalanceAt(ctx, alicePublicKey, nil)
	fmt.Printf("alice ctBalance: %s\n", ctBalance)
	ctBalance, _ = backend.CTBalanceAt(ctx, bobPublicKey, nil)
	fmt.Printf("bob ctBalance: %s\n", ctBalance)
	fmt.Printf("------------------------------------------------------\n")
}

func printUserState(backend *backends.SimulatedBackend, ctx context.Context, address common.Address) {
	//balance, _ := backend.BalanceAt(ctx, address, nil)
	//fmt.Printf("%s balance: %s", address.String(), balance.String())
	//ctBalance, _ := backend.CTBalanceAt(ctx, address, nil)
	//fmt.Printf(" ctBalance: %s\n", ctBalance)
}

type Receipt struct {
	Info      []byte
	Gr0       crypto2.Key
	CTValue   crypto2.Key
}

func GenerateAccount(count int) (privateKeys []*ecdsa.PrivateKey, publicKeys []common.Address,
		genesisAlloc core.GenesisAlloc) {
	privateKeys = make([]*ecdsa.PrivateKey, count)
	publicKeys = make([]common.Address, count)
	genesisAlloc = make(core.GenesisAlloc)
	for i := range privateKeys {
		privateKeys[i], _ = crypto.GenerateKey()
		publicKeys[i] = crypto.PubkeyToAddress(privateKeys[i].PublicKey)
		genesisAlloc[publicKeys[i]] = core.GenesisAccount{Balance:big.NewInt(100000000000000)}
	}
	return
}

func GenerateNormalTX(ctx context.Context, backend *backends.SimulatedBackend, privateKeys []*ecdsa.PrivateKey,
		publicKeys []common.Address, count int, value uint64) (txs types.Transactions) {
	txs = make(types.Transactions, count)
	userCount := len(publicKeys)
	amount := big.NewInt(0).SetUint64(value)
	for i := 0; i < count; i++ {
		nonce, _ := backend.NonceAt(ctx, publicKeys[i], nil)
		txs[i] = types.NewTransaction(nonce, publicKeys[(i + 1) % userCount], amount, 0x5208, BIGONE, []byte{})
		txs[i], _ = types.SignTx(txs[i], types.CTSigner{}, privateKeys[i])
	}
	return
}

func GenerateTXInit(ctx context.Context, backend *backends.SimulatedBackend, privateKeys []*ecdsa.PrivateKey,
		publicKeys []common.Address, count int, value uint64) (txs types.Transactions,
		balanceMasks map[common.Address]crypto2.Key) {
	txs = make(types.Transactions, count)
	balanceMasks = make(map[common.Address]crypto2.Key)
	amount := big.NewInt(0).SetUint64(value)
	valueKey := ringct.D2h(value)
	for i := 0; i < count; i++ {
		nonce, _ := backend.NonceAt(ctx, publicKeys[i], nil)
		mask := crypto2.SkGen()
		balanceMasks[publicKeys[i]] = mask
		commitment := ctcrypto.GenCommitment(valueKey, &mask)
		proof := ctcrypto.GenCommitmentProof(valueKey, &crypto2.Key{}, &mask)
		txs[i] = types.NewA2CTTransaction(nonce, amount, 0x5208, BIGONE, commitment, proof, []byte{})
		txs[i], _ = types.SignTx(txs[i], types.CTSigner{}, privateKeys[i])
	}
	return
}

func GenerateTXSend(ctx context.Context, backend *backends.SimulatedBackend, privateKeys []*ecdsa.PrivateKey,
		publicKeys []common.Address, count int, balance *uint64, value uint64,
		balanceMasks map[common.Address]crypto2.Key) (txs types.Transactions, valueMasks map[crypto2.Key]crypto2.Key) {
	txs = make(types.Transactions, count)
	valueMasks = make(map[crypto2.Key]crypto2.Key)
	*balance = *balance - value
	valueKey := *ringct.D2h(value)
	balanceKey := *ringct.D2h(*balance)
	for i := 0; i < count; i++ {
		nonce, _ := backend.NonceAt(ctx, publicKeys[i], nil)
		r1 := crypto2.SkGen()
		mask := balanceMasks[publicKeys[i]]
		crypto2.ScSub(&mask, &mask, &r1)
		balanceMasks[publicKeys[i]] = mask
		bulletproofs := BULLETPROOF_Prove([]crypto2.Key{valueKey, balanceKey}, []crypto2.Key{r1, mask})
		ctValue := bulletproofs.V[0]
		ctValue = *crypto2.ScalarMultKey(&ctValue, &crypto2.EIGHT)
		txs[i] = types.NewPureCTTransaction(nonce, 0x5208, BIGONE, ctValue, params.ShuffleGas * 10,
			[]byte{}, crypto2.Key{}, *bulletproofs, []byte{})
		txs[i], _ = types.SignTx(txs[i], types.CTSigner{}, privateKeys[i])
		valueMasks[ctValue] = r1
	}
	return
}

func txSendsToKeys(txSends types.Transactions) []crypto2.Key {
	result := make([]crypto2.Key, len(txSends))
	for i := range txSends {
		result[i] = txSends[i].CTValue()
	}
	return result
}

func GenerateTXRecv(ctx context.Context, backend *backends.SimulatedBackend, privateKeys []*ecdsa.PrivateKey,
		publicKeys []common.Address, balance *uint64, inputs []crypto2.Key, value uint64,
		valueMasks map[crypto2.Key]crypto2.Key, balanceMasks map[common.Address]crypto2.Key) (txs types.Transactions) {
	count := len(inputs)
	txs = make(types.Transactions, count)
	*balance = *balance + value
	for i := 0; i < count; i++ {
		nonce, _ := backend.NonceAt(ctx, publicKeys[i], nil)
		ctValue := inputs[len(inputs) - i - 1]
		ctMask := valueMasks[ctValue]
		c, D1, D2 := ctcrypto.GenChallengeClaimUTXO(ringct.D2h(value), &ctMask)
		txs[i] = types.NewClaimCTTransaction(nonce,0x5208, BIGONE, ctValue, c, D1, D2, []byte{})
		txs[i], _ = types.SignTx(txs[i], types.CTSigner{}, privateKeys[i])
		mask := balanceMasks[publicKeys[i]]
		crypto2.ScAdd(&mask, &mask, &ctMask)
		balanceMasks[publicKeys[i]] = mask
	}
	return
}

func GenerateTXShuffle(ctx context.Context, backend *backends.SimulatedBackend, privateKeys []*ecdsa.PrivateKey,
		publicKeys []common.Address, inputs []crypto2.Key, count int, ctGas *uint64, value uint64,
		valueMasks map[crypto2.Key]crypto2.Key) (txs types.Transactions, outputs []crypto2.Key,
													outputsValueMasks map[crypto2.Key]crypto2.Key) {
	if len(inputs) % count != 0 {
		panic("GenerateTXShuffle len(inputs) % count != 0")
	}
	singleShuffleCount := len(inputs) / count
	if !ctcrypto.CheckCount(singleShuffleCount) {
		panic("CheckCount(singleShuffleCount) failed")
	}
	valueKey := *ringct.D2h(value)
	txs = make(types.Transactions, count)
	outputs = make([]crypto2.Key, len(inputs))
	outputsValueMasks = make(map[crypto2.Key]crypto2.Key)
	for i := 0; i < count; i++ {
		inputs_seg := inputs[i * singleShuffleCount: i * singleShuffleCount + singleShuffleCount]
		r2 := make([]crypto2.Key, singleShuffleCount)
		inputGas := make([]uint64, singleShuffleCount)
		individualProof := make([]ctcrypto.IndividualProof, singleShuffleCount)
		for j := range r2 {
			var r1r2 crypto2.Key
			input := inputs_seg[j]
			r1 := valueMasks[input]
			r2[j] = crypto2.SkGen()
			crypto2.ScAdd(&r1r2, &r1, &r2[j])
			output := ctcrypto.GenCommitment(&valueKey, &r1r2)
			outputsValueMasks[output] = r1r2
			outputs[i * singleShuffleCount + j] = output
			individualProof[j] = *ctcrypto.GenIndividualProof(&valueKey, &r1r2, &output, *ctGas)
			inputGas[j] = *ctGas
		}
		proof, shuffledOutputs, outputsGas, shuffledIndividualProof :=
			ctcrypto.GenVerifiableShuffle(inputs_seg, inputGas, r2, individualProof)
		nonce, _ := backend.NonceAt(ctx, publicKeys[i], nil)
		txs[i] = types.NewShuffleCTTransaction(nonce, 0x5208, BIGONE, inputs_seg,
			shuffledOutputs, outputsGas, proof, shuffledIndividualProof, []byte{})
		txs[i], _ = types.SignTx(txs[i], types.CTSigner{}, privateKeys[i])
	}
	*ctGas = *ctGas - params.ShuffleGas
	return
}

func benchmarkNormalTX(count int, testCount int)  {
	println("start benchmarking Normal TX")
	privateKeys, publicKeys, genesisAlloc := GenerateAccount(count)
	backend := backends.NewSimulatedBackend(
		genesisAlloc,
		1000000000,
	)
	ctx := context.Background()
	defer backend.Close()

	printUserState(backend, ctx, publicKeys[0])
	printUserState(backend, ctx, publicKeys[1])

	totalTime := float64(0)
	for i := 0; i < testCount; i++ {
		txs := GenerateNormalTX(ctx, backend, privateKeys, publicKeys, count, 10000)
		t := time.Now()
		_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
		backend.Commit()
		_, _ = bind.WaitMined(ctx, backend, txs[len(txs) - 1])

		elapsed := time.Since(t)
		totalTime += elapsed.Seconds()
		fmt.Printf("normal tx tps:%0.1f\n", float64(count) / elapsed.Seconds())
		printUserState(backend, ctx, publicKeys[0])
		printUserState(backend, ctx, publicKeys[1])
	}
	fmt.Printf("normal tx average tps:%0.1f\n", float64(count * testCount) / totalTime)
}

func benchmarkCTTXSingle(count int, testCount int, shuffleCount int)  {
	println("start benchmarking CT TX Single")
	privateKeys, publicKeys, genesisAlloc := GenerateAccount(count)
	backend := backends.NewSimulatedBackend(
		genesisAlloc,
		1000000000,
	)
	ctx := context.Background()
	defer backend.Close()

	ctBalance := uint64(100000000)
	initTxs, balanceMasks := GenerateTXInit(ctx, backend, privateKeys, publicKeys, count, ctBalance)
	_ = backend.SendTransactions(ctx, initTxs, USE_BATCH_BULLETPROOFS_VER)
	backend.Commit()
	_, _ = bind.WaitMined(ctx, backend, initTxs[len(initTxs) - 1])

	printUserState(backend, ctx, publicKeys[0])
	printUserState(backend, ctx, publicKeys[1])

	txSendTotalTime := float64(0)
	txShuffleTotalTime := float64(0)
	txRecvTotalTime := float64(0)
	for i := 0; i < testCount; i++ {
		txs, valueMasks := GenerateTXSend(ctx, backend, privateKeys, publicKeys, count,
			&ctBalance, 10000, balanceMasks)
		//fmt.Println("generated txSends")
		t := time.Now()
		_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
		backend.Commit()
		receipt, _ := bind.WaitMined(ctx, backend, txs[len(txs) - 1])
		if receipt.Status != types.ReceiptStatusSuccessful {
			panic("block generator reject txSend!")
		}

		elapsed := time.Since(t)
		txSendTotalTime += elapsed.Seconds()
		fmt.Printf("ct txSend tps:%0.1f\n", float64(count) / elapsed.Seconds())
		printUserState(backend, ctx, publicKeys[0])
		printUserState(backend, ctx, publicKeys[1])

		ctGas := params.ShuffleGas * 10
		txs, outputs, valueMasks := GenerateTXShuffle(ctx, backend, privateKeys, publicKeys, txSendsToKeys(txs),
			shuffleCount, &ctGas, 10000, valueMasks)
		//fmt.Println("generated txShuffle")
		t = time.Now()
		_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
		backend.Commit()
		receipt, _ = bind.WaitMined(ctx, backend, txs[len(txs) - 1])
		if receipt.Status != types.ReceiptStatusSuccessful {
			panic("block generator reject txShuffle!")
		}

		elapsed = time.Since(t)
		txShuffleTotalTime += elapsed.Seconds()
		fmt.Printf("ct txShuffle m*n=%d tps:%0.1f\n", count / shuffleCount,
												float64(shuffleCount) / elapsed.Seconds())
		printUserState(backend, ctx, publicKeys[0])
		printUserState(backend, ctx, publicKeys[1])


		txs = GenerateTXRecv(ctx, backend, privateKeys, publicKeys, &ctBalance, outputs, 10000,
			valueMasks, balanceMasks)
		//fmt.Println("generated txRecvs")
		t = time.Now()
		_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
		backend.Commit()
		receipt, _ = bind.WaitMined(ctx, backend, txs[len(txs) - 1])
		if receipt.Status != types.ReceiptStatusSuccessful {
			panic("block generator reject txRecv!")
		}

		elapsed = time.Since(t)
		txRecvTotalTime += elapsed.Seconds()
		fmt.Printf("ct txRecv tps:%0.1f\n", float64(count) / elapsed.Seconds())
		printUserState(backend, ctx, publicKeys[0])
		printUserState(backend, ctx, publicKeys[1])
	}
	fmt.Printf("ct txSend average tps:%0.1f\n", float64(count * testCount) / txSendTotalTime)
	fmt.Printf("ct txShuffle m*n=%d average tps:%0.1f\n", count / shuffleCount,
									float64(shuffleCount * testCount) / txShuffleTotalTime)
	fmt.Printf("ct txRecv average tps:%0.1f\n", float64(count * testCount) / txRecvTotalTime)
}

func benchmarkCTTXMix(count int, testCount int)  {
	println("start benchmarking CT TX Mix")
	privateKeys, publicKeys, genesisAlloc := GenerateAccount(count)
	backend := backends.NewSimulatedBackend(
		genesisAlloc,
		1000000000,
	)
	ctx := context.Background()
	defer backend.Close()

	ctBalance := uint64(100000000)
	initTxs, balanceMasks := GenerateTXInit(ctx, backend, privateKeys, publicKeys, count, ctBalance)
	_ = backend.SendTransactions(ctx, initTxs, USE_BATCH_BULLETPROOFS_VER)
	backend.Commit()
	_, _ = bind.WaitMined(ctx, backend, initTxs[len(initTxs) - 1])

	ctBalanceA, ctBalanceB := ctBalance, ctBalance
	sendTxs, valueMasks := GenerateTXSend(ctx, backend, privateKeys, publicKeys, count / 2, &ctBalanceA,
		10000, balanceMasks)
	//fmt.Println("generated txSends")
	_ = backend.SendTransactions(ctx, sendTxs, USE_BATCH_BULLETPROOFS_VER)
	backend.Commit()
	_, _ = bind.WaitMined(ctx, backend, sendTxs[len(sendTxs) - 1])

	printUserState(backend, ctx, publicKeys[0])
	printUserState(backend, ctx, publicKeys[1])

	totalTime := float64(0)
	for i := 0; i < testCount; i++ {
		txs := GenerateTXRecv(ctx, backend, privateKeys[count / 2:count], publicKeys[count / 2:count],
			&ctBalanceB, txSendsToKeys(sendTxs), 10000, valueMasks, balanceMasks)
		//fmt.Println("generated txRecvs")
		sendTxs, valueMasks = GenerateTXSend(ctx, backend, privateKeys, publicKeys, count / 2,
			&ctBalanceA, 10000, balanceMasks)
		//fmt.Println("generated txSends")
		txs = append(txs, sendTxs...)

		t := time.Now()
		_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
		backend.Commit()
		_, _ = bind.WaitMined(ctx, backend, txs[len(txs) - 1])

		elapsed := time.Since(t)
		totalTime += elapsed.Seconds()
		fmt.Printf("ct txSend and txRecv tps:%0.1f\n", float64(count) / elapsed.Seconds())
		printUserState(backend, ctx, publicKeys[0])
		printUserState(backend, ctx, publicKeys[1])
	}
	fmt.Printf("ct txSend and txRecv average tps:%0.1f\n", float64(count * testCount) / totalTime)
}

func BULLETPROOF_Prove(sv []crypto2.Key, gamma []crypto2.Key) *ringct.BulletProof  {
	if USE_BULLETPROOFS_WITHREGULATION {
		sL2, sR2, rho, _ := ringct.GenRegulationParaForBulletproof2(uint32(len(sv)))
		return ringct.BULLETPROOF_Prove2_WithRegulation(sv, gamma, sL2, sR2, *rho)
	} else {
		return ringct.BULLETPROOF_Prove2(sv, gamma)
	}
}

func testCTTransaction()  {
	backend := backends.NewSimulatedBackend(
		core.GenesisAlloc{
			alicePublicKey: {Balance: big.NewInt(500000000000000)},
			bobPublicKey: {Balance: big.NewInt(100000000000000)},
		},
		10000000,
	)
	ctx := context.Background()
	defer backend.Close()

	mined := make(chan struct{})
	var err error
	var receipt *types.Receipt
	var tx *types.Transaction
	var txs []*types.Transaction

	printState(backend, ctx)

	// Alice init CT Account
	rA0 := crypto2.SkGen()
	aliceCTBalance := uint64(100000)
	tx = types.NewA2CTTransaction(0, big.NewInt(0).SetUint64(aliceCTBalance), 0x5208, BIGONE,
		ctcrypto.GenCommitment(ringct.D2h(aliceCTBalance), &rA0),
		ctcrypto.GenCommitmentProof(ringct.D2h(aliceCTBalance), &crypto2.Key{}, &rA0), []byte{})
	tx, _ = types.SignTx(tx, types.CTSigner{}, alicePrivateKey)
	go func() {
		receipt, err = bind.WaitMined(ctx, backend, tx)
		mined <- struct{}{}
	}()
	_ = backend.SendTransaction(ctx, tx)
	backend.Commit()

	<-mined
	printState(backend, ctx)

	xB := crypto2.SkGen() // Bob's secret key
	pkB := *crypto2.ScalarMultH(&xB) // Bob's pk

	// CT Transaction 1
	x1 := uint64(400)
	r0 := crypto2.SkGen()
	r1 := crypto2.SkGen()
	var rA0r1 crypto2.Key
	crypto2.ScSub(&rA0r1, &rA0, &r1)
	aliceCTBalance = aliceCTBalance - x1
	bulletproofs := BULLETPROOF_Prove([]crypto2.Key{*ringct.D2h(x1), *ringct.D2h(aliceCTBalance)},
		[]crypto2.Key{r1, rA0r1})
	pkB1r0 := *crypto2.ScalarMultKey(&pkB, &r0)
	gr0 := *crypto2.ScalarMultH(&r0)
	// do aes...
	cipher, err := aes.NewCipher(pkB1r0[:])
	if err != nil {
		panic(err)
	}
	_x1 := *ringct.D2h(x1)
	_src := bytes.Join([][]byte{_x1[:] ,r1[:]}, []byte{})
	info := make([]byte, len(_src))
	if len(_src) % cipher.BlockSize() != 0 {
		panic("invalid length")
	}
	_index := 0
	for _index < len(_src) {
		cipher.Encrypt(info[_index:_index + cipher.BlockSize()], _src[_index: _index + cipher.BlockSize()])
		_index += cipher.BlockSize()
	}
	tx = types.NewPureCTTransaction(1, 0x5208, BIGONE, bulletproofs.V[0], 100000, info, gr0,
		*bulletproofs, []byte{})
	tx, _ = types.SignTx(tx, types.CTSigner{}, alicePrivateKey)
	receipt1 := Receipt{Info:info, Gr0:gr0, CTValue:bulletproofs.V[0]}
	go func() {
		receipt, err = bind.WaitMined(ctx, backend, tx)
		mined <- struct{}{}
	}()
	_ = backend.SendTransaction(ctx, tx)
	backend.Commit()

	<-mined
	printState(backend, ctx)

	// CT Transaction 2
	x1 = uint64(600)
	r0 = crypto2.SkGen()
	r1 = crypto2.SkGen()
	crypto2.ScSub(&rA0r1, &rA0r1, &r1)
	aliceCTBalance = aliceCTBalance - x1
	bulletproofs = BULLETPROOF_Prove([]crypto2.Key{*ringct.D2h(x1), *ringct.D2h(aliceCTBalance)},
		[]crypto2.Key{r1, rA0r1})
	pkB1r0 = *crypto2.ScalarMultKey(&pkB, &r0)
	gr0 = *crypto2.ScalarMultH(&r0)
	// do aes...
	cipher, err = aes.NewCipher(pkB1r0[:])
	if err != nil {
		panic(err)
	}
	_x1 = *ringct.D2h(x1)
	_src = bytes.Join([][]byte{_x1[:] ,r1[:]}, []byte{})
	info = make([]byte, len(_src))
	if len(_src) % cipher.BlockSize() != 0 {
		panic("invalid length")
	}
	_index = 0
	for _index < len(_src) {
		cipher.Encrypt(info[_index:_index + cipher.BlockSize()], _src[_index: _index + cipher.BlockSize()])
		_index += cipher.BlockSize()
	}
	tx = types.NewPureCTTransaction(2, 0x5208, BIGONE, bulletproofs.V[0], 100000, info, gr0,
		*bulletproofs, []byte{})
	tx, _ = types.SignTx(tx, types.CTSigner{}, alicePrivateKey)
	receipt2 := Receipt{Info:info, Gr0:gr0, CTValue:bulletproofs.V[0]}
	txs = append(txs, tx)
	//go func() {
	//	receipt, err = bind.WaitMined(ctx, backend, tx)
	//	mined <- struct{}{}
	//}()
	//_ = backend.SendTransaction(ctx, tx)
	//backend.Commit()
	//
	//<-mined
	//printState(backend, ctx)

	// SSP do shuffle

	// after shuffling
	// Bob claims utxo1
	ctReceipt := receipt1
	_decryptedInfo := make([]byte, len(ctReceipt.Info))
	pkB1r0 = *crypto2.ScalarMultKey(&ctReceipt.Gr0, &xB)
	// do aes...
	cipher, err = aes.NewCipher(pkB1r0[:])
	if err != nil {
		panic(err)
	}
	if len(ctReceipt.Info) % cipher.BlockSize() != 0 {
		panic("invalid length")
	}
	_index = 0
	for _index < len(ctReceipt.Info) {
		cipher.Decrypt(_decryptedInfo[_index:_index + cipher.BlockSize()],
			ctReceipt.Info[_index: _index + cipher.BlockSize()])
		_index += cipher.BlockSize()
	}
	var x, r crypto2.Key
	copy(x[:], _decryptedInfo[0:32])
	copy(r[:], _decryptedInfo[32:64])
	c, D1, D2 := ctcrypto.GenChallengeClaimUTXO(&x, &r)
	tx = types.NewClaimCTTransaction(0,0x5208, BIGONE, ctReceipt.CTValue, c, D1, D2, []byte{})
	tx, _ = types.SignTx(tx, types.CTSigner{}, bobPrivateKey)
	go func() {
		receipt, err = bind.WaitMined(ctx, backend, tx)
		mined <- struct{}{}
	}()
	txs = append(txs, tx)
	_ = backend.SendTransactions(ctx, txs, USE_BATCH_BULLETPROOFS_VER)
	backend.Commit()

	<-mined
	printState(backend, ctx)

	// Bob claims utxo2
	ctReceipt = receipt2
	_decryptedInfo = make([]byte, len(ctReceipt.Info))
	pkB1r0 = *crypto2.ScalarMultKey(&ctReceipt.Gr0, &xB)
	// do aes...
	cipher, err = aes.NewCipher(pkB1r0[:])
	if err != nil {
		panic(err)
	}
	if len(ctReceipt.Info) % cipher.BlockSize() != 0 {
		panic("invalid length")
	}
	_index = 0
	for _index < len(ctReceipt.Info) {
		cipher.Decrypt(_decryptedInfo[_index:_index + cipher.BlockSize()],
			ctReceipt.Info[_index: _index + cipher.BlockSize()])
		_index += cipher.BlockSize()
	}
	copy(x[:], _decryptedInfo[0:32])
	copy(r[:], _decryptedInfo[32:64])
	c, D1, D2 = ctcrypto.GenChallengeClaimUTXO(&x, &r)
	tx = types.NewClaimCTTransaction(1,0x5208, BIGONE, ctReceipt.CTValue, c, D1, D2, []byte{})
	tx, _ = types.SignTx(tx, types.CTSigner{}, bobPrivateKey)
	go func() {
		receipt, err = bind.WaitMined(ctx, backend, tx)
		mined <- struct{}{}
	}()
	_ = backend.SendTransaction(ctx, tx)
	backend.Commit()

	<-mined
	printState(backend, ctx)
}

var ctTransaction = flag.Bool("ct", false, "benchmark ct transaction. (default false)")
var useBatchBulletproofs = flag.Bool("batchBulletproof", false, "use batch bulletproof to optimize txSend. (default false)")
var useRegulation = flag.Bool("regulation", false, "use bulletproof with regulation. (default false)")
var transactionsCount = flag.Int("count", 16 * 16, "transactions count.")
var repeatTestCount = flag.Int("testCount", 4, "repeat test count.")
var txShuffleCount = flag.Int("shuffleCount", 1, "txShuffle count.")


func main()  {
	flag.Usage()
	flag.Parse()

	core.USE_BULLETPROOFS_WITHREGULATION = *useRegulation
	USE_BULLETPROOFS_WITHREGULATION = *useRegulation

	USE_BATCH_BULLETPROOFS_VER = *useBatchBulletproofs

	count := *transactionsCount
	testCount := *repeatTestCount
	shuffleCount := *txShuffleCount

	if *ctTransaction {
		benchmarkCTTXSingle(count, testCount, shuffleCount)
	} else {
		benchmarkNormalTX(count, testCount)
	}
}