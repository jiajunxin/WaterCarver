// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"errors"
	math2 "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ctcrypto"
	crypto2 "github.com/ethereum/go-ethereum/ctcrypto/crypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto/ringct"
	"math"
	"math/big"
	"runtime"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

var USE_BULLETPROOFS_WITHREGULATION = false

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int
	CTValue() crypto2.Key
	CTGas() uint64
	Bulletproof() ringct.BulletProof
    Challenge() []crypto2.Key
    ShuffleInputs() []crypto2.Key
    ShuffleOutputs() []crypto2.Key
    OutputsGas() []uint64
    ShuffleProof() []byte
	IndividualProofs() []ctcrypto.IndividualProof

	Nonce() uint64
	CheckNonce() bool
	TransactionType() types.TransactionType

	Data() []byte
}

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, isEIP155 bool, isEIP2028 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && isEIP155 {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * nonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas() + st.msg.CTGas()), st.gasPrice)
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	st.state.SubBalance(st.msg.From(), mgval)
	return nil
}

func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

var bulletproofsResultCache map[crypto2.Key]bool // key is the commitment

func BULLETPROOF_Verify(proofs []ringct.BulletProof) bool  {
	if USE_BULLETPROOFS_WITHREGULATION {
		return ringct.BULLETPROOF_Verify2_Optimized_WithRegulation(proofs)
	} else {
		return ringct.BULLETPROOF_Verify2_Optimized(proofs)
	}
}

func InitBulletproofsResultCache(proofs []ringct.BulletProof) {
	if len(proofs) == 0 {
		return
	}
	bulletproofsResultCache = make(map[crypto2.Key]bool, len(proofs) * 2)
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
		seg := proofs[down:up]
		wg.Add(1)
		go func(proofs_seg []ringct.BulletProof) {
			defer wg.Done()
			if !BULLETPROOF_Verify(proofs_seg) {
				result = false
			}
		}(seg)
	}
	wg.Wait()
	if result {
		for i := range proofs {
			for k := range proofs[i].V {
				bulletproofsResultCache[proofs[i].V[k]] = true
			}
		}
	}
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the used gas. It returns an error if failed.
// An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := vm.AccountRef(msg.From())
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	istanbul := st.evm.ChainConfig().IsIstanbul(st.evm.BlockNumber)
	contractCreation := msg.To() == nil && msg.TransactionType() == types.TRANSACTION_ETH

	// Pay intrinsic gas
	gas, err := IntrinsicGas(st.data, contractCreation, homestead, istanbul)
	if err != nil {
		return nil, 0, false, err
	}
	if err = st.useGas(gas); err != nil {
		return nil, 0, false, err
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)
	if contractCreation {
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ctValue := msg.CTValue()
		snapshot := evm.StateDB.Snapshot()
		switchOut:
		switch msg.TransactionType() {
		case types.TRANSACTION_ETH:
			ret, st.gas, vmerr = evm.Call(sender, st.to(), st.data, st.gas, st.value)
		case types.TRANSACTION_CT_A2CT:
			if st.state.GetBalance(msg.From()).Cmp(st.value) < 0 {
				vmerr = vm.ErrInsufficientBalance
				break switchOut
			} else {
				currentCTBalance := st.state.GetCTBalance(msg.From())
				st.state.SubBalance(msg.From(), st.value)
				if bytes.Equal(currentCTBalance[:], crypto2.Zero[:]) {
					st.state.SetCTBalance(msg.From(), ctValue)
				} else {
					var afterCTBalance crypto2.Key
					crypto2.AddKeys(&afterCTBalance, &currentCTBalance, &ctValue)
					st.state.SetCTBalance(msg.From(), afterCTBalance)
				}
			}
		case types.TRANSACTION_CT_SEND:
			ctAddress := common.BytesToAddress(ctValue[:])
			if st.state.Exist(ctAddress) {
				vmerr = vm.ErrCTValueExist
				break switchOut
			} else {
				currentCTBalance := st.state.GetCTBalance(msg.From())
				var afterCTBalance crypto2.Key
				crypto2.SubKeys(&afterCTBalance, &currentCTBalance, &ctValue)
				bulletproof := msg.Bulletproof()
				bulletproof.V[1] = *crypto2.ScalarMultKey(&afterCTBalance, &crypto2.INV_EIGHT)
				if !(bulletproofsResultCache[bulletproof.V[0]] && bulletproofsResultCache[bulletproof.V[1]]) &&
						!BULLETPROOF_Verify([]ringct.BulletProof{bulletproof}) {
					vmerr = types.ErrInvalidCTProof
					break switchOut
				} else {
					st.state.SetCTBalance(msg.From(), afterCTBalance)
					// add utxo to pool
					st.state.AddBalance(ctAddress, big.NewInt(0).SetUint64(msg.CTGas()))
					st.state.SetCTBalance(ctAddress, ctValue)
				}
			}
		case types.TRANSACTION_CT_RECV:
			challenge := msg.Challenge()
			if len(challenge) != 3 {
				vmerr = vm.ErrCTInvalidChallenge
				break switchOut
			} else {
				ctAddress := common.BytesToAddress(ctValue[:])
				if !st.state.Exist(ctAddress) {
					vmerr = vm.ErrCTInvalidChallenge
					break switchOut
				} else {
					ctBalance := st.state.GetCTBalance(ctAddress)
					if !bytes.Equal(ctBalance[:], ctValue[:]) {
						vmerr = vm.ErrCTInvalidChallenge
						break switchOut
					}
					c, D1, D2 := challenge[0], challenge[1], challenge[2]
					var result crypto2.Key
					crypto2.AddKeys2(&result, &D2, &D1, &crypto2.H)
					crypto2.SubKeys(&result, &result, crypto2.ScalarMultKey(&ctValue, &c))
					result = *crypto2.HashToScalar(result[:])
					if !bytes.Equal(c[:], result[:]) {
						vmerr = vm.ErrCTInvalidChallenge
						break switchOut
					} else {
						st.state.Suicide(ctAddress)
						currentCTBalance := st.state.GetCTBalance(msg.From())
						if bytes.Equal(currentCTBalance[:], crypto2.Zero[:]) {
							st.state.SetCTBalance(msg.From(), ctValue)
						} else {
							var afterCTBalance crypto2.Key
							crypto2.AddKeys(&afterCTBalance, &currentCTBalance, &ctValue)
							st.state.SetCTBalance(msg.From(), afterCTBalance)
						}
					}
				}
			}
		case types.TRANSACTION_CT_SHUFFLE:
			inputsGas := make([]uint64, len(msg.ShuffleInputs()))
			for i, input := range msg.ShuffleInputs() {
				inputAddress := common.BytesToAddress(input[:])
				ctGas := st.state.GetBalance(inputAddress).Uint64()
				if ctGas >= params.ShuffleGas {
					inputsGas[i] = ctGas
					st.state.Suicide(inputAddress)
				} else {
					vmerr = vm.ErrShuffleInsufficientGas
					break switchOut
				}
				ctValue := st.state.GetCTBalance(inputAddress)
				if !bytes.Equal(ctValue[:], input[:]) {
					vmerr = vm.ErrShuffleInvalidProof
					break switchOut
				}
			}
			if !ctcrypto.VerVerifiableShuffle(msg.ShuffleInputs(), msg.ShuffleOutputs(),
					inputsGas, msg.OutputsGas(), msg.ShuffleProof(), msg.IndividualProofs()) {
				vmerr = vm.ErrShuffleInvalidProof
				break switchOut
			}
			outputsGas := msg.OutputsGas()
			for i, output := range msg.ShuffleOutputs() {
				outputAddress := common.BytesToAddress(output[:])
				if st.state.Exist(outputAddress) {
					vmerr = vm.ErrCTValueExist
					break switchOut
				}
				st.state.AddBalance(outputAddress, big.NewInt(0).SetUint64(outputsGas[i]))
				st.state.SetCTBalance(outputAddress, output)
			}
			sspReward, overflow := math2.SafeMul(uint64(len(msg.ShuffleInputs())), params.ShuffleGas)
			if overflow {
				vmerr = types.ErrInvalidShuffleArgs
				break switchOut
			}
			st.state.AddBalance(msg.From(), big.NewInt(0).SetUint64(sspReward))
		}
		if vmerr != nil {
			st.state.RevertToSnapshot(snapshot)
		}
	}
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}
	st.refundGas()
	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	return ret, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
