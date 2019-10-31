// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ctcrypto"
	"github.com/ethereum/go-ethereum/ctcrypto/crypto"
)

var _ = (*txdataMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (t txdata) MarshalJSON() ([]byte, error) {
	type txdata struct {
		AccountNonce     hexutil.Uint64             `json:"nonce"    gencodec:"required"`
		Price            *hexutil.Big               `json:"gasPrice" gencodec:"required"`
		GasLimit         hexutil.Uint64             `json:"gas"      gencodec:"required"`
		Recipient        *common.Address            `json:"to"       rlp:"nil"`
		Amount           *hexutil.Big               `json:"value"    gencodec:"required"`
		CTAmount         crypto.Key                 `json:"ctValue"`
		CTGas            uint64                     `json:"ctGas"`
		AmountProof      ctcrypto.CommitmentProof   `json:"ctProof"`
		Payload          hexutil.Bytes              `json:"input"    gencodec:"required"`
		BulletProofs     []byte                     `json:"bulletproof"`
		Info             []byte                     `json:"info"`
		CTAmount2        crypto.Key                 `json:"input"`
		SharedKey        crypto.Key                 `json:"sharedKey"`
		Challenge        []crypto.Key               `json:"challenge"`
		ShuffleInputs    []crypto.Key               `json:"shuffleInputs"`
		ShuffleOutputs   []crypto.Key               `json:"shuffleOutputs"`
		OutputsGas       []uint64                   `json:"outputsGas"`
		ShuffleProof     []byte                     `json:"shuffleProof"`
		IndividualProofs []ctcrypto.IndividualProof `json:"individualProofs"`
		V                *hexutil.Big               `json:"v" gencodec:"required"`
		R                *hexutil.Big               `json:"r" gencodec:"required"`
		S                *hexutil.Big               `json:"s" gencodec:"required"`
		Hash             *common.Hash               `json:"hash" rlp:"-"`
	}
	var enc txdata
	enc.AccountNonce = hexutil.Uint64(t.AccountNonce)
	enc.Price = (*hexutil.Big)(t.Price)
	enc.GasLimit = hexutil.Uint64(t.GasLimit)
	enc.Recipient = t.Recipient
	enc.Amount = (*hexutil.Big)(t.Amount)
	enc.CTAmount = t.CTAmount
	enc.CTGas = t.CTGas
	enc.AmountProof = t.AmountProof
	enc.Payload = t.Payload
	enc.BulletProofs = t.BulletProofs
	enc.Info = t.Info
	enc.CTAmount2 = t.CTAmount2
	enc.SharedKey = t.SharedKey
	enc.Challenge = t.Challenge
	enc.ShuffleInputs = t.ShuffleInputs
	enc.ShuffleOutputs = t.ShuffleOutputs
	enc.OutputsGas = t.OutputsGas
	enc.ShuffleProof = t.ShuffleProof
	enc.IndividualProofs = t.IndividualProofs
	enc.V = (*hexutil.Big)(t.V)
	enc.R = (*hexutil.Big)(t.R)
	enc.S = (*hexutil.Big)(t.S)
	enc.Hash = t.Hash
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (t *txdata) UnmarshalJSON(input []byte) error {
	type txdata struct {
		AccountNonce     *hexutil.Uint64            `json:"nonce"    gencodec:"required"`
		Price            *hexutil.Big               `json:"gasPrice" gencodec:"required"`
		GasLimit         *hexutil.Uint64            `json:"gas"      gencodec:"required"`
		Recipient        *common.Address            `json:"to"       rlp:"nil"`
		Amount           *hexutil.Big               `json:"value"    gencodec:"required"`
		CTAmount         *crypto.Key                `json:"ctValue"`
		CTGas            *uint64                    `json:"ctGas"`
		AmountProof      *ctcrypto.CommitmentProof  `json:"ctProof"`
		Payload          *hexutil.Bytes             `json:"input"    gencodec:"required"`
		BulletProofs     []byte                     `json:"bulletproof"`
		Info             []byte                     `json:"info"`
		CTAmount2        *crypto.Key                `json:"input"`
		SharedKey        *crypto.Key                `json:"sharedKey"`
		Challenge        []crypto.Key               `json:"challenge"`
		ShuffleInputs    []crypto.Key               `json:"shuffleInputs"`
		ShuffleOutputs   []crypto.Key               `json:"shuffleOutputs"`
		OutputsGas       []uint64                   `json:"outputsGas"`
		ShuffleProof     []byte                     `json:"shuffleProof"`
		IndividualProofs []ctcrypto.IndividualProof `json:"individualProofs"`
		V                *hexutil.Big               `json:"v" gencodec:"required"`
		R                *hexutil.Big               `json:"r" gencodec:"required"`
		S                *hexutil.Big               `json:"s" gencodec:"required"`
		Hash             *common.Hash               `json:"hash" rlp:"-"`
	}
	var dec txdata
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.AccountNonce == nil {
		return errors.New("missing required field 'nonce' for txdata")
	}
	t.AccountNonce = uint64(*dec.AccountNonce)
	if dec.Price == nil {
		return errors.New("missing required field 'gasPrice' for txdata")
	}
	t.Price = (*big.Int)(dec.Price)
	if dec.GasLimit == nil {
		return errors.New("missing required field 'gas' for txdata")
	}
	t.GasLimit = uint64(*dec.GasLimit)
	if dec.Recipient != nil {
		t.Recipient = dec.Recipient
	}
	if dec.Amount == nil {
		return errors.New("missing required field 'value' for txdata")
	}
	t.Amount = (*big.Int)(dec.Amount)
	if dec.CTAmount != nil {
		t.CTAmount = *dec.CTAmount
	}
	if dec.CTGas != nil {
		t.CTGas = *dec.CTGas
	}
	if dec.AmountProof != nil {
		t.AmountProof = *dec.AmountProof
	}
	if dec.Payload == nil {
		return errors.New("missing required field 'input' for txdata")
	}
	t.Payload = *dec.Payload
	if dec.BulletProofs != nil {
		t.BulletProofs = dec.BulletProofs
	}
	if dec.Info != nil {
		t.Info = dec.Info
	}
	if dec.CTAmount2 != nil {
		t.CTAmount2 = *dec.CTAmount2
	}
	if dec.SharedKey != nil {
		t.SharedKey = *dec.SharedKey
	}
	if dec.Challenge != nil {
		t.Challenge = dec.Challenge
	}
	if dec.ShuffleInputs != nil {
		t.ShuffleInputs = dec.ShuffleInputs
	}
	if dec.ShuffleOutputs != nil {
		t.ShuffleOutputs = dec.ShuffleOutputs
	}
	if dec.OutputsGas != nil {
		t.OutputsGas = dec.OutputsGas
	}
	if dec.ShuffleProof != nil {
		t.ShuffleProof = dec.ShuffleProof
	}
	if dec.IndividualProofs != nil {
		t.IndividualProofs = dec.IndividualProofs
	}
	if dec.V == nil {
		return errors.New("missing required field 'v' for txdata")
	}
	t.V = (*big.Int)(dec.V)
	if dec.R == nil {
		return errors.New("missing required field 'r' for txdata")
	}
	t.R = (*big.Int)(dec.R)
	if dec.S == nil {
		return errors.New("missing required field 's' for txdata")
	}
	t.S = (*big.Int)(dec.S)
	if dec.Hash != nil {
		t.Hash = dec.Hash
	}
	return nil
}
