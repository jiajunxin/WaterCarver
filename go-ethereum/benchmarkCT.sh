#!/bin/bash

echo "start building"
go build github.com/ethereum/go-ethereum/cmd/cttransaction
echo "start testing normal transaction"
#test normal transaction
./cttransaction -count 5000
echo "start testing ct transaction"
#test ct transaction
./cttransaction -ct
echo "start testing ct transaction with batch bulletproof"
#test ct transaction with batch bulletproof
./cttransaction -ct -batchBulletproof
echo "start testing ct transaction with batch bulletproof and regulation"
#test ct transaction with batch bulletproof and regulation
./cttransaction -ct -batchBulletproof -regulation
echo "start benchmarking"
#run benchmark
go test github.com/ethereum/go-ethereum/ctcrypto/benchmark -bench=.