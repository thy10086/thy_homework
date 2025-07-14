#!/bin/bash
set -e

echo "🧱 编译电路..."
circom circuits/poseidon2_hash.circom --r1cs --wasm --sym -o build/ -l node_modules


echo "📥 安装输入..."
node input/gen_input.js

echo "🔑 Powers of Tau 生成..."
snarkjs powersoftau new bn128 12 powersoftau/pot12_0000.ptau -v
snarkjs powersoftau contribute powersoftau/pot12_0000.ptau powersoftau/pot12_final.ptau --name="First" -v

echo "🧩 zkey..."
snarkjs groth16 setup build/poseidon2_hash.r1cs powersoftau/pot12_final.ptau build/circuit.zkey
snarkjs zkey export verificationkey build/circuit.zkey build/verification_key.json

echo "📦 witness..."
node build/poseidon2_hash_js/generate_witness.js build/poseidon2_hash.wasm input/input.json witness.wtns

echo "🪄 prove..."
snarkjs groth16 prove build/circuit.zkey witness.wtns proof/proof.json proof/public.json

echo "🔍 verify..."
snarkjs groth16 verify build/verification_key.json proof/public.json proof/proof.json

