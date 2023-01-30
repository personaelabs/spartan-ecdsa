#!/bin/bash 
sh ./scripts/build_wasm.sh &&
sh ./scripts/addr_membership_circuit.sh &&
sh ./scripts/pubkey_membership_circuit.sh
