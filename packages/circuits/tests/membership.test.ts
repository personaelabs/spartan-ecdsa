//! Does not work without a poseidon hash implementation on the secq256k1 base field.
const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { buildPoseidon } from "circomlibjs";
const ec = new EC("secp256k1");
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";

import { genEffEcdsaInput, bytesToBigInt } from "./test_utils";

describe.skip("membership", () => {
  it("should verify valid membership", async () => {
    // Compile the circuit
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/membership_test.circom"),
      {
        prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
      }
    );

    // Construct the tree
    const poseidon = await buildPoseidon();
    const nLevels = 20;
    const tree = new IncrementalMerkleTree(poseidon, nLevels, BigInt(0));

    const privKeys = [BigInt(1), BigInt(2), BigInt(3)];
    const pubKeyHashes: bigint[] = privKeys.map(privKey => {
      const pubKey = ec.keyFromPrivate(privKey).getPublic();
      const pubKeyHash = poseidon([pubKey]);
      return bytesToBigInt(pubKeyHash);
    });

    for (const pubKeyHash of pubKeyHashes) {
      tree.insert(pubKeyHash);
    }

    const index = 0; // Use privKeys[0] for this proving
    const privKey = privKeys[index];
    const msg = Buffer.from("hello world");

    const effEcdsaInput = genEffEcdsaInput(privKey, msg);
    const merkleProof = tree.createProof(index);

    // Formatting
    const siblings = merkleProof.siblings.map(s =>
      typeof s[0] === "bigint" ? s : bytesToBigInt(s[0])
    );

    const input = {
      ...effEcdsaInput,
      siblings,
      pathIndices: merkleProof.pathIndices
    };

    // Gen witness
    const witness = await circuit.calculateWitness(input, true);
    const expectedRoot = bytesToBigInt(tree.root);

    // Assert
    await circuit.assertOut(witness, {
      root: expectedRoot
    });
  });

  it("should assert invalid membership", async () => {
    // TODO
  });
});
