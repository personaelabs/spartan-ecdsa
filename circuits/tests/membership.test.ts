//! Does not work without a poseidon hash implementation on the secq256k1 base field.
const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { buildPoseidon } from "circomlibjs";
const ec = new EC("secp256k1");
import { IncrementalMerkleTree } from "@zk-kit/incremental-merkle-tree";

import { genEffEcdsaInput } from "./test_utils";

const bytesToBigInt = (bytes: Uint8Array): bigint =>
  BigInt("0x" + Buffer.from(bytes).toString("hex"));

describe.skip("membership", () => {
  it("should verify valid membership", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/membership_test.circom"),
      {
        prime: "secq256k1"
      }
    );

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

    const privKey = privKeys[0];
    const msg = Buffer.from("hello world");

    const effEcdsaInput = genEffEcdsaInput(privKey, msg);
    const merkleProof = tree.createProof(0);

    const siblings = merkleProof.siblings.map(s =>
      typeof s[0] === "bigint" ? s : bytesToBigInt(s[0])
    );

    const input = {
      ...effEcdsaInput,
      siblings,
      pathIndices: merkleProof.pathIndices
    };

    const witness = await circuit.calculateWitness(input, true);

    await circuit.assertOut(witness, {
      root: BigInt("0x" + Buffer.from(tree.root).toString("hex")).toString(10)
    });
  });

  it("should assert invalid membership", async () => {
    // TODO: implement this
  });
});
