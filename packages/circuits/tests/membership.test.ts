const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
const ec = new EC("secp256k1");
import { Poseidon, Tree } from "spartan-ecdsa";
import { getEffEcdsaCircuitInput } from "./test_utils";

describe("membership", () => {
  it("should verify correct signature and merkle proof", async () => {
    // Compile the circuit
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/membership_test.circom"),
      {
        prime: "secq256k1" // Specify to use the option --prime secq256k1 when compiling with circom
      }
    );

    // Construct the tree
    const poseidon = new Poseidon();
    await poseidon.init();
    const nLevels = 10;
    const tree = new Tree(nLevels, poseidon);

    const privKeys = [
      Buffer.from("".padStart(16, "🧙"), "utf16le"),
      Buffer.from("".padStart(16, "🪄"), "utf16le"),
      Buffer.from("".padStart(16, "🔮"), "utf16le")
    ];

    // Store public key hashes
    const pubKeyHashes: bigint[] = [];

    // Compute public key hashes
    for (const privKey of privKeys) {
      const pubKey = ec.keyFromPrivate(privKey).getPublic();
      const pubKeyX = BigInt(pubKey.x.toString());
      const pubKeyY = BigInt(pubKey.y.toString());
      const pubKeyHash = poseidon.hash([pubKeyX, pubKeyY]);
      pubKeyHashes.push(pubKeyHash);
    }

    // Insert the pubkey hashes into the tree
    for (const pubKeyHash of pubKeyHashes) {
      tree.insert(pubKeyHash);
    }

    // Sanity check (check that there are not duplicate members)
    expect(new Set(pubKeyHashes).size === pubKeyHashes.length).toBeTruthy();

    // Sign
    const index = 0; // Use privKeys[0] for proving
    const privKey = privKeys[index];
    const msg = Buffer.from("hello world");

    // Prepare signature proof input
    const effEcdsaInput = getEffEcdsaCircuitInput(privKey, msg);

    const merkleProof = tree.createProof(index);

    const input = {
      ...effEcdsaInput,
      siblings: merkleProof.siblings,
      pathIndices: merkleProof.pathIndices,
      root: tree.root()
    };

    // Generate witness
    const w = await circuit.calculateWitness(input, true);

    await circuit.checkConstraints(w);
  });
});
