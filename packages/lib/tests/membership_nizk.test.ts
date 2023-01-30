import * as path from "path";
import {
  MembershipProver,
  Tree,
  Poseidon,
  defaultAddressMembershipConfig,
  defaultPubkeyMembershipConfig,
  SpartanWasm,
  defaultWasmConfig
} from "../src/lib";
import {
  hashPersonalMessage,
  ecsign,
  privateToAddress,
  privateToPublic
} from "@ethereumjs/util";
var EC = require("elliptic").ec;

describe("membership prove and verify", () => {
  // Init prover
  const treeDepth = 20;

  const privKeys = ["1", "a", "bb", "ccc", "dddd", "ffff"].map(val =>
    Buffer.from(val.padStart(64, "0"), "hex")
  );

  // Sign (Use privKeys[0] for proving)
  const proverIndex = 0;
  const proverPrivKey = privKeys[proverIndex];
  let proverAddress: bigint;

  let msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, proverPrivKey);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  let poseidon: Poseidon;
  let wasm: SpartanWasm;

  beforeAll(async () => {
    // Init Wasm
    wasm = new SpartanWasm(defaultWasmConfig);

    // Init Poseidon
    poseidon = new Poseidon();
    await poseidon.initWasm(wasm);
  });

  describe("pubkey_membership prover and verify", () => {
    it("should prove and verify valid signature and merkle proof", async () => {
      const pubKeyTree = new Tree(treeDepth, poseidon);

      let proverPubKeyHash;
      // Insert the members into the tree
      for (const privKey of privKeys) {
        const pubKey = privateToPublic(privKey);
        const pubKeyHash = poseidon.hashPubKey(pubKey);
        pubKeyTree.insert(pubKeyHash);

        // Set prover's public key hash for the reference below
        if (proverPrivKey === privKey) proverPubKeyHash = pubKeyHash;
      }

      const pubKeyMembershipProver = new MembershipProver(
        defaultPubkeyMembershipConfig
      );

      await pubKeyMembershipProver.initWasm(wasm);

      const index = pubKeyTree.indexOf(proverPubKeyHash as bigint);
      const merkleProof = pubKeyTree.createProof(index);

      const { proof, publicInput } = await pubKeyMembershipProver.prove(
        sig,
        msgHash,
        merkleProof
      );

      // TODO: Verify the proof
    });
  });

  describe("adddr_membership prover and verify", () => {
    it("should prove and verify valid signature and merkle proof", async () => {
      const addressTree = new Tree(treeDepth, poseidon);

      let proverAddress;
      // Insert the members into the tree
      for (const privKey of privKeys) {
        const address = BigInt(
          "0x" + privateToAddress(privKey).toString("hex")
        );
        addressTree.insert(address);

        // Set prover's public key hash for the reference below
        if (proverPrivKey === privKey) proverAddress = address;
      }

      const addressMembershipProver = new MembershipProver(
        defaultAddressMembershipConfig
      );

      await addressMembershipProver.initWasm(wasm);

      const index = addressTree.indexOf(proverAddress as bigint);
      const merkleProof = addressTree.createProof(index);

      const { proof, publicInput } = await addressMembershipProver.prove(
        sig,
        msgHash,
        merkleProof
      );

      // TODO: Verify the proof
    });
  });
});
