import benchPubKeyMembership from "./node.bench_pubkey_membership";
import benchAddressMembership from "./node.bench_addr_membership";

const bench = async () => {
  await benchPubKeyMembership();
  await benchAddressMembership();
};

bench();
