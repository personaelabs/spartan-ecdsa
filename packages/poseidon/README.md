Generate Poseidon params for the secp256k1 base field

```
sh ./k256_params.sh
```

## Parameters

We use the following parameters for our Poseidon instantiation (using the notation from the [Neptune specification](https://spec.filecoin.io/#section-algorithms.crypto.poseidon)). Security inequalities are checked in [security_inequalities.sage](https://github.com/personaelabs/spartan-ecdsa/blob/f6ffbb4fc8977c4e30ae6df4eba6f1da0c534722/packages/poseidon/sage/security_inequalities.sage).

```
M=128
t=3
p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
Rf=8
Rp=56
a=5
```
