## Node.js

Recommended: v18 or later

## Install dependencies

```
yarn
```

## Run tests

Install [this](https://github.com/DanTehrani/circom-secq) fork of Circom that supports compiling to the secp256k1 base field.

```
git clone https://github.com/DanTehrani/circom-secq
```

```
cd circom-secq && cargo build --release && cargo install --path circom
```

(In this directory) Install dependencies

```
yarn
```

Run tests

```
yarn jest
```
