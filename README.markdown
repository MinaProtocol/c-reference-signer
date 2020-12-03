# Mina reference signer

See [main.c](main.c) for an example usage of how to sign a payment and a stake delegation.

## Building

Running `./build.sh` will build [main.c](main.c) into `a.out`.

## Repository overview

- `blake2` files: implementation of the blake2b hash function.
- `base10`: files for printing field elements in base 10
- `crypto`: group operations and the signer
- `pasta` files: implementations of the arithmetic of the base and scalar fields of the [Pallas curve](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/).
- `base58` files: implementation of [base58check](https://en.bitcoin.it/wiki/Base58Check_encoding) encoders and decoders.
- `poseidon`: Poseidon hash function
- `utils`: small utilities
