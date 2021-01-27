# Mina reference signer

See [main.c](reference_signer.c) for an example usage of how to sign a payment and a stake delegation.

## Building

Running `make` will build the `reference_signer` and `unit_tests`.

## Repository overview

- `blake2` files: implementation of the blake2b hash function.
- `base10`: files for printing field elements in base 10
- `crypto`: group operations and the signer
- `pasta` files: implementations of the arithmetic of the base and scalar fields of the [Pallas curve](https://electriccoin.co/blog/the-pasta-curves-for-halo-2-and-beyond/).
- `base58` files: implementation of [base58check](https://en.bitcoin.it/wiki/Base58Check_encoding) encoders and decoders.
- `poseidon`: Poseidon hash function
- `utils`: small utilities

## Unit tests

The unit tests run automatically as part of the build.  However, you can also run them manually.  There are three modes of operation.

Quiet mode
```bash
./unit_tests
```
The exit value of the process is set when if the unit tests fail.  Any errors are printed to stderr.

Verbose mode
```bash
./unit_tests v
```
This prints extra information about addresses and signatures to stdout.

Ledger-gen mode
```bash
./unit_tests ledger_gen
```
This mode is used to automatically generate the unit tests for the Ledger device that contain the target values from this reference signer.
