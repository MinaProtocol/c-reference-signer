# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a C reference implementation of Mina Protocol's Schnorr signature scheme. It provides cryptographic operations for signing and verifying Mina blockchain transactions, including payments and stake delegations.

## Build Commands

```bash
# Build everything (reference_signer and unit_tests, then run tests)
make

# Build and run unit tests
make unit_tests

# Build the reference signer demo
make reference_signer

# Clean build artifacts
make clean
```

The Makefile automatically runs unit tests after building them.

## Architecture

### Cryptographic Primitives

- **Elliptic Curve**: Pasta.Pallas curve (`y^2 = x^3 + 5`) from the Zcash Pasta curves
  - Field operations in `pasta_fp.c` (base field Fp)
  - Scalar operations in `pasta_fq.c` (scalar field Fq)
  - Uses fiat-crypto generated Montgomery form arithmetic

- **Group Operations** (`crypto.c`):
  - Projective (Jacobian) coordinates internally for efficiency
  - Affine coordinates for external API
  - `group_add`, `group_dbl`, `group_scalar_mul` for internal ops
  - `affine_*` functions wrap group operations

### Signature Scheme

The signing follows Mina's Schnorr specification:
1. `message_derive()` - Derives deterministic nonce `k` using Blake2b
2. `message_hash()` - Hashes message with Poseidon for challenge `e`
3. `sign()` - Produces signature `(rx, s)` where `s = k + e*sk`
4. `verify()` - Verifies using `s*G - e*pk` and checking x-coordinate

### Poseidon Hash (`poseidon.c`, `poseidon.h`)

Two variants supported:
- `POSEIDON_LEGACY` (0x00) - Original Mina parameters
- `POSEIDON_KIMCHI` (0x01) - Updated kimchi version

Parameters are in `poseidon_params_legacy.h` and `poseidon_params_kimchi.h`.

### Transaction Structure

`Transaction` struct in `crypto.h` contains:
- Common fields: fee, fee_token, fee_payer_pk, nonce, valid_until, memo
- Body fields: tag (payment/delegation), source_pk, receiver_pk, token_id, amount

### Key Data Types

- `Field` / `Scalar`: 4x uint64_t limbs (256-bit in Montgomery form)
- `Affine`: Point as (x, y) field elements
- `Group`: Point as (X, Y, Z) projective coordinates
- `Compressed`: Point as x-coordinate + y parity bit
- `ROInput`: Random oracle input for hashing (fields + packed bits)

### Network IDs

- `TESTNET_ID` (0x00)
- `MAINNET_ID` (0x01)
- `NULLNET_ID` (0xff) - For testing without network prefix

## Key Files

- `crypto.c/h` - Main cryptographic operations and type definitions
- `unit_tests.c` - Comprehensive test suite with known test vectors
- `reference_signer.c` - Demo showing payment and delegation signing
- `curve_checks.c/h` - Generated elliptic curve verification tests

## Development Guidelines

### Commit Guidelines

- **Never** add Claude as a co-author in commit messages
- Avoid emoji usage in commit messages
- Wrap commit titles and body text at 80 characters maximum

### Code Style

- Use `-Wall -Werror` flags (enforced by Makefile)
- Follow existing naming conventions: `snake_case` for functions and variables
- Montgomery form is used internally for field/scalar arithmetic
- Always run `make unit_tests` before committing to verify changes
