/*******************************************************************************
 * Poseidon is a hash function explained in https://eprint.iacr.org/2019/458
 * It requires the following parameters, with p a prime defining a prime field.
 * alpha = smallest prime st gcd(p, alpha) = 1
 * m = number of field elements in the state of the hash function.
 * N = number of rounds the hash function performs on each digest.
 * For m = r + c, the sponge absorbs (via field addition) and squeezes r field
 * elements per iteration, and offers log2(c) bits of security.
 * For our p (definied in crypto.c), we have alpha = 11, m = 3, r = 1, s = 2.
 *
 * Poseidon splits the full rounds into two, putting half before the parital
 * rounds are run, and the other half after. We have :
 * full rounds = 8
 * partial = 30,
 * meaning that the rounds total 38.
 * poseidon.c handles splitting the partial rounds in half and execution order.
 ********************************************************************************/

#pragma once

#include "crypto.h"

#define POSEIDON_3W 0x00
#define POSEIDON_5W 0x01
#define POSEIDON_3  0x02

#define MAX_SPONGE_WIDTH 5

typedef Field State[MAX_SPONGE_WIDTH];

typedef struct poseidon_context_t {
    State  state;
    size_t absorbed;
    size_t sponge_width;
    size_t sponge_rate;
    size_t full_rounds;
    uint8_t sbox_alpha;
    uint8_t type;
    const Field ***round_keys;
    const Field **mds_matrix;
    void (*permutation)(struct poseidon_context_t *);
} PoseidonCtx;

bool poseidon_init(PoseidonCtx *ctx, const uint8_t type, const uint8_t network_id);
void poseidon_update(PoseidonCtx *ctx, const Field *input, size_t len);
void poseidon_digest(Scalar out, PoseidonCtx *ctx);
