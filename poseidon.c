/*******************************************************************************
 * Poseidon is used to hash to a field in the schnorr signature scheme we use.
 * In order to be efficiently computed within the snark, it is computed using
 * the base field of the elliptic curve, and the result is then used as a
 * scalar field element, to scale the elliptic curve point. We do all of the
 * computation in this file in the base field, but output the result as a scalar.
 ********************************************************************************/

#include <assert.h>

#include "crypto.h"
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "poseidon.h"
#include "poseidon_params_3w.h"
#include "poseidon_params_5w.h"
#include "poseidon_params_3.h"

#define SPONGE_BYTES(sponge_width) (sizeof(Field)*sponge_width)
#define ROUND_KEY(ctx, round, idx) *(Field *)(ctx->round_keys + (round*ctx->sponge_width + idx)*LIMBS_PER_FIELD)
#define MATRIX_ELT(m, row, col, width) *(Field *)(m + (row*width + col)*LIMBS_PER_FIELD)

static void matrix_mul(State s1, const Field **m, const size_t width)
{
    Field tmp;

    State s2;
    bzero(s2, sizeof(s2));
    for (size_t row = 0; row < width; row++) {
        // Inner product
        for (size_t col = 0; col < width; col++) {
            Field t0;
            field_mul(t0, s1[col], MATRIX_ELT(m, row, col, width));
            field_copy(tmp, s2[row]);
            field_add(s2[row], tmp, t0);
        }
    }

    for (size_t col = 0; col < width; col++) {
        field_copy(s1[col], s2[col]);
    }
}

// 3-wire poseidon permutation function
static void permutation_3w(PoseidonCtx *ctx)
{
    Field tmp;

    // Full rounds only
    for (size_t r = 0; r < ctx->full_rounds; r++) {
        // ark
        for (size_t i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_add(ctx->state[i], tmp, ROUND_KEY(ctx, r, i));
        }

        // sbox
        for (size_t i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_pow(ctx->state[i], tmp, ctx->sbox_alpha);
        }

        // mds
        matrix_mul(ctx->state, ctx->mds_matrix, ctx->sponge_width);
    }

    // Final ark
    for (size_t i = 0; i < ctx->sponge_width; i++) {
        field_copy(tmp, ctx->state[i]);
        field_add(ctx->state[i], tmp, ROUND_KEY(ctx, ctx->full_rounds, i));
    }
}

static void permutation(PoseidonCtx *ctx)
{
    Field tmp;

    // Full rounds only
    for (size_t r = 0; r < ctx->full_rounds; r++) {
        // sbox
        for (unsigned int i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_pow(ctx->state[i], tmp, ctx->sbox_alpha);
        }

        // mds
        matrix_mul(ctx->state, ctx->mds_matrix, ctx->sponge_width);

        // ark
        for (unsigned int i = 0; i < ctx->sponge_width; i++) {
            field_copy(tmp, ctx->state[i]);
            field_add(ctx->state[i], tmp, ROUND_KEY(ctx, r, i));
        }
    }
}

struct poseidon_config_t {
    size_t sponge_width;
    size_t sponge_rate;
    size_t full_rounds;
    size_t sbox_alpha;
    const Field ***round_keys;
    const Field **mds_matrix;
    const Field *sponge_iv[2];
    void (*permutation)(PoseidonCtx *);
} _poseidon_config[3] = {
    // 0x00 - POSEIDON_3W
    {
        .sponge_width = SPONGE_WIDTH_3W,
        .sponge_rate  = SPONGE_RATE_3W,
        .full_rounds  = ROUND_COUNT_3W - 1,
        .sbox_alpha   = SBOX_ALPHA_3W,
        .round_keys   = (const Field ***)round_keys_3w,
        .mds_matrix   = (const Field **)mds_matrix_3w,
        .sponge_iv    = {
            (const Field *)testnet_iv_3w,
            (const Field *)mainnet_iv_3w
        },
        .permutation = permutation_3w
    },
    // 0x01 - POSEIDON_5W
    {
        .sponge_width = SPONGE_WIDTH_5W,
        .sponge_rate  = SPONGE_RATE_5W,
        .full_rounds  = ROUND_COUNT_5W,
        .sbox_alpha   = SBOX_ALPHA_5W,
        .round_keys   = (const Field ***)round_keys_5w,
        .mds_matrix   = (const Field **)mds_matrix_5w,
        .sponge_iv    = {
            (const Field *)testnet_iv_5w,
            (const Field *)mainnet_iv_5w
        },
        .permutation = permutation
    },
    // 0x02 - POSEIDON_3
    {
        .sponge_width = SPONGE_WIDTH_3,
        .sponge_rate  = SPONGE_RATE_3,
        .full_rounds  = ROUND_COUNT_3,
        .sbox_alpha   = SBOX_ALPHA_3,
        .round_keys   = (const Field ***)round_keys_3,
        .mds_matrix   = (const Field **)mds_matrix_3,
        .sponge_iv    = {
            (const Field *)testnet_iv_3,
            (const Field *)mainnet_iv_3
        },
        .permutation = permutation
    }
};

bool poseidon_init(PoseidonCtx *ctx, const uint8_t type, const uint8_t network_id)
{
    if (!ctx) {
      return false;
    }

    if (type != POSEIDON_3W &&
        type != POSEIDON_5W &&
        type != POSEIDON_3) {
        return false;
    }

    if (network_id != TESTNET_ID &&
        network_id != MAINNET_ID &&
        network_id != NULLNET_ID) {
        return false;
    }

    ctx->sponge_width = _poseidon_config[type].sponge_width;
    ctx->sponge_rate  = _poseidon_config[type].sponge_rate;
    ctx->full_rounds  = _poseidon_config[type].full_rounds;
    ctx->sbox_alpha   = _poseidon_config[type].sbox_alpha;
    ctx->round_keys   = _poseidon_config[type].round_keys;
    ctx->mds_matrix   = _poseidon_config[type].mds_matrix;
    ctx->permutation  = _poseidon_config[type].permutation;

    if (network_id != NULLNET_ID) {
        memcpy(ctx->state, _poseidon_config[type].sponge_iv[network_id],
               SPONGE_BYTES(ctx->sponge_width));
    }
    else {
        bzero(ctx->state, SPONGE_BYTES(ctx->sponge_width));
    }

    ctx->absorbed = 0;

    return true;
}

void poseidon_update(PoseidonCtx *ctx, const Field *input, size_t len)
{
    Field tmp;
    for (size_t i = 0; i < len; i++) {
        if (ctx->absorbed == ctx->sponge_rate) {
            ctx->permutation(ctx);
            ctx->absorbed = 0;
        }
        field_copy(tmp, ctx->state[ctx->absorbed]);
        field_add(ctx->state[ctx->absorbed], tmp, input[i]);
        ctx->absorbed++;
    }
}

// Squeezing poseidon returns the first element of its current state.
void poseidon_digest(Scalar out, PoseidonCtx *ctx) {
    ctx->permutation(ctx);

    uint64_t tmp[4];
    fiat_pasta_fp_from_montgomery(tmp, ctx->state[0]);

    // since the difference in modulus between the two fields is < 2^125,
    // with high probability, a random value from one field will fit in the
    // other field.
    fiat_pasta_fq_to_montgomery(out, tmp);
}
