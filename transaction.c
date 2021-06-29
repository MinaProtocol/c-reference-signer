#include <string.h>

#include "transaction.h"

void transaction_to_roinput(ROInput *input, const Transaction *tx)
{
    input->fields_len = 0;
    input->bits_len = 0;

    roinput_add_field(input, tx->fee_payer_pk.x);
    roinput_add_field(input, tx->source_pk.x);
    roinput_add_field(input, tx->receiver_pk.x);

    roinput_add_uint64(input, tx->fee);
    roinput_add_uint64(input, tx->fee_token);
    roinput_add_bit(input, tx->fee_payer_pk.is_odd);
    roinput_add_uint32(input, tx->nonce);
    roinput_add_uint32(input, tx->valid_until);
    roinput_add_bytes(input, tx->memo, MEMO_BYTES);
    for (size_t i = 0; i < 3; ++i) {
        roinput_add_bit(input, tx->tag[i]);
    }
    roinput_add_bit(input, tx->source_pk.is_odd);
    roinput_add_bit(input, tx->receiver_pk.is_odd);
    roinput_add_uint64(input, tx->token_id);
    roinput_add_uint64(input, tx->amount);
    roinput_add_bit(input, tx->token_locked);
}

void transaction_prepare_memo(uint8_t *out, const char *s)
{
    size_t len = strnlen(s, MEMO_BYTES - 2);
    out[0] = 1;
    out[1] = len; // length
    for (size_t i = 0; i < len; ++i) {
        out[2 + i] = s[i];
    }
    for (size_t i = 2 + len; i < MEMO_BYTES; ++i) {
        out[i] = 0;
    }
}
