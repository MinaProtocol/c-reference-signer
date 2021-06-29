#pragma once

#include "random_oracle_input.h"

#define MEMO_BYTES 34

typedef uint64_t Currency;
typedef uint32_t GlobalSlot;
typedef uint32_t Nonce;
typedef uint64_t TokenId;
typedef uint8_t  Memo[MEMO_BYTES];
typedef bool     Tag[3];

#define PAYMENT_TX    0x00
#define DELEGATION_TX 0x04

typedef struct transaction_t {
  // common
  Currency fee;
  TokenId fee_token;
  Compressed fee_payer_pk;
  Nonce nonce;
  GlobalSlot valid_until;
  Memo memo;
  // body
  Tag tag;
  Compressed source_pk;
  Compressed receiver_pk;
  TokenId token_id;
  Currency amount;
  bool token_locked;
} Transaction;

// Length of Transaction bitstrings in random oracle input
#define TX_BITSTRINGS_BYTES ( \
           sizeof(Currency)   + /* fee                */ \
           sizeof(TokenId)    + /* fee_token          */ \
           sizeof(Nonce)      + /* nonce              */ \
           sizeof(GlobalSlot) + /* valid_until        */ \
           sizeof(Memo)       + /* memo               */ \
           sizeof(TokenId)    + /* token_id           */ \
           sizeof(Currency)   + /* amount             */ \
           sizeof(Tag) - 2      /* tag + token_locked */ \
       )

void transaction_prepare_memo(uint8_t *out, const char *s);
void transaction_to_roinput(ROInput *input, const Transaction *tx);
