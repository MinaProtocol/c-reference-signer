#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#define os_memcpy memcpy

#define BIP32_PATH_LEN 5
#define BIP32_HARDENED_OFFSET 0x80000000

#define FIELD_BYTES   32
#define SCALAR_BYTES  32
#define SCALAR_BITS   256
#define SCALAR_OFFSET 2   // Scalars have 254 used bits

#define LIMBS_PER_FIELD 4

#define FIELD_SIZE_IN_BITS 255

#define MINA_ADDRESS_LEN 56 // includes null-byte

#define COIN 1000000000ULL

typedef uint64_t Field[LIMBS_PER_FIELD];
typedef uint64_t Scalar[LIMBS_PER_FIELD];

typedef uint64_t Currency;
#define FEE_BITS 64
#define AMOUNT_BITS 64
typedef uint32_t GlobalSlot;
#define GLOBAL_SLOT_BITS 32
typedef uint32_t Nonce;
#define NONCE_BITS 32
typedef uint64_t TokenId;
#define TOKEN_ID_BITS 64
#define MEMO_BYTES 34
typedef uint8_t Memo[MEMO_BYTES];
#define MEMO_BITS (MEMO_BYTES * 8)
typedef bool Tag[3];
#define TAG_BITS 3

typedef uint8_t* PackedBits;

typedef struct group {
    Field X;
    Field Y;
    Field Z;
} Group;

typedef struct affine {
    Field x;
    Field y;
} Affine;

typedef struct compressed {
    Field x;
    bool is_odd;
} Compressed;

typedef struct transaction {
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

typedef struct signature {
    Field rx;
    Scalar s;
} Signature;

typedef struct keypair {
    Affine pub;
    Scalar priv;
} Keypair;

typedef struct roinput {
  uint64_t* fields;
  PackedBits bits;
  size_t fields_len;
  size_t fields_capacity;
  size_t bits_len;
  size_t bits_capacity;
} ROInput;

void roinput_add_field(ROInput *input, const Field a);
void roinput_add_scalar(ROInput *input, const Scalar a);
void roinput_add_bit(ROInput *input, bool b);
void roinput_add_bytes(ROInput *input, const uint8_t *bytes, size_t len);
void roinput_add_uint32(ROInput *input, const uint32_t x);
void roinput_add_uint64(ROInput *input, const uint64_t x);

void scalar_copy(Scalar c, const Scalar a);

void field_add(Field c, const Field a, const Field b);
void field_copy(Field c, const Field a);
void field_mul(Field c, const Field a, const Field b);
void field_sq(Field c, const Field a);
void group_add(Group *c, const Group *a, const Group *b);
void group_dbl(Group *c, const Group *a);
void group_scalar_mul(Group *r, const Scalar k, const Group *p);
void affine_scalar_mul(Affine *r, const Scalar k, const Affine *p);
void projective_to_affine(Affine *p, const Group *r);

void generate_keypair(Keypair *keypair, uint32_t account);
void generate_pubkey(Affine *pub_key, const Scalar priv_key);
int get_address(char *address, size_t len, const Affine *pub_key);

void sign(Signature *sig, const Keypair *kp, const Transaction *transaction);

