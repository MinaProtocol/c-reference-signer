#include <stdio.h>
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "libbase58.h"
#include "base10.h"

void read_public_key_compressed(Compressed* out, char* pubkeyBase58) {
  size_t pubkeyBytesLen = 40;
  unsigned char pubkeyBytes[40];
  b58tobin(pubkeyBytes, &pubkeyBytesLen, pubkeyBase58, 0);

  uint64_t x_coord_non_montgomery[4] = { 0, 0, 0, 0 };

  size_t offset = 3;
  for (size_t i = 0; i < 4; ++i) {
    const size_t BYTES_PER_LIMB = 8;
    // 8 bytes per limb
    for (size_t j = 0; j < BYTES_PER_LIMB; ++j) {
      size_t k = offset + BYTES_PER_LIMB * i + j;
      x_coord_non_montgomery[i] |= ( ((uint64_t) pubkeyBytes[k]) << (8 * j));
    }
  }

  fiat_pasta_fp_to_montgomery(out->x, x_coord_non_montgomery);
  out->is_odd = (bool) pubkeyBytes[offset + 32];
}

int main(int argc, char* argv[]) {
  Scalar priv_key = { 0xca14d6eed923f6e3, 0x61185a1b5e29e6b2, 0xe26d38de9c30753b, 0x3fdf0efb0a5714 };

  /*
    This illustrates constructing and signing the following transaction.

    amounts are in nanocodas.

    {
      "common": {
        "fee": "3",
        "fee_token": "1",
        "fee_payer_pk": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
        "nonce": "200",
        "valid_until": "10000",
        "memo": "E4Yq8cQXC1m9eCYL8mYtmfqfJ5cVdhZawrPQ6ahoAay1NDYfTi44K"
      },
      "body": [
        "Payment",
        {
          "source_pk": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
          "receiver_pk": "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy",
          "token_id": "1",
          "amount": "42"
        }
      ]
    }
  */

  Transaction txn;

  char* actual_memo = "this is a memo";
  size_t actual_memo_len = strlen(actual_memo);
  txn.memo[0] = 1;
  txn.memo[1] = actual_memo_len; // length
  for (size_t i = 0; i < actual_memo_len; ++i) {
    txn.memo[2 + i] = actual_memo[i];
  }
  for (size_t i = 2 + actual_memo_len; i < MEMO_BYTES; ++i) {
    txn.memo[i] = 0;
  }

  char* fee_payer_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* source_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* receiver_str = "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy";

  txn.fee = 3;
  txn.fee_token = 1;
  read_public_key_compressed(&txn.fee_payer_pk, fee_payer_str);
  txn.nonce = 200;
  txn.valid_until = 10000;

  txn.tag[0] = 0;
  txn.tag[1] = 0;
  txn.tag[2] = 0;

  read_public_key_compressed(&txn.source_pk, source_str);
  read_public_key_compressed(&txn.receiver_pk, receiver_str);
  txn.token_id = 1;
  txn.amount = 42;
  txn.token_locked = false;

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  Signature sig;
  sign(&sig, &kp, &txn);

  char field_str[DIGITS] = { 0 };
  char scalar_str[DIGITS] = { 0 };
  uint64_t tmp[4];
  fiat_pasta_fp_from_montgomery(tmp, sig.rx);
  bigint_to_string(field_str, tmp);

  fiat_pasta_fq_from_montgomery(tmp, sig.s);
  bigint_to_string(scalar_str, tmp);

  printf("{ publicKey: '%s',\n", fee_payer_str);
  printf("  signature:\n");
  printf("   { field:\n");
  printf("      '%s',\n", field_str);
  printf("     scalar:\n");
  printf("      '%s' },\n", scalar_str);
  printf("  payload:\n");
  printf("   { to: '%s',\n", receiver_str);
  printf("     from: '%s',\n", source_str);
  printf("     fee: '%lu',\n", txn.fee);
  printf("     amount: '%lu',\n", txn.amount);
  printf("     nonce: '%u',\n", txn.nonce);
  printf("     memo: '%s',\n", txn.memo); // TODO: This should actually be b58 encoded
  printf("     validUntil: '%u' } }\n", txn.valid_until);

  printf("\nsignature only:\n");

  char buf[DIGITS] = { 0 };

  fiat_pasta_fp_from_montgomery(tmp, sig.rx);
  bigint_to_string(buf, tmp);
  printf("field = %s\n", buf);

  for (size_t i = 0; i < DIGITS; ++i) { buf[i] = 0; }

  fiat_pasta_fq_from_montgomery(tmp, sig.s);
  bigint_to_string(buf, tmp);
  printf("scalar = %s\n", buf);
}
