#include <stdio.h>
#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "base10.h"
#include "utils.h"

#include <sys/resource.h>
#include <inttypes.h>

#define MAINNET 0

#define DEFAULT_TOKEN_ID 1

int main(int argc, char* argv[]) {
  struct rlimit lim = {1, 1};
  if (setrlimit(RLIMIT_STACK, &lim) == -1) {
      printf("rlimit failed\n");
      return 1;
  }

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
  prepare_memo(txn.memo, actual_memo);

  char* fee_payer_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* source_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* receiver_str = "B62qrcFstkpqXww1EkSGrqMCwCNho86kuqBd4FrAAUsPxNKdiPzAUsy";

  txn.fee = 3;
  txn.fee_token = DEFAULT_TOKEN_ID;
  read_public_key_compressed(&txn.fee_payer_pk, fee_payer_str);
  txn.nonce = 200;
  txn.valid_until = 10000;

  txn.tag[0] = 0;
  txn.tag[1] = 0;
  txn.tag[2] = 0;

  read_public_key_compressed(&txn.source_pk, source_str);
  read_public_key_compressed(&txn.receiver_pk, receiver_str);
  txn.token_id = DEFAULT_TOKEN_ID;
  txn.amount = 42;
  txn.token_locked = false;

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  Compressed pub_compressed;
  compress(&pub_compressed, &kp.pub);

  Signature sig;
  uint8_t network_id = MAINNET ? MAINNET_ID : TESTNET_ID;
  sign(&sig, &kp, &txn, network_id);

  if (!verify(&sig, &pub_compressed, &txn, network_id)) {
    exit(1);
  }

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
  printf("     fee: '%" PRIu64 "',\n", txn.fee);
  printf("     amount: '%" PRIu64 "',\n", txn.amount);
  printf("     nonce: '%u',\n", txn.nonce);
  printf("     memo: '%s',\n", txn.memo); // TODO: This should actually be b58 encoded
  printf("     validUntil: '%u' } }\n", txn.valid_until);

  printf("\npayment signature only:\n");

  char buf[DIGITS] = { 0 };

  fiat_pasta_fp_from_montgomery(tmp, sig.rx);
  bigint_to_string(buf, tmp);
  printf("field = %s\n", buf);

  for (size_t i = 0; i < DIGITS; ++i) { buf[i] = 0; }

  fiat_pasta_fq_from_montgomery(tmp, sig.s);
  bigint_to_string(buf, tmp);
  printf("scalar = %s\n", buf);

  /*
    Stake delegation

    {
      "common": {
        "fee": 3,
        "fee_token": "1",
        "fee_payer_pk": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
        "nonce": 10,
        "valid_until": 4000,
        "memo": "E4ZAWz4pyDBBzt1zZGcVNtHLBGZf3pW9MHQvoA9BVZZNZGmyjhBuV"
      },
      "body": [
        "Stake_delegation",
        [
          "Set_delegate",
          {
            "delegator": "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg",
            "new_delegate": "B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR"
          }
        ]
      ]
    }
  */
  char* del_fee_payer_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* del_delegator_str = "B62qiy32p8kAKnny8ZFwoMhYpBppM1DWVCqAPBYNcXnsAHhnfAAuXgg";
  char* del_delegate_str = "B62qkfHpLpELqpMK6ZvUTJ5wRqKDRF3UHyJ4Kv3FU79Sgs4qpBnx5RR";
  char* del_actual_memo = "more delegates, more fun";
  Transaction del;
  del.fee = 3;
  del.fee_token = DEFAULT_TOKEN_ID;
  read_public_key_compressed(&del.fee_payer_pk, del_fee_payer_str);
  del.nonce = 10;
  del.valid_until = 4000;
  prepare_memo(del.memo, del_actual_memo);
  del.tag[0] = 0;
  del.tag[1] = 0;
  del.tag[2] = 1;
  read_public_key_compressed(&del.source_pk, del_delegator_str);
  read_public_key_compressed(&del.receiver_pk, del_delegate_str);
  del.token_id = DEFAULT_TOKEN_ID;
  del.token_locked = false;
  del.amount = 0;

  sign(&sig, &kp, &del, network_id);

  if (!verify(&sig, &pub_compressed, &del, network_id)) {
    exit(1);
  }

  printf("\ndelegation signature only:\n");

  for (size_t i = 0; i < DIGITS; ++i) { buf[i] = 0; }
  fiat_pasta_fp_from_montgomery(tmp, sig.rx);
  bigint_to_string(buf, tmp);
  printf("field = %s\n", buf);

  for (size_t i = 0; i < DIGITS; ++i) { buf[i] = 0; }

  fiat_pasta_fq_from_montgomery(tmp, sig.s);
  bigint_to_string(buf, tmp);
  printf("scalar = %s\n", buf);
}
