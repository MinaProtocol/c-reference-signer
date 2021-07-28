#include <stdio.h>
#include <assert.h>
#include <sys/resource.h>
#include <inttypes.h>

#include "pasta_fp.h"
#include "pasta_fq.h"
#include "crypto.h"
#include "poseidon.h"
#include "base10.h"
#include "utils.h"
#include "sha256.h"
#include "curve_checks.h"

#define ARRAY_LEN(x) (sizeof(x)/sizeof(x[0]))

#define DEFAULT_TOKEN_ID 1
static bool _verbose;
static bool _ledger_gen;

void privkey_to_hex(char *hex, const size_t len, const Scalar priv_key) {
  uint64_t priv_words[4];
  hex[0] = '\0';

  assert(len > 2*sizeof(priv_words));
  if (len < 2*sizeof(priv_words)) {
    return;
  }

  uint8_t *p = (uint8_t *)priv_words;
  fiat_pasta_fq_from_montgomery(priv_words, priv_key);
  // Mina privkey hex format is in big-endian
  for (size_t i = sizeof(priv_words); i > 0; i--) {
    sprintf(&hex[2*(sizeof(priv_words) - i)], "%02x", p[i - 1]);
  }
  hex[len] = '\0';
}

bool privkey_from_hex(Scalar priv_key, const char *priv_hex) {
  size_t priv_hex_len = strnlen(priv_hex, 64);
  if (priv_hex_len != 64) {
    return false;
  }
  uint8_t priv_bytes[32];
  // Mina privkey hex format is in big-endian
  for (size_t i = sizeof(priv_bytes); i > 0; i--) {
    sscanf(&priv_hex[2*(i - 1)], "%02hhx", &priv_bytes[sizeof(priv_bytes) - i]);
  }

  if (priv_bytes[3] & 0xc000000000000000) {
      return false;
  }

  fiat_pasta_fq_to_montgomery(priv_key, (uint64_t *)priv_bytes);

  char priv_key_hex[65];
  privkey_to_hex(priv_key_hex, sizeof(priv_key_hex), priv_key);

  // sanity check
  int result = memcmp(priv_key_hex, priv_hex, sizeof(priv_key_hex)) == 0;
  assert(result);
  return result;
}

bool privhex_to_address(char *address, const size_t len,
                        const char *account_number, const char *priv_hex) {
  Scalar priv_key;
  if (!privkey_from_hex(priv_key, priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  if (!generate_address(address, len, &kp.pub)) {
    return false;
  }

  if (_verbose) {
    printf("%s => %s\n", priv_hex, address);
  }
  else if (_ledger_gen) {
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", priv_hex);
    printf("    assert(test_get_address(%s) == \"%s\")\n\n",
           account_number, address);
  }

  return true;
}

void sig_to_hex(char *hex, const size_t len, const Signature sig) {
  hex[0] = '\0';

  assert(len == 2*sizeof(Signature) + 1);
  if (len < 2*sizeof(Signature) + 1) {
    return;
  }

  uint64_t words[4];
  fiat_pasta_fp_from_montgomery(words, sig.rx);
  for (size_t i = 4; i > 0; i--) {
    sprintf(&hex[16*(4 - i)], "%016lx", htole64(words[i - 1]));
  }
  fiat_pasta_fq_from_montgomery(words, sig.s);
  for (size_t i = 4; i > 0; i--) {
    sprintf(&hex[64 + 16*(4 - i)], "%016lx", htole64(words[i - 1]));
  }
}

bool sign_transaction(char *signature, const size_t len,
                      const char *account_number,
                      const char *sender_priv_hex,
                      const char *receiver_address,
                      Currency amount,
                      Currency fee,
                      Nonce nonce,
                      GlobalSlot valid_until,
                      const char *memo,
                      bool delegation,
                      uint8_t network_id) {
  Transaction txn;

  assert(len == 2*sizeof(Signature) + 1);
  if (len != 2*sizeof(Signature) + 1) {
    return false;
  }

  prepare_memo(txn.memo, memo);

  Scalar priv_key;
  if (!privkey_from_hex(priv_key, sender_priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  char source_str[MINA_ADDRESS_LEN];
  if (!generate_address(source_str, sizeof(source_str), &kp.pub)) {
    return false;
  }

  char *fee_payer_str = source_str;

  txn.fee = fee;
  txn.fee_token = DEFAULT_TOKEN_ID;
  read_public_key_compressed(&txn.fee_payer_pk, fee_payer_str);
  txn.nonce = nonce;
  txn.valid_until = valid_until;

  if (delegation) {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 1;
  }
  else {
    txn.tag[0] = 0;
    txn.tag[1] = 0;
    txn.tag[2] = 0;
  }

  read_public_key_compressed(&txn.source_pk, source_str);
  read_public_key_compressed(&txn.receiver_pk, receiver_address);
  txn.token_id = DEFAULT_TOKEN_ID;
  txn.amount = amount;
  txn.token_locked = false;

  Signature sig;
  sign(&sig, &kp, &txn, network_id);

  Compressed pub_compressed;
  compress(&pub_compressed, &kp.pub);
  if (!verify(&sig, &pub_compressed, &txn, network_id)) {
    return false;
  }

  sig_to_hex(signature, len, sig);

  if (_verbose) {
    fprintf(stderr, "%d %s\n", delegation, signature);
  }
  else if (_ledger_gen) {
    printf("    # account %s\n", account_number);
    printf("    # private key %s\n", sender_priv_hex);
    printf("    # sig=%s\n", signature);
    printf("    assert(test_sign_tx(mina.%s,\n"
           "                        %s,\n"
           "                        \"%s\",\n"
           "                        \"%s\",\n"
           "                        %zu,\n"
           "                        %zu,\n"
           "                        %u,\n"
           "                        %u,\n"
           "                        \"%s\",\n"
           "                        mina.%s) == \"%s\")\n\n",
           delegation ? "TX_TYPE_DELEGATION" : "TX_TYPE_PAYMENT",
           account_number,
           source_str,
           receiver_address,
           amount,
           fee,
           nonce,
           valid_until,
           memo,
           network_id == MAINNET_ID ? "MAINNET_ID" : "TESTNET_ID",
           signature);
  }

  return true;
}

bool check_get_address(const char *account_number,
                       const char *priv_hex, const char *address) {
  char target[MINA_ADDRESS_LEN];
  if (!privhex_to_address(target, sizeof(target), account_number, priv_hex)) {
    return false;
  }

  return strcmp(address, target) == 0;
}

bool check_sign_tx(const char *account_number,
                   const char *sender_priv_hex,
                   const char *receiver_address,
                   Currency amount,
                   Currency fee,
                   Nonce nonce,
                   GlobalSlot valid_until,
                   const char *memo,
                   bool delegation,
                   const char *signature,
                   uint8_t network_id) {
  char target[129];
  if (!sign_transaction(target, sizeof(target),
                        account_number,
                        sender_priv_hex,
                        receiver_address,
                        amount,
                        fee,
                        nonce,
                        valid_until,
                        memo,
                        delegation,
                        network_id)) {
    return false;
   }

   return strcmp(signature, target) == 0;
}

bool check_sign_message(const char *signer_priv_hex, const uint8_t *msg, const size_t len,
                        const uint8_t network_id, const char *target)
{
  Scalar priv_key;
  if (!privkey_from_hex(priv_key, signer_priv_hex)) {
    return false;
  }

  Keypair kp;
  scalar_copy(kp.priv, priv_key);
  generate_pubkey(&kp.pub, priv_key);

  Signature sig;
  if (!sign_message(&sig, &kp, msg, len, network_id)) {
     return false;
  }

  Compressed pub_compressed;
  compress(&pub_compressed, &kp.pub);
  if (!verify_message(&sig, &pub_compressed, msg, len, network_id)) {
    return false;
  }

  char signature[129];
  sig_to_hex(signature, sizeof(signature), sig);

  if (strcmp(signature, target) != 0) {
    fprintf(stderr, "signature mismatch: expected=%s, got=%s\n",
            target, signature);
    return false;
  }

  return true;
}

char *field_to_hex(char *hex, size_t len, const Field x) {
  assert(len == 65);
  hex[64] = '\0';
  Scalar y;
  fiat_pasta_fp_from_montgomery(y, x);
  uint8_t *p = (uint8_t *)y;
  for (size_t i = 0; i < sizeof(y); i++) {
    sprintf(&hex[2*i], "%02x", p[i]);
  }

  return hex;
}

char *scalar_to_hex(char *hex, size_t len, const Scalar x) {
  assert(len == 65);
  hex[64] = '\0';
  Scalar y;
  fiat_pasta_fq_from_montgomery(y, x);
  uint8_t *p = (uint8_t *)y;
  for (size_t i = 0; i < sizeof(y); i++) {
    sprintf(&hex[2*i], "%02x", p[i]);
  }

  return hex;
}

void print_scalar_as_cstruct(const Scalar x) {
  printf("        { ");
  for (size_t i = 0; i < sizeof(Scalar)/sizeof(x[0]); i++) {
    printf("0x%016lx, ", x[i]);
  }
  printf("},\n");
}

void print_affine_as_cstruct(const Affine *a) {
  printf("        {\n");
  printf("            { ");
  for (size_t i = 0; i < sizeof(Field)/sizeof(a->x[0]); i++) {
    printf("0x%016lx, ", a->x[i]);
  }
  printf(" },\n");
  printf("            { ");
  for (size_t i = 0; i < sizeof(Field)/sizeof(a->y[0]); i++) {
    printf("0x%016lx, ", a->y[i]);
  }
  printf(" },");
  printf("\n        },\n");
}

void print_scalar_as_ledger_cstruct(const Scalar x) {
  uint64_t tmp[4];
  uint8_t *p = (uint8_t *)tmp;

  fiat_pasta_fq_from_montgomery(tmp, x);
  printf("        {");
  for (size_t i = sizeof(Scalar); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n            ");
    }
    printf("0x%02x, ", p[i - 1]);
  }
  printf("\n        },\n");
}

void print_affine_as_ledger_cstruct(const Affine *a) {
  uint64_t tmp[4];
  uint8_t *p = (uint8_t *)tmp;

  fiat_pasta_fp_from_montgomery(tmp, a->x);
  printf("        {\n");
  printf("            {");
  for (size_t i = sizeof(Field); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n                ");
    }
    printf("0x%02x, ", p[i - 1]);
  }
  printf("\n            },\n");
  fiat_pasta_fp_from_montgomery(tmp, a->y);
  printf("            {");
  for (size_t i = sizeof(Field); i > 0; i--) {
    if (i % 8 == 0) {
      printf("\n                ");
    }
    printf("0x%02x, ", p[i - 1]);
  }
  printf("\n            },");
  printf("\n        },\n");
}

void generate_curve_checks(bool ledger_gen) {
  Scalar S[EPOCHS][3];
  Affine A[EPOCHS][3];

  printf("// curve_checks.h - elliptic curve unit tests\n");
  printf("//\n");
  printf("//    These constants were generated from the Mina c-reference-signer\n");
  printf("//    Do not edit this file\n");

  if (ledger_gen) {
    printf("//\n");
    printf("//    Details:  https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
    printf("//    Generate: ./unit_tests ledger_gen\n");
  }

  printf("\n");
  printf("#pragma once\n");
  printf("\n");
  printf("#include \"crypto.h\"\n");

  printf("\n");
  printf("#define EPOCHS %u\n", EPOCHS);
  printf("\n");

  // Generate test scalars
  printf("// Test scalars\n");
  printf("static const Scalar S[%u][2] = {\n", EPOCHS);

  Scalar s0; // Seed with zero scalar
  explicit_bzero(s0, sizeof(s0));
  for (size_t i = 0; i < EPOCHS; i++) {
    // Generate two more scalars
    Scalar s1, s2;
    sha256_hash(s0, sizeof(s0), s1, sizeof(s1));
    scalar_from_words(s1, s1);

    sha256_hash(s1, sizeof(s1), s2, sizeof(s2));
    scalar_from_words(s2, s2);

    memcpy(S[i][0], &s0, sizeof(S[i][0]));
    memcpy(S[i][1], &s1, sizeof(S[i][1]));
    memcpy(S[i][2], &s2, sizeof(S[i][2]));

    printf("    {\n");
    if (ledger_gen) {
      print_scalar_as_ledger_cstruct(S[i][0]);
      print_scalar_as_ledger_cstruct(S[i][1]);
      // Tests do not need S2
    }
    else {
      print_scalar_as_cstruct(S[i][0]);
      print_scalar_as_cstruct(S[i][1]);
      // Tests do not need S2
    }
    printf("    },\n");

    sha256_hash(s2, sizeof(s2), s0, sizeof(s0));
    scalar_from_words(s0, s0);
    // s0 is seed for next round!
  }
  printf("};\n");
  printf("\n");

  // Generate test curve points
  printf("// Test curve points\n");
  printf("static const Affine A[%u][3] = {\n", EPOCHS);

  for (size_t i = 0; i < EPOCHS; i++) {
    // Generate three curve points
    generate_pubkey(&A[i][0], S[i][0]);
    generate_pubkey(&A[i][1], S[i][1]);
    generate_pubkey(&A[i][2], S[i][2]);

    // Check on curve
    assert(affine_is_on_curve(&A[i][0]));
    assert(affine_is_on_curve(&A[i][1]));
    assert(affine_is_on_curve(&A[i][2]));

    printf("    {\n");
    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&A[i][0]);
      print_affine_as_ledger_cstruct(&A[i][1]);
      print_affine_as_ledger_cstruct(&A[i][2]);
    }
    else {
      print_affine_as_cstruct(&A[i][0]);
      print_affine_as_cstruct(&A[i][1]);
      print_affine_as_cstruct(&A[i][2]);
    }
    printf("    },\n");
  }
  printf("};\n");
  printf("\n");

  // Generate target outputs
  printf("// Target outputs\n");
  printf("static const Affine T[%u][5] = {\n", EPOCHS);
  for (size_t i = 0; i < EPOCHS; i++) {
    Affine a3;
    Affine a4;
    union {
      // Fit in stackspace!
      Affine a5;
      Scalar s2;
    } u;

    // Test1: On curve after scaling
    assert(affine_is_on_curve(&A[i][0]));
    assert(affine_is_on_curve(&A[i][1]));
    assert(affine_is_on_curve(&A[i][2]));

    // Test2: Addition is commutative
    //     A0 + A1 == A1 + A0
    affine_add(&a3, &A[i][0], &A[i][1]); // a3 = A0 + A1
    affine_add(&a4, &A[i][1], &A[i][0]); // a4 = A1 + A0
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    printf("    {\n");
    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test3: Scaling commutes with adding scalars
    //     G*(S0 + S1) == G*S0 + G*S1
    scalar_add(u.s2, S[i][0], S[i][1]);
    generate_pubkey(&a3, u.s2);          // a3 = G*(S0 + S1)
    affine_add(&a4, &A[i][0], &A[i][1]); // a4 = G*S0 + G*S1
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test4: Scaling commutes with multiplying scalars
    //    G*(S0*S1) == S0*(G*S1)
    scalar_mul(u.s2, S[i][0], S[i][1]);
    generate_pubkey(&a3, u.s2);                // a3 = G*(S0*S1)
    affine_scalar_mul(&a4, S[i][0], &A[i][1]); // a4 = S0*(G*S1)
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test5: Scaling commutes with negation
    //    G*(-S0) == -(G*S0)
    scalar_negate(u.s2, S[i][0]);
    generate_pubkey(&a3, u.s2);   // a3 = G*(-S0)
    affine_negate(&a4, &A[i][0]); // a4 = -(G*S0)
    assert(affine_eq(&a3, &a4));
    assert(affine_is_on_curve(&a3));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a3);
    }
    else {
      print_affine_as_cstruct(&a3);
    }

    // Test6: Addition is associative
    //     (A0 + A1) + A2 == A0 + (A1 + A2)
    affine_add(&a3, &A[i][0], &A[i][1]);
    affine_add(&a4, &a3, &A[i][2]);      // a4 = (A0 + A1) + A2
    affine_add(&a3, &A[i][1], &A[i][2]);
    affine_add(&u.a5, &A[i][0], &a3);    // a5 = A0 + (A1 + A2)
    assert(affine_eq(&a4, &u.a5));
    assert(affine_is_on_curve(&a4));

    if (ledger_gen) {
      print_affine_as_ledger_cstruct(&a4);
    }
    else {
      print_affine_as_cstruct(&a4);
    }
    printf("    },\n");
  }
  printf("};\n\n");
  printf("bool curve_checks(void);\n\n");

  if (ledger_gen) {
     printf("\n");
     printf("** Copy the above constants and curve_checks.c into the ledger project\n");
     printf("\n");
  }
}

typedef struct poseidon_test {
  int   input_len;
  char *input[10];
  char *output;
} PoseidonTest;

#define ARRAY_SAFE(...) __VA_ARGS__
#define ASSERT_POSEIDON_EQ(type, input, len, out) { \
  char *inputs[len] = input; \
  Field fields[len]; \
  for (size_t i = 0; i < len; i++) { \
    assert(field_from_hex(fields[i], inputs[i])); \
  } \
  Scalar target; \
  assert(scalar_from_hex(target, out)); \
  PoseidonCtx ctx; \
  assert(poseidon_init(&ctx, type, NULLNET_ID)); \
  poseidon_update(&ctx, fields, ARRAY_LEN(fields)); \
  Scalar output; \
  poseidon_digest(output, &ctx); \
  if (memcmp(output, target, sizeof(output)) != 0) { \
    char buf[65]; \
    fprintf(stderr, " output: %s\n", scalar_to_hex(buf, ARRAY_LEN(buf), output)); \
    fprintf(stderr, " target: %s\n", scalar_to_hex(buf, ARRAY_LEN(buf), target)); \
    assert(memcmp(output, target, sizeof(output)) == 0); \
  } \
}

void test_scalars() {
    Scalar s;
    assert(scalar_from_hex(s, "d2f75185842484ba5a1a4e0ba5f3870ed48782cc4f89a8228f5eaf75e1833906"));
    assert(scalar_from_hex(s, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));
    assert(!scalar_from_hex(s, "0000000000000000000000000000000000000000000000000000000000000040"));
    assert(!scalar_from_hex(s, "01000000ed302d991bf94c09fc98462200000000000000000000000000000040"));
}

void test_fields() {
    Field f;
    assert(field_from_hex(f, "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d"));
    assert(field_from_hex(f, "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"));
    assert(field_from_hex(f, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f"));
    assert(!field_from_hex(f, "0000000000000000000000000000000000000000000000000000000000000040"));
    assert(!field_from_hex(f, "01000000ed302d991bf94c09fc98462200000000000000000000000000000040"));
}

void test_poseidon() {
    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
      }),
      0,
      "1b3251b6912d82edc78bbb0a5c88f0c6fde1781bc3e654123fa6862a4c63e617"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
        "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"
      }),
      1,
      "f9b1b6c5f8c98017c6b35ac74bc689b6533d6dbbee1fd868831b637a43ea720c"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
        "56b648a5a85619814900a6b40375676803fe16fb1ad2d1fb79115eb1b52ac026",
        "f26a8a03d9c9bbd9c6b2a1324d2a3f4d894bafe25a7e4ad1a498705f4026ff2f"
      }),
      2,
      "7a556e93bcfbd27b55867f533cd1df293a7def60dd929a086fdd4e70393b0918"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
        "075c41fa23e4690694df5ded43624fd60ab7ee6ec6dd48f44dc71bc206cecb26",
        "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d",
        "7dfc23a1242d9c0d6eb16e924cfba342bb2fccf36b8cbaf296851f2e6c469639"
      }),
      3,
      "f94b39a919aab06f43f4a4b5a3e965b719a4dbd2b9cd26d2bba4197b10286b35"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
        "a1a659b14e80d47318c6fcdbbd388de4272d5c2815eb458cf4f196d52403b639",
        "5e33065d1801131b64d13038ff9693a7ef6283f24ec8c19438d112ff59d50f04",
        "38a8f4d0a9b6d0facdc4e825f6a2ba2b85401d5de119bf9f2bcb908235683e06",
        "3456d0313a30d7ccb23bd71ed6aa70ab234dad683d8187b677aef73f42f4f52e"
      }),
      4,
      "cc1ccfa964fd6ef9ff1994beb53cfce9ebe1212847ce30e4c64f0777875aec34"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3W,
      ARRAY_SAFE({
        "bccfee48dc76bb991c97bd531cf489f4ee37a66a15f5cfac31bdd4f159d4a905",
        "2d106fb21a262f85fd400a995c6d74bad48d8adab2554046871c215e585b072b",
        "8300e93ee8587956534d0756bb2aa575e5878c670cff5c8e3e55c62632333c06",
        "879c32da31566f6d16afdefff94cba5260fec1057e97f19fc9a61dc2c54a6417",
        "9c0aa6e5501cfb2d08aeaea5b3cddac2c9bee85d13324118b44bafb63a59611e"
      }),
      5,
      "cf7b9c2128f0e2c0fed4e1eca8d5954b629640c2458d24ba238c1bd3ccbc8e12"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
      }),
      0,
      "01ca17b5913ca7a42adfd9353676cd9a939effb71e3246fd78a2d9283c664529"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
        "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"
      }),
      1,
      "e7d279a184604c5ae038be9d7e62a23b75373825614f3b8175db6378e4fbc622"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
        "56b648a5a85619814900a6b40375676803fe16fb1ad2d1fb79115eb1b52ac026",
        "f26a8a03d9c9bbd9c6b2a1324d2a3f4d894bafe25a7e4ad1a498705f4026ff2f"
      }),
      2,
      "5c3f7b7b0bd53a6713b23b5c84bc6842831acd1c6a322806706167f767ee360c"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
        "075c41fa23e4690694df5ded43624fd60ab7ee6ec6dd48f44dc71bc206cecb26",
        "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d",
        "7dfc23a1242d9c0d6eb16e924cfba342bb2fccf36b8cbaf296851f2e6c469639"
      }),
      3,
      "e600482c4ef466db52ee02bf64cc9dd71a5a5e63eb94ff37033a10bce618a42d"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
        "a1a659b14e80d47318c6fcdbbd388de4272d5c2815eb458cf4f196d52403b639",
        "5e33065d1801131b64d13038ff9693a7ef6283f24ec8c19438d112ff59d50f04",
        "38a8f4d0a9b6d0facdc4e825f6a2ba2b85401d5de119bf9f2bcb908235683e06",
        "3456d0313a30d7ccb23bd71ed6aa70ab234dad683d8187b677aef73f42f4f52e"
      }),
      4,
      "14278226e4fa816ef6444773268a8cf10c84ac3b8e7a62323f2f768a6d6c8537"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_5W,
      ARRAY_SAFE({
        "bccfee48dc76bb991c97bd531cf489f4ee37a66a15f5cfac31bdd4f159d4a905",
        "2d106fb21a262f85fd400a995c6d74bad48d8adab2554046871c215e585b072b",
        "8300e93ee8587956534d0756bb2aa575e5878c670cff5c8e3e55c62632333c06",
        "879c32da31566f6d16afdefff94cba5260fec1057e97f19fc9a61dc2c54a6417",
        "9c0aa6e5501cfb2d08aeaea5b3cddac2c9bee85d13324118b44bafb63a59611e"
      }),
      5,
      "9775860a0bfff072224efdc657c239a81526ba2d4a46d95925bf868b7672d02b"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
      }),
      0,
      "87b24ed3fe1f35af6497c504acd6de35f06bd9c2e2490a1b5012715719de8d05"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
        "df698e389c6f1987ffe186d806f8163738f5bf22e8be02572cce99dc6a4ab030"
      }),
      1,
      "d2f75185842484ba5a1a4e0ba5f3870ed48782cc4f89a8228f5eaf75e1833906"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
        "56b648a5a85619814900a6b40375676803fe16fb1ad2d1fb79115eb1b52ac026",
        "f26a8a03d9c9bbd9c6b2a1324d2a3f4d894bafe25a7e4ad1a498705f4026ff2f"
      }),
      2,
      "922d4e7f5802aee157ae13afb8c7a4aadca06913b9d36a9d1f20f5edb70e2c30"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
        "075c41fa23e4690694df5ded43624fd60ab7ee6ec6dd48f44dc71bc206cecb26",
        "a4e2beebb09bd02ad42bbccc11051e8262b6ef50445d8382b253e91ab1557a0d",
        "7dfc23a1242d9c0d6eb16e924cfba342bb2fccf36b8cbaf296851f2e6c469639"
      }),
      3,
      "1879e13397b27ddec5fcdfb50183d106744368525494afcb256c8207129a103d"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
        "a1a659b14e80d47318c6fcdbbd388de4272d5c2815eb458cf4f196d52403b639",
        "5e33065d1801131b64d13038ff9693a7ef6283f24ec8c19438d112ff59d50f04",
        "38a8f4d0a9b6d0facdc4e825f6a2ba2b85401d5de119bf9f2bcb908235683e06",
        "3456d0313a30d7ccb23bd71ed6aa70ab234dad683d8187b677aef73f42f4f52e"
      }),
      4,
      "415aab36a9011fa8218bd67be746c7a8fd9ba83d01d1ca669574c60caef12d30"
    );

    ASSERT_POSEIDON_EQ(
      POSEIDON_3,
      ARRAY_SAFE({
        "bccfee48dc76bb991c97bd531cf489f4ee37a66a15f5cfac31bdd4f159d4a905",
        "2d106fb21a262f85fd400a995c6d74bad48d8adab2554046871c215e585b072b",
        "8300e93ee8587956534d0756bb2aa575e5878c670cff5c8e3e55c62632333c06",
        "879c32da31566f6d16afdefff94cba5260fec1057e97f19fc9a61dc2c54a6417",
        "9c0aa6e5501cfb2d08aeaea5b3cddac2c9bee85d13324118b44bafb63a59611e"
      }),
      5,
      "9d69ee732cfe073cc9417aef734293002c8db0c69b1e814cfa7a858e7c995d33"
    );
}

void test_get_address() {
      if (_ledger_gen) {
        printf("    # Address generation tests\n");
        printf("    #\n");
        printf("    #     These tests were automatically generated from the Mina c-reference-signer\n");
        printf("    #\n");
        printf("    #     Details:  https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
        printf("    #     Generate: ./unit_tests ledger_gen\n");
        printf("\n");
      }

      assert(check_get_address("0",
                               "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                               "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV"));

      assert(check_get_address("1",
                               "3ca187a58f09da346844964310c7e0dd948a9105702b716f4d732e042e0c172e",
                               "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt"));

      assert(check_get_address("2",
                               "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
                               "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi"));

      assert(check_get_address("3",
                               "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
                               "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N"));

      assert(check_get_address("49370",
                               "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
                               "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M"));

      assert(check_get_address("0x312a",
                               "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                               "B62qoG5Yk4iVxpyczUrBNpwtx2xunhL48dydN53A2VjoRwF8NUTbVr4"));
}

void test_sign_tx() {
      if (_ledger_gen) {
        printf("    # Sign transaction tests\n");
        printf("    #\n");
        printf("    #     These tests were automatically generated from the Mina c-reference-signer\n");
        printf("    #\n");
        printf("    #     Details:  https://github.com/MinaProtocol/c-reference-signer/README.markdown\n");
        printf("    #     Generate: ./unit_tests ledger_gen\n");
        printf("\n");
      }

      uint8_t network_ids[2] = { TESTNET_ID, MAINNET_ID };

      char* signatures[2][8] = {
        {
          "11a36a8dfe5b857b95a2a7b7b17c62c3ea33411ae6f4eb3a907064aecae353c60794f1d0288322fe3f8bb69d6fabd4fd7c15f8d09f8783b2f087a80407e299af",
          "23a9e2375dd3d0cd061e05c33361e0ba270bf689c4945262abdcc81d7083d8c311ae46b8bebfc98c584e2fb54566851919b58cf0917a256d2c1113daa1ccb27f",
          "2b4d0bffcb57981d11a93c05b17672b7be700d42af8496e1ba344394da5d0b0b0432c1e8a77ee1bd4b8ef6449297f7ed4956b81df95bdc6ac95d128984f77205",
          "25bb730a25ce7180b1e5766ff8cc67452631ee46e2d255bccab8662e5f1f0c850a4bb90b3e7399e935fff7f1a06195c6ef89891c0260331b9f381a13e5507a4c",
          "30797d7d0426e54ff195d1f94dc412300f900cc9e84990603939a77b3a4d2fc11ebab12857b47c481c182abe147279732549f0fd49e68d5541f825e9d1e6fa04",
          "07e9f88fc671ed06781f9edb233fdbdee20fa32303015e795747ad9e43fcb47b3ce34e27e31f7c667756403df3eb4ce670d9175dd0ae8490b273485b71c56066",
          "1ff9f77fed4711e0ebe2a7a46a7b1988d1b62a850774bf299ec71a24d5ebfdd81d04a570e4811efe867adefe3491ba8b210f24bd0ec8577df72212d61b569b15",
          "26ca6b95dee29d956b813afa642a6a62cd89b1929320ed6b099fd191a217b08d2c9a54ba1c95e5000b44b93cfbd3b625e20e95636f1929311473c10858a27f09"
        },
        {
          "124c592178ed380cdffb11a9f8e1521bf940e39c13f37ba4c55bb4454ea69fba3c3595a55b06dac86261bb8ab97126bf3f7fff70270300cb97ff41401a5ef789",
          "204eb1a37e56d0255921edd5a7903c210730b289a622d45ed63a52d9e3e461d13dfcf301da98e218563893e6b30fa327600c5ff0788108652a06b970823a4124",
          "076d8ebca8ccbfd9c8297a768f756ff9d08c049e585c12c636d57ffcee7f6b3b1bd4b9bd42cc2cbee34b329adbfc5127fe5a2ceea45b7f55a1048b7f1a9f7559",
          "058ed7fb4e17d9d400acca06fe20ca8efca2af4ac9a3ed279911b0bf93c45eea0e8961519b703c2fd0e431061d8997cac4a7574e622c0675227d27ce2ff357d9",
          "0904e9521a95334e3f6757cb0007ec8af3322421954255e8d263d0616910b04d213344f8ec020a4b873747d1cbb07296510315a2ec76e52150a4c765520d387f",
          "2406ab43f8201bd32bdd81b361fdb7871979c0eec4e3b7a91edf87473963c8a4069f4811ebc5a0e85cbb4951bffe93b638e230ce5a250cb08d2c250113a1967c",
          "36a80d0421b9c0cbfa08ea95b27f401df108b30213ae138f1f5978ffc59606cf2b64758db9d26bd9c5b908423338f7445c8f0a07520f2154bbb62926aa0cb8fa",
          "093f9ef0e4e051279da0a3ded85553847590ab739ee1bfd59e5bb30f98ed8a001a7a60d8506e2572164b7a525617a09f17e1756ac37555b72e01b90f37271595",
        }
      };

      for (size_t i = 0; i < 2; ++i) {
        uint8_t network_id = network_ids[i];
        assert(check_sign_tx("0",
                            "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                            1729000000000,
                            2000000000,
                            16,
                            271828,
                            "Hello Mina!",
                            false,
                            signatures[i][0],
                            network_id));

        assert(check_sign_tx("12586",
                            "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                            "B62qrKG4Z8hnzZqp1AL8WsQhQYah3quN1qUj3SyfJA8Lw135qWWg1mi",
                            314159265359,
                            1618033988,
                            0,
                            4294967295,
                            "",
                            false,
                            signatures[i][1],
                            network_id));

        assert(check_sign_tx("12586",
                            "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                            "B62qoqiAgERjCjXhofXiD7cMLJSKD8hE8ZtMh4jX5MPNgKB4CFxxm1N",
                            271828182845904,
                            100000,
                            5687,
                            4294967295,
                            "01234567890123456789012345678901",
                            false,
                            signatures[i][2],
                            network_id));

        assert(check_sign_tx("3",
                            "1dee867358d4000f1dafa5978341fb515f89eeddbe450bd57df091f1e63d4444",
                            "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
                            0,
                            2000000000,
                            0,
                            1982,
                            "",
                            false,
                            signatures[i][3],
                            network_id));

        // Sign delegation tx tests

        assert(check_sign_tx("0",
                            "164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                            0,
                            2000000000,
                            16,
                            1337,
                            "Delewho?",
                            true,
                            signatures[i][4],
                            network_id));

        assert(check_sign_tx("49370",
                            "20f84123a26e58dd32b0ea3c80381f35cd01bc22a20346cc65b0a67ae48532ba",
                            "B62qnzbXmRNo9q32n4SNu2mpB8e7FYYLH8NmaX6oFCBYjjQ8SbD7uzV",
                            0,
                            2000000000,
                            0,
                            4294967295,
                            "",
                            true,
                            signatures[i][5],
                            network_id));

        assert(check_sign_tx("12586",
                            "3414fc16e86e6ac272fda03cf8dcb4d7d47af91b4b726494dab43bf773ce1779",
                            "B62qkiT4kgCawkSEF84ga5kP9QnhmTJEYzcfgGuk6okAJtSBfVcjm1M",
                            0,
                            42000000000,
                            1,
                            4294967295,
                            "more delegates, more fun........",
                            true,
                            signatures[i][6],
                            network_id));

        assert(check_sign_tx("2",
                            "336eb4a19b3d8905824b0f2254fb495573be302c17582748bf7e101965aa4774",
                            "B62qicipYxyEHu7QjUqS7QvBipTs5CzgkYZZZkPoKVYBu6tnDUcE9Zt",
                            0,
                            1202056900,
                            0,
                            577216,
                            "",
                            true,
                            signatures[i][7],
                            network_id));
      }

      // Check testnet and mainnet signatures are not equal
      for (size_t i = 0; i < 8; ++i) {
          assert(strncmp(signatures[0][i], signatures[1][i], strlen(signatures[1][i])) != 0);
      }
}

void test_sign_message() {
  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"Hello message signing!", 22, MAINNET_ID,
                             "323b8ceb03a61d9e1b6e36b5aae40c660989fb7a082d7821175c7acaf0bb860a0ecaa64d883c4fc849d003c7dba7f5b32f3296f7a20dc31c0da9eb7c4add9d70"));

  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"Hello message signing!", 22, TESTNET_ID,
                            "21d34c4dea1737e99b60b23f2f75e1a4f307e599f8e0e2c7812f0401a12f809404d5d98701fb82215ed60fc06e31c57f2dda19a852c991b1329502f95d865a37"));

  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"Hello message signing\"", 22, MAINNET_ID,
                            "22343219a00a6a96ea921ed5b123f04d3fed5c127679015ab517a47191fc3d6d0f6f91857051c42b246e8ac213364f7a75de17704409050f0aba7daeffdcf87e"));

  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"Hello message signing#", 22, MAINNET_ID,
                            "2f5c98cb977722a2d3ef62d2f8f56fdbc36958dd85a935f3fac2986e6ab7f2a923f0398a8a8ef6ade3aa484299939aa8c63c5dacd4c2e5bb08129a0a25dc9c99"));

  // TODO: Check with Izaak if signing empty messages is OK security wise with schnorr scheme
  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"", 0, MAINNET_ID,
                            "2f55b066d17000d46f1e99557b478cf69bdef36c70cec0187dcb0eedf0957d65089944c833195fd7c12a640430936cce07449689c2d58effdf8d7215980d75ce"));

  // Check we are respecting the length passed
  assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                            (uint8_t *)"1123", 0, MAINNET_ID,
                            "2f55b066d17000d46f1e99557b478cf69bdef36c70cec0187dcb0eedf0957d65089944c833195fd7c12a640430936cce07449689c2d58effdf8d7215980d75ce"));

  {
    uint8_t bytes[] = { };
    assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                              bytes, sizeof(bytes), MAINNET_ID,
                              "2f55b066d17000d46f1e99557b478cf69bdef36c70cec0187dcb0eedf0957d65089944c833195fd7c12a640430936cce07449689c2d58effdf8d7215980d75ce"));
  }

  {
    uint8_t byte = 0;
    assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                              &byte, sizeof(byte), MAINNET_ID,
                              "313950fd22463fd2b79d3b2a2ce9ddffe57b4c115442c20a0c247f07a56999b73b09bcedb217ea151c5557fb9a549cafaca72c2bbd21ac31c77c26f59a70fd0d"));
  }

  {
    uint8_t byte = 0xfe;
    assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                              &byte, sizeof(byte), MAINNET_ID,
                              "091aaf54133ac3ec97c8db1bf9b47d11bed6741337d09c44af739eab4d6f961616234e7d5c4f74260ddb361558c7f06843cbc20fa8e25a87b39e0ff5c7377787"));
  }

  {
    uint8_t bytes[] = { 0x01, 0xfe, 0x74 };
    assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                              bytes, sizeof(bytes), MAINNET_ID,
                              "197c2fa73e4b4acd47ada0c97ff6c2cbda162dc812e0156c441f4b32993e48223b0b7dbe85a8270823726f65cc6f47dccfef0dd0c391fbb335a288d4694b538a"));
  }

  {
    uint8_t bytes[] = {
      0xaf, 0xac, 0xfa, 0xca, 0x12, 0xbc, 0x09, 0x00,
      0x5d, 0x99, 0x01, 0xd4, 0xe9, 0x9b, 0xce, 0xee,
      0x1d, 0x22, 0x46, 0x3f, 0xb7, 0x23, 0x9d, 0xb3,
      0x2a, 0x2c, 0xe9, 0xd7, 0xdf, 0xfe, 0x57, 0xb4,
      0xc1, 0x15, 0x44, 0x2c, 0x20, 0xa1, 0x00, 0x01,
      0xb1, 0x7f, 0x7b, 0x73, 0x1c, 0x57, 0x16, 0x1a,
      0x2e, 0x01, 0x3c, 0x50, 0x15, 0x1c, 0x54, 0xf2,
      0x45, 0x3b, 0x78, 0x45, 0x4e, 0xbc, 0x71, 0x83
    };
    assert(check_sign_message("164244176fddb5d769b7de2027469d027ad428fadcc0c02396e6280142efb718",
                              bytes, sizeof(bytes), MAINNET_ID,
                              "1b58d0c5a7ff38259ecf631a49cd7e2895631e1967564bccc73736c7b0ff3a443eaa2bcbf824c6dc1a4dd04c9fa7d128ee79688a44515320a58963d02ab3cb38"));
  }
}

int main(int argc, char* argv[]) {
  printf("Running unit tests\n");

  if (argc > 1) {
    if (strncmp(argv[1], "ledger_gen", 10) == 0) {
        _ledger_gen = true;
    }
    else {
        _verbose = true;
    }
  }
  struct rlimit lim = {1, 1};
  if (setrlimit(RLIMIT_STACK, &lim) == -1) {
    printf("rlimit failed\n");
    return 1;
  }

  // Perform crypto tests
  if (!curve_checks()) {
      // Dump computed c-reference signer constants
      generate_curve_checks(false);
      fprintf(stderr, "!! Curve checks FAILED !! (error above)\n\n");
      exit(211);
  }
  if (_ledger_gen) {
      generate_curve_checks(true);
  }

  // fiat-crypto sqrt not square
  {
    Affine pub;

    Compressed good_pk;
    read_public_key_compressed(&good_pk, "B62qoCvDGrbMFn5bj7PRmQC7CVvXzNQSoXXo5BmwVGTZUdUV3aCgkaK");
    assert(decompress(&pub, &good_pk));

    Compressed bad_pk;
    read_public_key_compressed(&bad_pk, "B62qprBg8jPke59MztbJPLKnSY9xbEiNNG9JqSA5jKxqXHPCWMYJjPM");
    assert(!decompress(&pub, &bad_pk));
  }

  test_scalars();

  test_fields();

  test_poseidon();

  test_get_address();

  test_sign_tx();

  test_sign_message();

  printf("Unit tests completed successfully\n");

  return 0;
}
